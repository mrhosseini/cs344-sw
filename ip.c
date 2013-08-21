/**
* @file ip.c
* @author Mohammad Reza Hosseini 
* 
* 
*/

#include "ip.h"
#include "router.h"
#include "arp.h"
#include "pwospf.h"
#include "ICMP.h"
#include "rtable.h"


#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <assert.h>



void ip_processPacket(struct sr_instance* sr, const uint8_t * packet, unsigned int len, const char* interface){
	router_t* router = (router_t*) sr_get_subsystem(sr);
	
	/*
	 * Check if the packet is invalid, if so drop it 
	 */
	if (!ip_isValid(packet, len)) {
		return;
	}
	
	router_lockRead(&router->lock_arp_cache);
	router_lockWrite(&router->lock_arp_queue);
	router_lockRead(&router->lock_rtable);
	
	
	/*
	 * Check if the packet is headed to one of our interfaces 
	 */
	ip_header_t* ip_hdr = ip_getHeader(packet);
	int if_index = router_getInterfaceByIp(router, ip_hdr->ip_dst.s_addr);
	if (if_index >= 0){
		switch (ip_hdr->ip_p) {
			case IP_PROTO_TCP:
				/*
				 * We don't accept TCP
				 * If TCP, send ICMP reply port unreachable
				 */
				printf("\n\tPacket IP Proto : TCP, sending ICMP Port Unreachable");
				if (icmp_sendPacket(sr, packet, len, ICMP_TYPE_DESTINATION_UNREACHABLE, ICMP_CODE_PROTOCOL_UNREACHABLE) != 0){
					printf("Failure sending icmp reply\n");
				}
				break;
			case IP_PROTO_ICMP:
				printf("\n\tPacket IP Proto : ICMP, processing ...");
				icmp_processPacket(sr, packet, len, interface);
				break;
			case IP_PROTO_PWOSPF:
				printf("\n\tPacket IP Proto : PWOSPF, processing ...");
// 				process_pwospf_packet(sr, packet, len, interface);//TODO
				break;
			case IP_PROTO_UDP:
				/*
				 * We don't accept UDP so ICMP reply port unreachable
				 */
				printf("\n\tPacket IP Proto : UDP, sending ICMP Port Unreachable");
				if (icmp_sendPacket(sr, packet, len, ICMP_TYPE_DESTINATION_UNREACHABLE, ICMP_CODE_PORT_UNREACHABLE) != 0){
					printf("Failure sending icmp reply\n");
				}
				break;
			default:
				/*
				 * If other? return ICMP protocol unreachable 
				 */
				printf("\n\tUnknown protocol, sending ICMP unreachable");
				if (icmp_sendPacket(sr, packet, len, ICMP_TYPE_DESTINATION_UNREACHABLE, ICMP_CODE_PROTOCOL_UNREACHABLE) != 0){
					printf("Failure sending icmp reply\n");
				}
				break;
		}
	}
	else if (ip_hdr->ip_dst.s_addr == htonl(PWOSPF_HELLO_TIP)) {
		/*
		 * if the packet is destined to the PWOSPF address then process it 
		 */
// 		process_pwospf_packet(sr, packet, len, interface);//TODO
	} 
	else {
		/*
		 * Need to forward this packet to another host 
		 */
		
		struct in_addr next_hop;
		int next_hop_ifIndex = 0;

		/*
		 * is there an entry in our routing table for the destination? 
		 */
		if (rtable_nextHop(router, &ip_hdr->ip_dst, &next_hop, &next_hop_ifIndex) != 0){
			/* 
			 * send ICMP no route to host 
			 */
			icmp_sendPacket(sr, packet, len, ICMP_TYPE_DESTINATION_UNREACHABLE, ICMP_CODE_NET_UNKNOWN);
		} 
		else if (strcmp(interface, router->if_list[next_hop_ifIndex].name)){
			/*
			 * send ICMP net unreachable 
			 */
			icmp_sendPacket(sr, packet, len, ICMP_TYPE_DESTINATION_UNREACHABLE, ICMP_CODE_NET_UNREACHABLE);
		}
		else{
			/*
			 * check ttl to see if is ttl < 1? 
			 */
			if (ip_hdr->ip_ttl == 1){
				/*
				 * send ICMP time exceeded 
				 */
				icmp_sendPacket(sr, packet, len, ICMP_TYPE_TIME_EXCEEDED, ICMP_CODE_TTL_EXCEEDED);
				
			}
			else{
				/* 
				 * decrement ttl 
				 */
				ip_hdr->ip_ttl--;
				
				/*
				 * recalculate checksum 
				 */
				bzero(&ip_hdr->ip_sum, sizeof(uint16_t));
				uint16_t checksum = htons(ip_checksum(ip_hdr));
				ip_hdr->ip_sum = checksum;
				
				/*
				 * update the eth header 
				 */
				eth_header_t* eth = (eth_header_t*) packet;
				eth_createHeader(eth, NULL, router->if_list[next_hop_ifIndex].addr, ETH_TYPE_IP);
				
				/* 
				 * duplicate this packet here because the memory will be freed
				 * by router_ip2mac, and our copy of the packet is only on loan
				 */
				
				uint8_t* packet_copy = (uint8_t*) malloc(len);
				memcpy(packet_copy, packet, len);
				
				/*
				 * forward packet out the next hop interface 
				 * (sending to link layer)
				 */
				router_ip2mac(sr, packet_copy, len, &(next_hop), router->if_list[next_hop_ifIndex].name);
			}
		}
	}
	
	router_unlock(&router->lock_rtable);
	router_unlock(&router->lock_arp_queue);
	router_unlock(&router->lock_arp_cache);
}


/**
 * @return 0 if not IPV4, options exist, is fragmented, invalid checksum. 1 otherwise.
 *
 */
int ip_isValid(const uint8_t* packet, unsigned int len) {
	ip_header_t* ip_hdr = ip_getHeader((uint8_t*)packet);
	
	/* 
	 * check for IPV4 
	 */
	if (ip_hdr->ip_v != 4) {
		return 0;
	}
	
	/*
	 * check for options 
	 */
	if (ip_hdr->ip_hl != 5) {
		return 0;
	}
	
	/*
	 * check for fragmentation 
	 */
	uint16_t frag_field = ntohs(ip_hdr->ip_off);
	if ((frag_field & IP_FRAG_MF) || (frag_field & IP_FRAG_OFFMASK)) {
		return 0;
	}
	
	/*
	 * check the checksum 
	 */
	if (ip_verifyChecksum((uint8_t *)ip_hdr, 4 * ip_hdr->ip_hl)) {
		return 0;
	}	
	
	return 1;
}

int ip_verifyChecksum(uint8_t *data, unsigned int data_length){
	uint16_t* bytes;
	size_t length;
	uint32_t sum_2_comp = 0;
	uint16_t sum_1_comp = 0;
	int i;
	bytes = (uint16_t*) data;
	length = data_length / 2;
	
	for (i = 0; i < length; i++){
		sum_2_comp += ntohs(bytes[i]);
	}
	sum_1_comp = (sum_2_comp >> 16) + (sum_2_comp & 0xFFFF);
	
	if (sum_1_comp == 0xFFFF){
		return 0;
	}
	
	return 1;
}

ip_header_t* ip_getHeader(const uint8_t* packet){
	return (ip_header_t*)(&packet[ETH_HDR_LEN]);
}


/**
 * @return the host order checksum for the given packet
 */
uint16_t ip_checksum(ip_header_t* iphdr){
	iphdr->ip_sum = 0;
	unsigned long sum = 0;
	uint16_t s_sum = 0;
	int numShorts = iphdr->ip_hl * 2;
	int i = 0;
	uint16_t* s_ptr = (uint16_t*)iphdr;
	
	for (i = 0; i < numShorts; ++i) {
		/* 
		 * sum all except checksum field 
		 */
		if (i != 5) {
			sum += ntohs(*s_ptr);
		}
		++s_ptr;
	}
	
	/*
	 * sum carries 
	 */
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	
	/* 
	 * ones compliment 
	 */
	s_sum = sum & 0xFFFF;
	s_sum = (~s_sum);
	
	return s_sum;
}

/**
 * Populates an IP header with the usual data.  Note source_ip and dest_ip must be passed into
 * the function in network byte order.
 */
void ip_createHeader(ip_header_t* ip, uint16_t payload_size, uint8_t protocol, uint32_t source_ip, uint32_t dest_ip){
	bzero(ip, sizeof(ip_header_t));
	ip->ip_hl = 5;
	ip->ip_v = 4;
	
	ip->ip_off = htons(IP_FRAG_DF);
	
	ip->ip_len = htons(20 + payload_size);
	ip->ip_ttl = 0x40;
	ip->ip_p = protocol;
	ip->ip_src.s_addr = source_ip;
	ip->ip_dst.s_addr = dest_ip;
}