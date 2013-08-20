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


#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <assert.h>



void ip_processPacket(struct sr_instance* sr, const uint8_t * packet, unsigned int len, const char* interface){
	
// 	router_state *rs = get_router_state(sr);
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
				printf("\n\tPacket IP Proto : TCP, sending to transport layer");
// 				sr_transport_input((uint8_t *)ip_hdr);
				//TODO
				break;
			case IP_PROTO_ICMP:
				printf("\n\tPacket IP Proto : ICMP, processing ...");
// 				process_icmp_packet(sr, packet, len, interface);//TODO
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
// 				if (send_icmp_packet(sr, packet, len, ICMP_TYPE_DESTINATION_UNREACHABLE, ICMP_CODE_PORT_UNREACHABLE) != 0) { //TODO
// 					printf("Failure sending icmp reply\n");
// 				}
				break;
			default:
				/*
				 * If other? return ICMP protocol unreachable 
				 */
				printf("\n\tUnknown protocol, sending ICMP unreachable");
// 				if (send_icmp_packet(sr, packet, len, ICMP_TYPE_DESTINATION_UNREACHABLE, ICMP_CODE_PROTOCOL_UNREACHABLE) != 0) {//TODO
// 					//printf("Failure sending icmp reply\n");
// 				}
				break;
		}
	} else if (ip_hdr->ip_dst.s_addr == htonl(PWOSPF_HELLO_TIP)) {
		/*
		 * if the packet is destined to the PWOSPF address then process it 
		 */
// 		process_pwospf_packet(sr, packet, len, interface);//TODO
	} else {
		/*
		 * Need to forward this packet to another host 
		 */
		
		//TODO: lpm and forwarding process
		
// 		struct in_addr next_hop;
// 		char next_hop_iface[IF_LEN];
// 		bzero(next_hop_iface, IF_LEN);
// 		
// 		
// 		/* is there an entry in our routing table for the destination? */
// 		if(get_next_hop(&next_hop, next_hop_iface, IF_LEN,
// 			rs,
// 		  &((get_ip_hdr(packet, len))->ip_dst))) {
// 			
// 			/* send ICMP no route to host */
// 			uint8_t icmp_type = ICMP_TYPE_DESTINATION_UNREACHABLE;
// 			uint8_t icmp_code = ICMP_CODE_NET_UNKNOWN;
// 			send_icmp_packet(sr, packet, len, icmp_type, icmp_code);
// 		  }	else {
// 			  
// 			  
// 			  if(strncmp(interface, next_hop_iface, IF_LEN) == 0){
// 				  /* send ICMP net unreachable */
// 				  uint8_t icmp_type = ICMP_TYPE_DESTINATION_UNREACHABLE;
// 				  uint8_t icmp_code = ICMP_CODE_NET_UNREACHABLE;
// 				  send_icmp_packet(sr, packet, len, icmp_type, icmp_code);
// 			  }
// 			  else {
// 				  
// 				  /* check for outgoing interface is WAN */
// 				  iface_entry* iface = get_iface(rs, next_hop_iface);
// 				  if(iface->is_wan) {
// 					  
// 					  lock_nat_table(rs);
// 					  process_nat_int_packet(rs, packet, len, iface->ip);
// 					  unlock_nat_table(rs);
// 				  }
// 				  
// 				  ip_hdr *ip = get_ip_hdr(packet, len);
// 				  
// 				  /* is ttl < 1? */
// 				  if(ip->ip_ttl == 1) {
// 					  
// 					  /* send ICMP time exceeded */
// 					  uint8_t icmp_type = ICMP_TYPE_TIME_EXCEEDED;
// 					  uint8_t icmp_code = ICMP_CODE_TTL_EXCEEDED;
// 					  send_icmp_packet(sr, packet, len, icmp_type, icmp_code);
// 					  
// 				  } else {
// 					  /* decrement ttl */
// 					  ip->ip_ttl--;
// 					  
// 					  /* recalculate checksum */
// 					  bzero(&ip->ip_sum, sizeof(uint16_t));
// 					  uint16_t checksum = htons(compute_ip_checksum(ip));
// 					  ip->ip_sum = checksum;
// 					  
// 					  eth_hdr *eth = (eth_hdr *)packet;
// 					  iface_entry* sr_if = get_iface(rs, next_hop_iface);
// 					  assert(sr_if);
// 					  
// 					  /* update the eth header */
// 					  populate_eth_hdr(eth, NULL, sr_if->addr, ETH_TYPE_IP);
// 					  
// 					  /* duplicate this packet here because the memory will be freed
// 					   * by send_ip, and our copy of the packet is only on loan
// 					   */
// 					  
// 					  uint8_t* packet_copy = (uint8_t*)malloc(len);
// 					  memcpy(packet_copy, packet, len);
// 					  
// 					  /* forward packet out the next hop interface */
// 					  send_ip(sr, packet_copy, len, &(next_hop), next_hop_iface);
// 				}
// 			} /* end of strncmp(interface ... */
// 		} /* end of if(get_next_hop) */
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
