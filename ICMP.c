/**
 * @file ICMP.c
 * @author Mohammad Reza Hosseini 
 * 
 * 
 */

#include "ICMP.h"
#include "ip.h"
#include "ethernet.h"
#include "rtable.h"


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>



void icmp_processPacket(struct sr_instance* sr, const uint8_t * packet, unsigned int len, const char* interface){
	icmp_header_t* icmp_hdr = icmp_getHeader(packet);
	if (icmp_hdr->icmp_type == ICMP_TYPE_ECHO_REQUEST){
		printf("\n\t\tICMP Type: Echo Request, sending reply ...");
		icmp_sendPacket(sr, packet, len, ICMP_TYPE_ECHO_REPLY, ICMP_CODE_ECHO);
	}
	if (icmp_hdr->icmp_type == ICMP_TYPE_ECHO_REPLY){
		printf("\n\t\tICMP Type: Echo Reply, processing reply ...");
		icmp_processEchoReply(sr, packet, len);
	}
}


icmp_header_t* icmp_getHeader(const uint8_t* packet){
	ip_header_t* ip_hdr = ip_getHeader(packet);
	return (icmp_header_t*)(&ip_hdr[sizeof(ip_header_t)]);
}

/**
 * This method is NOT thread safe, accesses rtable (which currently is locking itself),
 * ARP cache, and potentially ARP queue
 *
 * @returns 0 on success, 1 on failure
 */
int icmp_sendPacket(struct sr_instance* sr, const uint8_t* src_packet, unsigned int len, uint8_t icmp_type, uint8_t icmp_code){
	
	router_t* router = sr_get_subsystem(sr);
	
	int new_packet_len;
	int icmp_payload_len;
	
	if (icmp_type == ICMP_TYPE_ECHO_REPLY) {
		new_packet_len = len;
		icmp_payload_len = new_packet_len - (sizeof(eth_header_t) + sizeof(ip_header_t) + sizeof(icmp_header_t));
	} else {
		new_packet_len = sizeof(eth_header_t) + sizeof(ip_header_t) + sizeof(icmp_header_t) + 4 + sizeof(ip_header_t) + 8;
		icmp_payload_len = 4 + sizeof(ip_header_t) + 8;
	}
	
	uint8_t* new_packet = (uint8_t*)malloc(new_packet_len);
	
	bzero(new_packet, new_packet_len);
	
	eth_header_t* new_eth = (eth_header_t*) new_packet;
	ip_header_t* ip_hdr = ip_getHeader(src_packet);
	ip_header_t* new_ip = ip_getHeader(new_packet);
	icmp_header_t* new_icmp = icmp_getHeader(new_packet);
	
	struct in_addr next_hop;
	int next_hop_ifIndex = 0;
	
	/* 
	 * Check that we have a next hop, and if so get the next hop IP, and outgoing interface name 
	 */
	if (rtable_nextHop(router, &ip_hdr->ip_src, &next_hop, &next_hop_ifIndex)){
		printf("\nFailure getting next hop address");
		return 1;
	}
	
	if (icmp_type == ICMP_TYPE_ECHO_REPLY){
		icmp_create(new_icmp, icmp_type, icmp_code, ((uint8_t*) icmp_getHeader(src_packet)) + sizeof(icmp_header_t*), icmp_payload_len);
	} else {
		uint8_t *new_payload = calloc(icmp_payload_len, sizeof(uint8_t));
		bcopy(ip_hdr, new_payload + 4, icmp_payload_len - 4);
		icmp_create(new_icmp, icmp_type, icmp_code, new_payload, icmp_payload_len);
		free(new_payload);
	}
	
	new_icmp->icmp_sum = htons(icmp_checksum(new_icmp, icmp_payload_len));
	
	
	/*
	 * populate the ip header and checksum 
	 */
	if ((icmp_type == ICMP_TYPE_ECHO_REPLY) || ((icmp_type == ICMP_TYPE_DESTINATION_UNREACHABLE) && (icmp_code == ICMP_CODE_PORT_UNREACHABLE))) {
		
		/* If we are sending back a port unreachable, that means the packet was destined to one of our interfaces,
		 * which may not be the ingress interface, thus we need to set the reply IP packets source address
		 * with the address it was initialy sent to
		 *
		 * Or if we are sending back an echo reply, then it was destined to our router, so send it
		 * back with the proper ip
		 */
		ip_createHeader(new_ip, sizeof(icmp_header_t) + icmp_payload_len, IP_PROTO_ICMP, ip_hdr->ip_dst.s_addr, ip_hdr->ip_src.s_addr);
		
	} else {
		ip_createHeader(new_ip, sizeof(icmp_header_t) + icmp_payload_len, IP_PROTO_ICMP, router->if_list[next_hop_ifIndex].ip, ip_hdr->ip_src.s_addr);
	}
	new_ip->ip_sum = htons(ip_checksum(new_ip));
		
	/*
	 * populate the packet with the eth information we have 
	 */
	eth_createHeader(new_eth, NULL, router->if_list[next_hop_ifIndex].addr, ETH_TYPE_IP);
	
	/*
	 * ship the packet to lower layer for sending 
	 */
	return router_ip2mac(sr, new_packet, new_packet_len, &next_hop, router->if_list[next_hop_ifIndex].name);
}

/** 
 * Populates the ICMP header and its payload.  You must set the checksum yourself. 
 */
void icmp_create(icmp_header_t* icmp, uint8_t icmp_type, uint8_t icmp_code, uint8_t* payload, int payload_len){
	bzero(icmp, sizeof(icmp_header_t));
	icmp->icmp_type = icmp_type;
	icmp->icmp_code = icmp_code;
	
	uint8_t* p = (uint8_t*) icmp;
	p += sizeof(icmp_header_t);
	memcpy(p, payload, payload_len);	
}

/**
 * @return the host order checksum for the given packet
 */
uint16_t icmp_checksum(icmp_header_t* icmp, int payload_len){
	
	icmp->icmp_sum = 0;
	unsigned long sum = 0;
	uint16_t s_sum = 0;
	int numShorts = (sizeof(icmp_header_t) + payload_len) / 2;
	int i = 0;
	uint16_t* s_ptr = (uint16_t*) icmp;
	
	for (i = 0; i < numShorts; ++i) {
		if (i != 1) {
			sum += ntohs(*s_ptr);
		}
		++s_ptr;
	}
	
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	
	s_sum = sum & 0xFFFF;
	s_sum = (~s_sum);
	
	return s_sum;
}


void icmp_processEchoReply(struct sr_instance* sr, const uint8_t* packet, unsigned int len){
	/*
	 * NOTE: no ping support currently
	 */
	
// 	router_t* router = (router_t* router) sr_get_subsystem(sr);
// 	
// 	/*
// 	 * Create an entry in the sping queue for this echo reply  
// 	 */
// 	sping_queue_entry *sping_entry = calloc(1, sizeof(sping_queue_entry));
// 	sping_entry->packet = calloc(len, sizeof(uint8_t));
// 	memcpy(sping_entry->packet, packet, len);
// 	sping_entry->len = len;
// 	time(&(sping_entry->arrival_time));
// 	
// 	node *n = node_create();
// 	n->data = sping_entry;
// 	
// 	/* put the packet on the sping queue and broadcast its arrival */
// 	lock_mutex_sping_queue(rs);
// 	if(rs->sping_queue == NULL) {
// 		rs->sping_queue = n;
// 	} else {
// 		node_push_back(rs->sping_queue, n);
// 	}
// 	pthread_cond_broadcast(rs->sping_cond);
// 	unlock_mutex_sping_queue(rs);
}
