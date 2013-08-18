/**
 * @file arp.c
 * @author Mohammad Reza Hosseini 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 */

#include "arp.h"
#include "ll.h"


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <time.h>
#include <arpa/inet.h>

arp_header_t* arp_getHeader(const uint8_t* packet){
 	return ((arp_header_t*)&packet[ETH_HDR_LEN]);
}

void arp_processPacket(struct sr_instance *sr, const uint8_t *packet, unsigned int len, const char *interface){
	
	assert(sr);
	assert(packet);
	assert(interface);
	
	arp_header_t* arp_hdr = arp_getHeader(packet);
	
	/*
	 * arp_op is in network byte order
	 */
 	switch (ntohs(arp_hdr->arp_op)) { 
		
		case ARP_OP_REQUEST:
			printf("\n ARP Request Operation ...");
			arp_processRequest(sr, packet, len, interface);
			break;
			
		case ARP_OP_REPLY:
			printf("\n ARP Reply Operation ...");
			arp_processReply(sr, packet, len, interface);
			break;
			
		default: return;
	}
}


void arp_processRequest(struct sr_instance *sr, const uint8_t *packet, unsigned int len, const char *interface){
	
	assert(sr);
	assert(packet);
	assert(interface);
	
	arp_header_t* arp_hdr = arp_getHeader(packet);
	
	/* get interface list read lock */
	//lock_if_list_rd(rs);TODO: lock if_list
	
	router_t* router = (router_t*) sr_get_subsystem(sr);
	
	/* scan the interface list
	 * match the requested ip
	 */
	int i = 0;
	for (i = 0; i < NUM_INTERFACES; i++){
		if (router->if_list[i].ip == arp_hdr->arp_tip.s_addr){
			printf("\n Interface %s has the IP address, sending reply ...", router->if_list[i].name);
// 			send_arp_reply(sr, packet, len, (iface_entry*)(n->data));
			arp_sendReply(sr, packet, len, i);
			break;
		}
	}
	
	/* release the interface list lock */
// 	unlock_if_list(rs);
}


void arp_processReply(struct sr_instance *sr, const uint8_t *packet, unsigned int len, const char *interface){
	
	assert(sr);
	assert(packet);
	assert(interface);
	
// 	router_state *rs = get_router_state(sr);
	router_t* router = sr_get_subsystem(sr);
	
	/* update the arp cache */
// 	arp_hdr *arp = get_arp_hdr(packet, len);
	arp_header_t* arp_hdr = arp_getHeader(packet);
	
	//TODO:
	
// 	lock_arp_cache_wr(rs);
	arp_updateCache(sr, &(arp_hdr->arp_sip), arp_hdr->arp_sha, 0);
// 	unlock_arp_cache(rs);
// 	
// 	lock_arp_cache_rd(rs);
// 	lock_arp_queue_wr(rs);
// 	send_queued_packets(sr, &(arp->arp_sip), arp->arp_sha);
// 	unlock_arp_queue(rs);
// 	unlock_arp_cache(rs);
}

void arp_sendReply(struct sr_instance *sr, const uint8_t *packet, unsigned int len, int interface_index){
	eth_header_t* eth_hdr = (eth_header_t*) packet;
// 	eth_hdr* eth = (eth_hdr*)packet;
// 	arp_hdr* arp_req = get_arp_hdr(packet, len);
	arp_header_t* arp_hdr = arp_getHeader(packet);
	
	uint8_t* new_packet = (uint8_t*) malloc(sizeof(eth_header_t) + sizeof(arp_header_t));
	
	/* Setup the ETHERNET header */
// 	eth_hdr* new_eth = (eth_hdr*)new_packet;
	eth_header_t* new_eth = (eth_header_t*) new_packet;
	
	router_t* router = (router_t*) sr_get_subsystem(sr);
// 	populate_eth_hdr(new_eth, eth->eth_shost, iface->addr, ETH_TYPE_ARP);
	eth_createHeader(new_eth, eth_hdr->s_addr, router->if_list[interface_index].addr, ETH_TYPE_ARP);
	
	/* Setup the ARP header */
// 	arp_hdr* new_arp = get_arp_hdr(new_packet, sizeof(eth_hdr) + sizeof(arp_hdr));
	arp_header_t* new_arp = arp_getHeader(new_packet);
// 	populate_arp_hdr(new_arp, arp_req->arp_sha, arp_req->arp_sip.s_addr, iface->addr, iface->ip, ARP_OP_REPLY);
	arp_createHeader(new_arp, arp_hdr->arp_sha, arp_hdr->arp_sip.s_addr, router->if_list[interface_index].addr, router->if_list[interface_index].ip, ARP_OP_REPLY);
	
	/* Send the reply */
	if (router_sendPacket(sr, new_packet, sizeof(eth_header_t) + sizeof(arp_header_t), router->if_list[interface_index].name) <= 0) {
		printf("Error sending ARP reply\n");
	}
	
	free(new_packet);
}


void arp_createHeader(arp_header_t* arp_header, uint8_t* arp_tha, uint32_t arp_tip, uint8_t* arp_sha, uint32_t arp_sip, uint16_t op){	
	arp_header->arp_hrd = htons(ARP_HRD_ETHERNET);
	arp_header->arp_pro = htons(ARP_PRO_IP);
	arp_header->arp_hln = ETH_ADDR_LEN;
	arp_header->arp_pln = 4;
	arp_header->arp_op = htons(op);
	
	memcpy(arp_header->arp_sha, arp_sha, ETH_ADDR_LEN);
	arp_header->arp_sip.s_addr = arp_sip;
	if(arp_tha != NULL) {
		memcpy(arp_header->arp_tha, arp_tha, ETH_ADDR_LEN);
	}
	arp_header->arp_tip.s_addr = arp_tip;
}


void arp_updateCache(struct sr_instance* sr, struct in_addr* remote_ip, uint8_t* remote_mac, int is_static){
	assert(sr);
	assert(remote_ip);
	assert(remote_mac);
	
// 	router_state *rs = (router_state *)sr->interface_subsystem;
	router_t* router = (router_t*) sr_get_subsystem(sr);
	arp_item_t* arp_item = 0;
	
	//arp_entry = in_arp_cache(rs, remote_ip);
	arp_item = arp_searchCache(router, remote_ip);
	if (arp_item) {
		
		/* if this remote ip is in the cache, update its data */
		memcpy(arp_item->arp_ha, remote_mac, ETH_ADDR_LEN);
		if (is_static == 1) {
			arp_item->ttl = 0;
		} else {
			time(&arp_item->ttl);
		}
		arp_item->is_static = is_static;
	}
	else {
		/* if this interface is not in the cache, create a new entry */
		node_t* n = node_create();
		arp_item = calloc(1, sizeof(arp_item_t));
		
		arp_item->ip.s_addr = remote_ip->s_addr;
		memcpy(arp_item->arp_ha, remote_mac, ETH_ADDR_LEN);
		if (is_static == 1) {
			arp_item->ttl = 0;
		} else {
			time(&arp_item->ttl);
		}
		arp_item->is_static = is_static;
		
		n->data = (void *)arp_item;
		if (router->arp_cache == NULL) {
			router->arp_cache = n;
		} else {
			node_push_back(router->arp_cache, n);
		}
	}
	
	/* update the hw arp cache copy */
//	trigger_arp_cache_modified(rs);//TODO
	
	return;
}

arp_item_t* arp_searchCache(router_t* router, struct in_addr* ip_addr) {
	node_t* arp_walker = 0;
	arp_item_t* arp_item = 0;
	
	arp_walker = router->arp_cache;
	while (arp_walker){
		arp_item = (arp_item_t*) arp_walker->data;
		
		if (ip_addr->s_addr == arp_item->ip.s_addr) {
			break;
		}
		
		arp_item = 0;
		arp_walker = arp_walker->next;
	}
	
	return arp_item;
}


