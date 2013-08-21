/**
 * @file arp.c
 * @author Mohammad Reza Hosseini 
 * 
 */

#include "arp.h"
#include "ll.h"
#include "reg_defines.h"
#include "netfpga.h"
#include "ip.h"
#include "ICMP.h"


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
	
	router_t* router = (router_t*) sr_get_subsystem(sr);
	
	/* scan the interface list
	 * match the requested ip
	 */
	int i = 0;
	for (i = 0; i < NUM_INTERFACES; i++){
		if (router->if_list[i].ip == arp_hdr->arp_tip.s_addr){
			printf("\n Interface %s has the IP address, sending reply ...", router->if_list[i].name);
			arp_sendReply(sr, packet, len, i);
			break;
		}
	}
}


void arp_processReply(struct sr_instance *sr, const uint8_t *packet, unsigned int len, const char *interface){
	
	assert(sr);
	assert(packet);
	assert(interface);
	
	router_t* router = sr_get_subsystem(sr);
	
	/* 
	 * update the arp cache 
	 */
	arp_header_t* arp_hdr = arp_getHeader(packet);
	arp_updateCache(sr, &(arp_hdr->arp_sip), arp_hdr->arp_sha, 0);

	
	/*
	 * process arp_queue for possible resolve
	 */
	router_lockRead(&router->lock_arp_cache);
	router_lockWrite(&router->lock_arp_queue);
	arp_checkQueue(sr, &(arp_hdr->arp_sip), arp_hdr->arp_sha);
	router_unlock(&router->lock_arp_queue);
	router_unlock(&router->lock_arp_cache);
}

void arp_sendReply(struct sr_instance *sr, const uint8_t *packet, unsigned int len, int interface_index){
	eth_header_t* eth_hdr = (eth_header_t*) packet;
	arp_header_t* arp_hdr = arp_getHeader(packet);
	
	
	router_t* router = (router_t*) sr_get_subsystem(sr);
	uint8_t* new_packet = (uint8_t*) malloc(sizeof(eth_header_t) + sizeof(arp_header_t));
	
	/*
	 * Setup the ETHERNET header 
	 */
	eth_header_t* new_eth = (eth_header_t*) new_packet;
	eth_createHeader(new_eth, eth_hdr->s_addr, router->if_list[interface_index].addr, ETH_TYPE_ARP);
	
	/*
	 * Setup the ARP header 
	 */
	arp_header_t* new_arp = arp_getHeader(new_packet);
	arp_createHeader(new_arp, arp_hdr->arp_sha, arp_hdr->arp_sip.s_addr, router->if_list[interface_index].addr, router->if_list[interface_index].ip, ARP_OP_REPLY);
	
	/*
	 * Send the reply 
	 */
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
	
	router_t* router = (router_t*) sr_get_subsystem(sr);
	arp_item_t* arp_item = 0;
	
	
	/*
	 * lock arp_cache for write
	 */
	router_lockWrite(&router->lock_arp_cache);
	
	arp_item = arp_searchCache(router, remote_ip);
	if (arp_item) {
		
		/* 
		 * if this remote ip is in the cache, update its data 
		 */
		memcpy(arp_item->arp_ha, remote_mac, ETH_ADDR_LEN);
		if (is_static == 1) {
			arp_item->ttl = 0;
		} else {
			time(&arp_item->ttl);
		}
		arp_item->is_static = is_static;
	}
	else {
		/* 
		 * if this interface is not in the cache, create a new entry 
		 */
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
	
	/* 
	 * update the hw arp cache copy 
	 * cache is locked, no need to lock again
	 */
	arp_updateHw(router);
	

	/*
	 * unlock arp_cache
	 */
	router_unlock(&router->lock_arp_cache);
	
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

void arp_updateHw(router_t* router){
	
	/* 
	 * iterate sequentially through the 16 slots in hw updating all entries 
	 */
	int i = 0;
	
	/* 
	 * first write all the static entries 
	 */
	node_t* cur = router->arp_cache;
	while((cur != NULL) && (i < ROUTER_OP_LUT_ARP_TABLE_DEPTH)) {
		arp_item_t* arp_item = (arp_item_t*) cur->data;
		
		if (arp_item->is_static) {
			netfpga_writeArpCacheItem(&router->netfpga, arp_item, i);
			i++;
		}
		
		cur = cur->next;
	}
	
	/*
	 * second write all the non-static entries and zero out remaining entries in hw
	 */
	cur = router->arp_cache;
	while(i < ROUTER_OP_LUT_ARP_TABLE_DEPTH) {
		
		if (cur) {
			arp_item_t* arp_item = (arp_item_t*)cur->data;
			if(arp_item->is_static == 0) {
				netfpga_writeArpCacheItem(&router->netfpga, arp_item, i);
				i++;
			}
			cur = cur->next;
			
		} else {
			/*
			 * zero out the rest of the rows 
			 */
			netfpga_writeArpCacheItem(&router->netfpga, NULL, i);
			i++;
		}
	}
}

void arp_checkQueue(struct sr_instance* sr, struct in_addr* dest_ip, unsigned char* dest_mac) {
	router_t* router = (router_t*) sr_get_subsystem(sr);
	node_t* n = router->arp_queue;
	node_t* next = NULL;
	
	while (n) {
		next = n->next;
		
		arp_qi_t* aqi = (arp_qi_t*)n->data;
		
		/*
		 * match the arp reply sip to our entry next hop ip
		 */
		if (dest_ip->s_addr == aqi->next_hop.s_addr) {
			node_t* cur_packet_node = aqi->head;
			node_t* next_packet_node = NULL;
			
			while (cur_packet_node) {
				next_packet_node = cur_packet_node->next;
				
				/*
				 * rerun the ip2mac process to see if the packet can be sent
				 */
				arp_qp_t* aqp = (arp_qp_t*) cur_packet_node->data;
				
				router_ip2mac(sr, aqp->packet, aqp->len, &(aqi->next_hop), aqi->out_iface_name);
				
				node_remove(&(aqi->head), cur_packet_node);
				
				cur_packet_node = next_packet_node;
			}
			
			/*
			 * free the arp queue entry for this destination ip, and patch the list 
			 */
			node_remove(&router->arp_queue, n);
		}
		
		n = next;
	}
}

void arp_qAdd(struct sr_instance* sr, uint8_t* packet, unsigned int len, const char* out_iface_name, struct in_addr *next_hop){
	assert(sr);
	assert(packet);
	assert(out_iface_name);
	assert(next_hop);
	
	router_t* router = (router_t*) sr_get_subsystem(sr);
	
	/*
	 * Is there an existing queue entry for this IP? 
	 */
	arp_qi_t* aqi = arp_qSearch(router, next_hop);
	if (!aqi) {
		/*
		 * create a new queue entry 
		 */
		aqi = (arp_qi_t*) malloc(sizeof(arp_qi_t));
		bzero(aqi, sizeof(arp_qi_t));
		memcpy(aqi->out_iface_name, out_iface_name, IF_LEN);
		aqi->next_hop = *next_hop;
		
		/*
		 * send a request 
		 */
		time(&(aqi->last_req_time));
		aqi->requests = 1;
		arp_sendRequest(sr, next_hop->s_addr, out_iface_name);
		arp_qAddPacket(aqi, packet, len);
		
		/*
		 * create a node, add this entry to the node, and push it into our linked list 
		 */
		node_t* n = node_create();
		n->data = aqi;
		
		if (router->arp_queue == NULL) {
			router->arp_queue = n;
		} else {
			node_push_back(router->arp_queue, n);
		}
	} else {
		/*
		 * entry exists, just add the packet 
		 */
		arp_qAddPacket(aqi, packet, len);
	}
}

arp_qi_t* arp_qSearch(router_t* router, struct in_addr* ip){
	node_t* n = router->arp_queue;
	
	while (n) {
		arp_qi_t* aqi = (arp_qi_t*) n->data;
		if (aqi->next_hop.s_addr == ip->s_addr) {
			return aqi;
		}
		n = n->next;
	}
	
	return NULL;
}

void arp_qAddPacket(arp_qi_t* aqi, uint8_t* packet, unsigned int len){
	node_t* n = node_create();
	arp_qp_t* aqp = (arp_qp_t*)malloc(sizeof(arp_qp_t));
	
	aqp->packet = packet;
	aqp->len = len;
	
	/*
	 * set the new nodes data to point to the packet entry 
	 */
	n->data = aqp;
	
	/*
	 * add the new node to the arp queue entry 
	 */
	if (aqi->head == NULL) {
		aqi->head = n;
	} else {
		node_push_back(aqi->head, n);
	}
}


void arp_sendRequest(struct sr_instance* sr, uint32_t tip /* Net byte order */, const char* interface){
	
	assert(sr);
	assert(interface);
	router_t* router = (router_t*) sr_get_subsystem(sr);

	int interface_index = router_getInterfaceIndex(router, interface);
	uint8_t *request_packet = 0;
	eth_header_t *eth_request = 0;
	arp_header_t *arp_request = 0;
	uint32_t len = 0;
	uint8_t default_addr[ETH_ADDR_LEN] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
	
	/*
	 * construct the ARP request 
	 */
	len = sizeof(eth_header_t) + sizeof(arp_header_t);
	request_packet = calloc(len, sizeof(uint8_t));
	eth_request = (eth_header_t*) request_packet;
	arp_request = (arp_header_t*) (request_packet + sizeof(eth_header_t));
	
	eth_createHeader(eth_request, default_addr, router->if_list[interface_index].addr, ETH_TYPE_ARP);
	arp_createHeader(arp_request, NULL, tip, router->if_list[interface_index].addr, router->if_list[interface_index].ip, ARP_OP_REQUEST);
	
	
	/* 
	 * send the ARP request 
	 */
	if (router_sendPacket(sr, request_packet, len, interface) != 0) {
		printf("Failure sending arp request\n");
	}
	
	/*
	 * recover allocated memory 
	 */
	free(request_packet);
}

void arp_processQueue(struct sr_instance* sr) {
	router_t* router = (router_t*) sr_get_subsystem(sr);
	node_t* n = router->arp_queue;
	node_t* next = NULL;
	time_t now;
	double diff;
	
	while (n) {
		next = n->next;
		arp_qi_t* aqi = (arp_qi_t*) n->data;
		
		/*
		 * has it been over a second since the last arp request was sent? 
		 */
		time(&now);
		diff = difftime(now, aqi->last_req_time);
		if (diff > ARP_REQUEST_INTERVAL) {
			/*
			 * have we sent less than 5 arp requests? 
			 */
			if (aqi->requests < ARP_MAX_REQUESTS) {
				/*
				 * send another arp request
				 */
				time(&(aqi->last_req_time));
				++(aqi->requests);
				arp_sendRequest(sr, aqi->next_hop.s_addr, aqi->out_iface_name);
			} else {
				/*
				 * we have exceeded the max arp requests, return packets to sender 
				 */
				node_t* cur_packet_node = aqi->head;
				node_t* next_packet_node = NULL;
				
				while (cur_packet_node) {
					/*
					 * send icmp for the packet, free it, and its encasing entry 
					 */
					arp_qp_t* aqp = (arp_qp_t*) cur_packet_node->data;
					
					/* only send an icmp error if the packet is not icmp, or if it is, its an echo request or reply
					 * also ensure we don't send an icmp error back to one of our interfaces
					 */
					ip_header_t* ip_hdr = ip_getHeader(aqp->packet);
					icmp_header_t* icmp_hdr = icmp_getHeader(aqp->packet);
					if ( ip_hdr->ip_p != IP_PROTO_ICMP || icmp_hdr->icmp_type == ICMP_TYPE_ECHO_REPLY || icmp_hdr->icmp_type == ICMP_TYPE_ECHO_REQUEST){
						
						/*
						 * also ensure we don't send an icmp error back to one of our interfaces 
						 */
						if (router_getInterfaceByIp(router, ip_hdr->ip_src.s_addr) >= 0){
							/* Total hack here to increment the TTL since we already decremented it earlier in the pipeline
							 * and the ICMP error should return the original packet. 
							 */

							if (ip_hdr->ip_ttl < 255) {
								ip_hdr->ip_ttl++;
								
								/* recalculate checksum */
								bzero(&ip_hdr->ip_sum, sizeof(uint16_t));
								uint16_t checksum = htons(ip_checksum(ip_hdr));
								ip_hdr->ip_sum = checksum;
							}
							icmp_sendPacket(sr, aqp->packet, aqp->len, ICMP_TYPE_DESTINATION_UNREACHABLE, ICMP_CODE_HOST_UNREACHABLE);
						}
					}
						
					free(aqp->packet);
					next_packet_node = cur_packet_node->next;
					//free(cur_packet_node);   /* IS THIS CORRECT TO FREE IT ? */
					node_remove(&(aqi->head), cur_packet_node);
					cur_packet_node = next_packet_node;
				}
				
				/*
				 * free the arp queue entry for this destination ip, and patch the list 
				 */
				node_remove(&router->arp_queue, n);
			}
		}
		n = next;
	}
	
}

void* arp_thread(void *param) {
	assert(param);
	struct sr_instance *sr = (struct sr_instance *)param;
	router_t* router = (router_t*) sr_get_subsystem(sr);
	
	while (1) {
		router_lockWrite(&router->lock_arp_cache);
		arp_expireCache(sr);
		router_unlock(&router->lock_arp_cache);		
		
		
		router_lockRead(&router->lock_arp_cache);
		router_lockWrite(&router->lock_arp_queue);
		router_lockRead(&router->lock_rtable); /* because we may send an icmp packet back, requiring get next hop */
		
		arp_processQueue(sr);
		
		router_unlock(&router->lock_rtable);
		router_unlock(&router->lock_arp_queue);
		router_unlock(&router->lock_arp_cache);
		
		sleep(1);
	}
}

void arp_expireCache(struct sr_instance* sr){
	assert(sr);
	router_t* router = (router_t*) sr_get_subsystem(sr);
	node_t* arp_walker = 0;
	arp_item_t* arp_item = 0;
	time_t now;
	double diff;
	int timedout_entry = 0;
	
	
	/*
	 * iterate through arp_cache to find expired entries
	 */
	arp_walker = router->arp_cache;
	while(arp_walker) {
		arp_item = (arp_item_t *)arp_walker->data;
		node_t* tmp = arp_walker;
		arp_walker = arp_walker->next;
		
		/*
		 * if not static, check that TTL is within reason 
		 */
		if (arp_item->is_static != 1) {
			time(&now);
			diff = difftime(now, arp_item->ttl);
			
			if (diff > ARP_TIMEOUT) {
				node_remove(&router->arp_cache, tmp);
				timedout_entry = 1;
			}
		}
	}
	
	/* 
	 * update hw
	 */
	if (timedout_entry == 1) {
		arp_updateHw(router);
	}
}
