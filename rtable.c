/**
 * @file rtable.c
 * @author Mohammad Reza Hosseini 
 * 
 * 
 */

#include "rtable.h"
#include "sr_base_internal.h"
#include "router.h"
#include "ll.h"
#include "netfpga.h"
#include "pwospf.h"
#include "dijkstra.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/**
 * performs a linear longest prefix match
 * @param router pointer to #router_t struct
 * @param dest destination address to lookup
 * @param [out] next_hop result of lpm
 * @param [out] next_hop_ifIndex index of interface to return the packet
 * @return: 1 if no match, 0 if there is a match
 */
int rtable_nextHop(router_t* router, struct in_addr* dest, struct in_addr* next_hop, int* next_hop_ifIndex){
	int i;
	
	node_t* n = router->rtable;
	rtable_row_t* lpm = NULL;
	
	int most_bits_matched = -1;
	while (n){
		rtable_row_t* row = (rtable_row_t*) n->data;
		
		if (row->is_active){
			uint32_t mask = ntohl(row->mask.s_addr);
			uint32_t ip = ntohl(row->ip.s_addr) & mask;
			uint32_t dest_ip = ntohl(dest->s_addr) & mask;
			
			if (ip == dest_ip) {
				/*
				 * count the number of bits in the mask 
				 */
				int bits_matched = 0;
				for (i = 0; i < 32; ++i) {
					if ((mask >> i) & 0x1) {
						++bits_matched;
					}
				}
				
				if (bits_matched > most_bits_matched) {
					lpm = row;
					most_bits_matched = bits_matched;
				}
			}
		}
		n = n->next;
	}
	
	int retval = 1;
	if (lpm) {
		if (lpm->gw.s_addr == 0) {
			/*
			 * Support for next hop 0.0.0.0, meaning it is equivalent to the destination ip 
			 */
			next_hop->s_addr = dest->s_addr;
		} else {
			next_hop->s_addr = lpm->gw.s_addr;
		}
		
		(*next_hop_ifIndex) = router_getInterfaceIndex(router, lpm->iface);
		
		retval = 0;
	}
	
	return retval;
}

void rtable_init(struct sr_instance* sr){
	router_t* router = (router_t*) sr_get_subsystem(sr);
	/*
	 * lock rtable
	 */
	router_lockWrite(&router->lock_rtable);
	
	/*
	 * the sr_instance only holds 32 chars of the path to the rtable file so we have
	 * to pass it in as a relative path to the working directory, which requires
	 * us to get the working directory, do some string manipulation, and append
	 * the relative path to the end of the working directory 
	 */
	char path[256];
	bzero(path, 256);
	getcwd(path, 256);
	int len = strlen(path);
	path[len] = '/';
	strcpy(path+len+1, sr->rtable);
	FILE* file = fopen(path, "r");
	if (file == NULL) {
		perror("Failure opening file");
		exit(1);
	}
	
	char buf[1024];
	bzero(buf, 1024);
	
	
	/*
	 * walk through the file one line at a time adding its contents to the rtable 
	 */
	while (fgets(buf, 1024, file) != NULL) {
		char* ip = NULL;
		char* gw = NULL;
		char* mask = NULL;
		char* iface = NULL;
		if (sscanf(buf, "%as %as %as %as", &ip, &gw, &mask, &iface) != 4) {
			printf("ignoring incorrect line in rtable file\n");
			continue;
		}
		
		rtable_row_t* row = (rtable_row_t*) malloc(sizeof(rtable_row_t));
		bzero(row, sizeof(rtable_row_t));
		
		if (inet_pton(AF_INET, ip, &(row->ip)) == 0) {
			perror("Failure reading rtable");
		}
		if (inet_pton(AF_INET, gw, &(row->gw)) == 0) {
			perror("Failure reading rtable");
		}
		if (inet_pton(AF_INET, mask, &(row->mask)) == 0) {
			perror("Failure reading rtable");
		}
		strncpy(row->iface, iface, 32);
		
		row->is_active = 1;
		row->is_static = 1;
		
		/*
		 * create a node, set data pointer to the new entry 
		 */
		node_t* n = node_create();
		n->data = row;
		
		if (router->rtable == NULL) {
			router->rtable = n;
		} else {
			node_push_back(router->rtable, n);
		}
		
		char ip_array[INET_ADDRSTRLEN];
		char gw_array[INET_ADDRSTRLEN];
		char mask_array[INET_ADDRSTRLEN];
		
		printf("Read: %s ", inet_ntop(AF_INET, &(row->ip), ip_array, INET_ADDRSTRLEN));
		printf("%s ", inet_ntop(AF_INET, &(row->gw), gw_array, INET_ADDRSTRLEN));
		printf("%s ", inet_ntop(AF_INET, &(row->mask), mask_array, INET_ADDRSTRLEN));
		printf("%s\n", row->iface);
	}
	
	
	if (fclose(file) != 0) {
		perror("Failure closing file");
	}
	netfpga_writeRTable(&router->netfpga, router->rtable);
	
	/* check if we have a default route entry, if so we need to add it to our pwospf router */
	pwospf_iface_t* default_route = pwospf_hasDefaultRoute(router);
	
	/*
	 * release the rtable lock 
	 */
	router_unlock(&router->lock_rtable);
	
	if (default_route) {
// 		lock_mutex_pwospf_router_list(rs);
		router_lockMutex(&router->lock_pwospf_list);
		
		pwospf_router_t* r = pwospf_searchList(router->router_id, router->pwospf_router_list);
		node_t* n = node_create();
		n->data = default_route;
		
		if (r->interface_list) {
			node_push_back(r->interface_list, n);
		} else {
			r->interface_list = n;
		}
		
// 		unlock_mutex_pwospf_router_list(rs);
	router_unlockMutex(&router->lock_pwospf_list);
	}
	/*
	 * tell our dijkstra algorithm to run 
	 */
	dijkstra_trigger(router);
}

/*
 * NOT Threadsafe, ensure rtable locked for write
 */
void rtable_updated(router_t* router){
	/*
	 * bubble sort by netmask 
	 */
	
	int swapped = 0;
	do {
		swapped = 0;
		node_t* cur = router->rtable;
		while (cur && cur->next){
			rtable_row_t* a = (rtable_row_t*)cur->data;
			rtable_row_t* b = (rtable_row_t*)cur->next->data;
			if ((ntohl(a->mask.s_addr) < ntohl(b->mask.s_addr)) ||
			   ((a->mask.s_addr == b->mask.s_addr) && (ntohl(a->ip.s_addr) < ntohl(b->ip.s_addr))) ||
			   ((a->mask.s_addr == b->mask.s_addr) && (a->ip.s_addr == b->ip.s_addr) && !a->is_static && b->is_static)) 
			{
				cur->data = b;
				cur->next->data = a;
				swapped = 1;
			}
			cur = cur->next;
		}
	} while (swapped);
	
	/*
	 * write to hardware
	 */
	netfpga_writeRTable(&router->netfpga, router->rtable);
}
