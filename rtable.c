/**
 * @file rtable.c
 * @author Mohammad Reza Hosseini 
 * 
 * 
 */

#include "rtable.h"


/*
 * next_hop, next_hop_iface are parameters returned by the function
 * len is the max length that can be copied into next_hop_iface
 * THIS METHOD IS NOT THREAD SAFE! AQUIRE THE rtable lock first!
 * Returns: 1 if no match, 0 if there is a match
 */
int rtable_nextHop(router_t* router, struct in_addr* dest, struct in_addr* next_hop, int* next_hop_ifIndex){

// int get_next_hop(struct in_addr* next_hop, char* next_hop_iface, int len, router_state* rs, struct in_addr* destination) {
// 	int i;
// 	
// 	node* n = rs->rtable;
// 	rtable_entry* lpm = NULL;
// 	int most_bits_matched = -1;
// 	while (n) {
// 		rtable_entry* re = (rtable_entry*)n->data;
// 		
// 		if (re->is_active) {
// 			uint32_t mask = ntohl(re->mask.s_addr);
// 			uint32_t ip = ntohl(re->ip.s_addr) & mask;
// 			uint32_t dest_ip = ntohl(destination->s_addr) & mask;
// 			
// 			if (ip == dest_ip) {
// 				/* count the number of bits in the mask */
// 				int bits_matched = 0;
// 				for (i = 0; i < 32; ++i) {
// 					if ((mask >> i) & 0x1) {
// 						++bits_matched;
// 					}
// 				}
// 				
// 				if (bits_matched > most_bits_matched) {
// 					lpm = re;
// 					most_bits_matched = bits_matched;
// 				}
// 			}
// 		}
// 		n = n->next;
// 	}
// 	
// 	int retval = 1;
// 	if (lpm) {
// 		if (lpm->gw.s_addr == 0) {
// 			/* Support for next hop 0.0.0.0, meaning it is equivalent to the destination ip */
// 			/*next_hop->s_addr = lpm->ip.s_addr;*/
// 			next_hop->s_addr = destination->s_addr;
// 		} else {
// 			next_hop->s_addr = lpm->gw.s_addr;
// 		}
// 		strncpy(next_hop_iface, lpm->iface, len);
// 		retval = 0;
// 	}
// 	
// 	return retval;
	
	return 0;
}
