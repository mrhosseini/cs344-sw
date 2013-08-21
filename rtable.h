/**
 * @file rtable.h
 * @author Mohammad Reza Hosseini 
 * 
 * 
 */
#ifndef RTABLE_H_
#define RTABLE_H_

#include "router.h"
#include <arpa/inet.h>


typedef struct RoutingTableRow {
	struct in_addr ip;
	struct in_addr gw;
	struct in_addr mask;
	char iface[32];
	unsigned int is_static:1;
	unsigned int is_active:1;
} rtable_row_t;

int rtable_nextHop(router_t* router, struct in_addr* dest, struct in_addr* next_hop, int* next_hop_ifIndex);

void rtable_init(struct sr_instance* sr);
#endif

