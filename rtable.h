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

int rtable_nextHop(router_t* router, struct in_addr* dest, struct in_addr* next_hop, int* next_hop_ifIndex);
#endif
