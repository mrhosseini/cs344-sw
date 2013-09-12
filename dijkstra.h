/**
 * @file dijkstra.h
 * @author Mohammad Reza Hosseini 
 * 
 * 
 */
#ifndef DIJKSTRA_H_
#define DIJKSTRA_H_

#include "router.h"
#include "rtable.h"
#include "ll.h"
#include "pwospf.h"


typedef struct route_wrapper{
	rtable_row_t entry; /* entry being wrapped, lacking next hop ip */
	uint16_t distance; /* distance from source in hops */
	uint32_t next_rid; /* next router id from source */
	uint8_t directly_connected:1; /* is this route directly connected to us? */
} route_wrapper_t;

void dijkstra_trigger(router_t* router);

void dijkstra_updateNeighborDistance(pwospf_router_t* w, node_t* pwospf_router_list);

pwospf_router_t* dijkstra_getShortest(node_t* pwospf_router_list);

node_t* dijkstra_buildRouteWrapperList(uint32_t our_rid, node_t* pwospf_router_list);

node_t* dijkstra_getRouteWrapper(node_t* head, struct in_addr* subnet, struct in_addr* mask);

void dijkstra_addRouteWrappers(uint32_t our_rid, node_t** head, pwospf_router_t* r);

node_t* dijkstra_computeRtable(uint32_t our_router_id, node_t* pwospf_router_list, interface_t* if_list);

void* dijkstra_thread(void* arg);

#endif
