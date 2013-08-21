/**
 * @file netfpga.h
 * @author Mohammad Reza Hosseini 
 * 
 * data structure and related operation for interaction with netfpga boards
 */
#ifndef NETFPGA_H_
#define NETFPGA_H_

#include "sr_base_internal.h"
#include "nf2.h"
#include "nf2util.h"
#include "router.h"
#include "arp.h"
#include "rtable.h"


#define ETH0 "eth0"
#define ETH1 "eth1"
#define ETH2 "eth2"
#define ETH3 "eth3"
#define CPU0 "cpu0"
#define CPU1 "cpu1"
#define CPU2 "cpu2"
#define CPU3 "cpu3"

///structure to handle netfpga state
typedef struct netfpga{
	
} netfpga_t;

int netfpga_init(router_t* router);

int netfpga_initInterfaces(router_t* router, interface_t* interface);

int netfpga_getPortNum(const char* name);

void netfpga_writeArpCacheItem(struct nf2device* netfpga, arp_item_t* arp_item, int row);

void netfpga_writeRTable(struct nf2device* netfpga, node_t* rtable_head);

unsigned int netfpga_getPortId(char* name);

#endif

