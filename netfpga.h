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


#define ETH0 "eth0"
#define ETH1 "eth1"
#define ETH2 "eth2"
#define ETH3 "eth3"

///structure to handle netfpga state
typedef struct netfpga{
	
} netfpga_t;

int netfpga_init(router_t* router);
int netfpga_initInterfaces(router_t* router, interface_t* interface);
int netfpga_getPortNum(const char* name);

#endif
