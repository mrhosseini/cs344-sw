/**
 * @file router.h
 * @author Mohammad Reza Hosseini 
 * 
 * data structure and related operation for our router 
 */
#ifndef ROUTER_H_
#define ROUTER_H_

#include "sr_base_internal.h"
#include "nf2.h"
#include "nf2util.h"
#include "ll.h"

#include <stdint.h>
#include <pthread.h>


///number of hardware interfaces 
#define NUM_INTERFACES	4

#define PHY_ADDR_LEN	6
#define ETH_TYPE_IP	0x0800
#define ETH_TYPE_ARP	0x0806

///structure to hold interface data
typedef struct Interface{
	//struct sr_vns_if vns_if;
	uint32_t ip; /* nbo? */
	uint32_t mask;
	uint32_t speed;
	char name[SR_NAMELEN];
	unsigned char addr[PHY_ADDR_LEN];
} interface_t;



///structure to handle router state
typedef struct Router{
	struct sr_instance* sr;///>pointer to base system simple router
	int32_t if_list_index; ///>index of active interface
	interface_t if_list[NUM_INTERFACES]; ///>list of interfaces of router
	int sockfd[NUM_INTERFACES]; ///>sockets to read from and write to nf devices
	struct nf2device netfpga; ///>NetFPGA device
	
	node_t* arp_cache;///> a linked list showing ARP cache
	node_t* arp_queue;///> a linked list for ARP queue
	
	pthread_rwlock_t lock_arp_cache; ///> access lock for ARP cache
	pthread_rwlock_t lock_arp_queue;///> access lock for ARP queue
	pthread_rwlock_t lock_rtable;///> access lock for routing table
	
	pthread_t arp_thread;///>ARP thread
	
	
} router_t;


int router_init(struct sr_instance* sr);

int router_processPacket(struct sr_instance* sr, const uint8_t* packet, int len, const char* interface);

void router_initInterfaces(router_t* router, interface_t* interface, struct sr_vns_if vns_if);

int router_sendPacket(struct sr_instance* sr, uint8_t* packet, unsigned int len, const char* interface);

int router_lockRead(pthread_rwlock_t* lock);

int router_lockWrite(pthread_rwlock_t* lock);

int router_unlock(pthread_rwlock_t* lock);

int router_ip2mac(struct sr_instance* sr, uint8_t* packet, unsigned int len, struct in_addr* next_hop, const char* out_iface);

int router_getInterfaceIndex(router_t* router, const char* interface);

int router_getInterfaceByIp(router_t* router, uint32_t ip);


#endif
