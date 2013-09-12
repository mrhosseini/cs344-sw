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
#include <time.h>


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
	node_t* neighbors;
	time_t last_sent_hello;
} interface_t;


typedef struct nbr_router {
	uint32_t router_id;	/* net byte order */
	struct in_addr ip;	/* net byte order */
	time_t last_rcvd_hello;
} nbr_router_t;


///structure to handle router state
typedef struct Router{
	struct sr_instance* sr;///>pointer to base system simple router
	int32_t if_list_index; ///>index of active interface
	interface_t if_list[NUM_INTERFACES]; ///>list of interfaces of router
	int sockfd[NUM_INTERFACES]; ///>sockets to read from and write to nf devices
	struct nf2device netfpga; ///>NetFPGA device
	
	uint32_t router_id;
	uint32_t area_id;
	uint32_t lsu_update_needed:1;
	uint16_t pwospf_hello_interval;
	uint32_t pwospf_lsu_interval;
	uint32_t pwospf_lsu_broadcast;
	uint32_t dijkstra_dirty;
	
	node_t* arp_cache;///> a linked list showing ARP cache
	node_t* arp_queue;///> a linked list for ARP queue
	node_t* rtable;///>a linked list for routing table
	node_t* pwospf_router_list;///> a linked list for PWOSPF router list
	node_t* pwospf_lsu_queue;///> a linked list for PWOSFP LSU packets
	
	
	pthread_rwlock_t lock_arp_cache; ///> access lock for ARP cache
	pthread_rwlock_t lock_arp_queue;///> access lock for ARP queue
	pthread_rwlock_t lock_rtable;///> access lock for routing table
	pthread_mutex_t lock_send;///> lock for sending packets
	pthread_mutex_t lock_pwospf_list;///> access lock for pwospf_router_list
	pthread_mutex_t lock_pwospf_queue;///> access lock for pwospf_lsu_queue
	pthread_mutex_t lock_dijkstra;
	pthread_mutex_t lock_pwospf_bcast;
	
	pthread_cond_t dijkstra_cond;
	pthread_cond_t pwospf_lsu_bcast_cond;
	
	pthread_t arp_thread;///>ARP thread	
	pthread_t dijkstra_thread;
	pthread_t pwospf_lsu_thread;
	pthread_t pwospf_hello_thread;
	pthread_t pwospf_lsu_bcast_thread;
	pthread_t pwospf_lsu_timeout_thread;
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

int router_unlockMutex(pthread_mutex_t* mutex);

int router_lockMutex(pthread_mutex_t* mutex);

interface_t* router_getInterfaceByRid(interface_t* if_list, uint32_t rid);

interface_t* router_getInterfaceByMask(interface_t* if_list, struct in_addr* subnet, struct in_addr* mask);

nbr_router_t* router_getNbrByRid(interface_t* iface, uint32_t rid);

#endif
