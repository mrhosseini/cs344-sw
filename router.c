/**
 * @file router.c
 * @author Mohammad Reza Hosseini 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 */

#include "router.h"
#include "sr_integration.h"
#include "nf2util.h"
#include "nf2.h"
#include "netfpga.h"
#include "functions.h"
#include "ethernet.h"
#include "arp.h"
#include "ip.h"


#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <string.h>
#include <libnet.h>
#include <pcap.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>


void router_initInterfaces(router_t* router, interface_t *interface, struct sr_vns_if vns_if){
	printf(" ** if_init(..) called \n");
	interface->ip = vns_if.ip;
	interface->mask = vns_if.mask;
	interface->speed = vns_if.speed;
	memcpy((unsigned char*)interface->addr, vns_if.addr, PHY_ADDR_LEN);
	strcpy(interface->name, vns_if.name);
	interface->neighbors = NULL;
	interface->last_sent_hello = 0;
	netfpga_initInterfaces(router, interface);
	return;
}


int router_init(struct sr_instance* sr){
	router_t* router = (router_t*) malloc(sizeof(router_t));
	assert(router);
	
	
	/*
	 * init sockets
	 */
	int base = 0;
	
	char iface_name[32] = "nf2c";
	int i;
	for (i = 0; i < NUM_INTERFACES; ++i) {
		sprintf(&(iface_name[4]), "%i", base+i);
		int s = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
		
		struct ifreq ifr;
		bzero(&ifr, sizeof(struct ifreq));
		strncpy(ifr.ifr_ifrn.ifrn_name, iface_name, IFNAMSIZ);
		if (ioctl(s, SIOCGIFINDEX, &ifr) < 0) {
			perror("ioctl SIOCGIFINDEX");
			exit(1);
		}
		
		struct sockaddr_ll saddr;
		bzero(&saddr, sizeof(struct sockaddr_ll));
		saddr.sll_family = AF_PACKET;
		saddr.sll_protocol = htons(ETH_P_ALL);
		saddr.sll_ifindex = ifr.ifr_ifru.ifru_ivalue;
		
		if (bind(s, (struct sockaddr*)(&saddr), sizeof(saddr)) < 0) {
			perror("bind error");
			exit(1);
		}
		
		router->sockfd[i] = s;
	}
	
	/*
	 * initialize other members
	 */
	router->if_list_index = 0;
	router->arp_cache = NULL;
	router->arp_queue = NULL;
	router->router_id = 0;
	router->area_id = 0;
	router->lsu_update_needed = 0;
	router->pwospf_hello_interval = 0;
	router->pwospf_lsu_interval = 0;
	router->pwospf_lsu_broadcast = 0;
	router->dijkstra_dirty = 0;
	
	
	/*
	 * initialize locks
	 */
	if (pthread_mutex_init(&router->lock_send, NULL) != 0){
		perror("Lock init error");
		exit(1);
	}
	
	if (pthread_rwlock_init(&router->lock_arp_cache, NULL) != 0){
		perror("Lock init error");
		exit(1);
	}
	
	if (pthread_rwlock_init(&router->lock_arp_queue, NULL) != 0){
		perror("Lock init error");
		exit(1);
	}
	
	if (pthread_rwlock_init(&router->lock_rtable, NULL) != 0){
		perror("Lock init error");
		exit(1);
	}
	
	if (pthread_mutex_init(&router->lock_pwospf_list, NULL) != 0){
		perror("Lock init error");
		exit(1);
	}
	
	if (pthread_mutex_init(&router->lock_pwospf_queue, NULL) != 0){
		perror("Lock init error");
		exit(1);
	}
	
	if (pthread_mutex_init(&router->lock_dijkstra, NULL) != 0){
		perror("Lock init error");
		exit(1);
	}
	
	if (pthread_mutex_init(&router->lock_pwospf_bcast, NULL) != 0){
		perror("Lock init error");
		exit(1);
	}
	
	
	/*
	 * initialize conditions
	 */
	if (pthread_cond_init(&router->pwospf_lsu_bcast_cond, NULL) != 0){
		perror("LSU bcast cond init error");
		exit(1);
	}
	
	if (pthread_cond_init(&router->dijkstra_cond, NULL) != 0){
		perror("Dijkstra cond init error");
		exit(1);
	}
	
	/*
	 * register with the global instance
	 */
	sr_set_subsystem(get_sr(), router);
	
	
	
	#ifdef _CPUMODE_
// 	rs->is_netfpga = 1;
	char* name = (char*)calloc(1, 32);
	strncpy(name, "nf2c0", 5);
	router->netfpga.device_name = name;
	router->netfpga.fd = 0;
	router->netfpga.net_iface = 0;
	
	if (check_iface(&(router->netfpga))){
		printf("Failure connecting to NETFPGA\n");
		exit(1);
	}
	
	if (openDescriptor(&(router->netfpga))){
		printf("Failure connecting to NETFPGA\n");
		exit(1);
	}
	
	/* 
	 * initialize the hardware 
	 */
	netfpga_init(router);
	
	#else
	//rs->is_netfpga = 0;
	#endif
	
	/*
	 * create ARP thread
	 */
	if (pthread_create(&router->arp_thread, NULL, arp_thread, (void *)sr) != 0){
		perror("ARP thread create error");
	}
	
	/*
	 * save a pointer to global instance
	 */
	router->sr = sr;
	
	return 0;
}

int router_processPacket(struct sr_instance* sr, const uint8_t* packet, int len, const char* interface){
	
	/*
	 * check ethernet header type
	 */
	uint16_t eth_type = eth_getType(packet);
	
	eth_header_t* eth_hdr = (eth_header_t*) packet;
	int i = 0;
	printf("\n\n\tEthernet Header: ");
	printf("\n\t\tDestination: ");
	for (i = 0; i < ETH_ADDR_LEN; i++){
		if (i > 0)
			printf(":");
		printf("%02X",eth_hdr->d_addr[i]);
	}
	printf("\n\t\tSource: ");
	for (i = 0; i < ETH_ADDR_LEN; i++){
		if (i > 0)
			printf(":");
		printf("%02X",eth_hdr->d_addr[i]);
	}
	printf("\n\t\tType: %04X", eth_hdr->type);
	printf("\n\n");
	
	switch(eth_type){
		case ETH_TYPE_ARP:
			printf("\n Packet Type: ARP, length: %d, Interface: %s", len, interface);				
			arp_processPacket(sr, packet, len, interface);
			break;
		case ETH_TYPE_IP:
			printf("\n Packet Type: IP,  length: %d, Interface: %s",len, interface);
			ip_processPacket(sr, packet, len, interface);
			break;
		default:
			printf("\n Packet Type: %X (UNKNOWN), length: %d, Interface: %s",eth_type, len, interface);
	}
	return 0;
}


int router_sendPacket(struct sr_instance* sr, uint8_t* packet, unsigned int len, const char* interface) {
	router_t* router = sr_get_subsystem(sr);
	if (pthread_mutex_lock(&router->lock_send) != 0) {
		perror("Failure locking write lock\n");
		exit(1);
	}
	
	int result = 0;
	
	if (len < 60) {
		int pad_len = 60 - len;
		uint8_t* pad_packet = (uint8_t*) malloc (len + pad_len);
		if (!pad_packet) {
			perror("Failed to malloc in send_packet().\n");
			exit(1);
		}
		
		bzero(pad_packet, len + pad_len);
		memmove(pad_packet, packet, len);
		
		printf("\n Sending packet with size = %d, from interface %s ", len+pad_len, interface);
		
		result = sr_integ_low_level_output(sr, pad_packet, len+pad_len, interface);
		
		free(pad_packet);
	} else {
		printf("\n Sending packet with size = %d, from interface %s ", len, interface);
		result = sr_integ_low_level_output(sr, packet, len, interface);
	}
	
	/*
	 * print_packet(packet, len);
	 */
	
	if (pthread_mutex_unlock(&router->lock_send) != 0) {
		perror("Failure unlocking write lock\n");
		exit(1);
	}
	
	return result;
}


int router_lockRead(pthread_rwlock_t* lock){
	if (pthread_rwlock_rdlock(lock) != 0){
		perror("pthread_rwlock_rdlock");
		return -1;
	}
	return 0;
}


int router_lockWrite(pthread_rwlock_t* lock){
	if (pthread_rwlock_wrlock(lock) != 0){
		perror("pthread_rwlock_wrlock");
		return -1;
	}
	return 0;
}

int router_unlock(pthread_rwlock_t* lock){
	if (pthread_rwlock_unlock(lock) != 0) {
		perror("Failure releasing lock");
		return -1;
	}
	return 0;
}

int router_lockMutex(pthread_mutex_t* mutex){
	if (pthread_mutex_lock(mutex) != 0){
		perror("Failure locking mutex\n");
		return -1;
	}
	return 0;
}

int router_unlockMutex(pthread_mutex_t* mutex){
	if (pthread_mutex_unlock(mutex) != 0){
		perror("Failure unlocking mutex\n");
		return -1;
	}
	return 0;
}



/**
 * find ETH address of packet and send it, if not find add to queue
 */
int router_ip2mac(struct sr_instance* sr, uint8_t* packet, unsigned int len, struct in_addr* next_hop, const char* out_iface) {
	
	router_t* router = (router_t*) sr_get_subsystem(sr);
	eth_header_t* eth = (eth_header_t*) packet;
	
	
	arp_item_t* arp_item = arp_searchCache(router, next_hop);
 	if (arp_item) {
		memcpy(eth->d_addr, arp_item->arp_ha, ETH_ADDR_LEN);
		
		if (router_sendPacket(sr, packet, len, out_iface) != 0) {
			printf("Failure sending IP packet\n");
			free(packet);
			return 1;
		}
		
		free(packet);
	} else {
		/* 
		 * add the packet to the queue, will free later 
		 */
		arp_qAdd(sr, packet, len, out_iface, next_hop);
	}
	
	return 0;
}

int router_getInterfaceIndex(router_t* router, const char* interface){
	int i = 0;
	for (i = 0; i < NUM_INTERFACES; i++){
		if (!strcmp(router->if_list[i].name, interface)){
			return i;
		}
	}
	return -1;
}


int router_getInterfaceByIp(router_t* router, uint32_t ip){
	int i = 0;
	for (i = 0; i < NUM_INTERFACES; i++){
		if (router->if_list[i].ip == ip){
			return i;
		}
	}
	return -1;
}