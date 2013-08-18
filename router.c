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
	netfpga_initInterfaces(router, interface);
	return;
}


int router_init(struct sr_instance* sr){
	router_t* router = (router_t*) malloc(sizeof(router_t));
	assert(router);
	
	
	/*
	 * init sockets
	 */
	//struct sr_instance* sr = (struct sr_instance*)rs->sr;
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
	
	if (check_iface(&(router->netfpga))) {
		printf("Failure connecting to NETFPGA\n");
		exit(1);
	}
	
	if (openDescriptor(&(router->netfpga))) {
		printf("Failure connecting to NETFPGA\n");
		exit(1);
	}
	
	/* initialize the hardware */
	netfpga_init(router);
	
	#else
	//rs->is_netfpga = 0;
	#endif
	
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
	
	int i = 0;
	printf("\n");
	for (i = 0; i < 6 + 6 + 2; i++){
		printf("%02X ", packet[i]);
	}
	printf("\n");
	uint16_t eth_type = eth_getType(packet);
	switch(eth_type){
		case ETH_TYPE_ARP:
			printf("\nPacket Type: ARP, length: %d, Interface: %s", len, interface);
			break;
		case ETH_TYPE_IP:
			printf("\nPacket Type: IP,  length: %d, Interface: %s",len, interface);
			break;
		default:
			printf("\nPacket Type: UNKNOWN, length: %d, Interface: %s",len, interface);
	}
	
	return 0;
}


int router_sendPacket(struct sr_instance* sr, uint8_t* packet, unsigned int len, const char* interface) {
// 	router_t* router = sr_get_subsystem(sr);
// 	if (pthread_mutex_lock(rs->write_lock) != 0) {
// 		perror("Failure locking write lock\n");
// 		exit(1);
// 	}TODO: lock
	
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
	
// 	if (pthread_mutex_unlock(rs->write_lock) != 0) {
// 		perror("Failure unlocking write lock\n");
// 		exit(1);
// 	}TODO: unlock
	
	return result;
}