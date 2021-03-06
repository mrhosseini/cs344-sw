/**
 * @file arp.h
 * @author Mohammad Reza Hosseini 
 * 
 * 
 */
#ifndef ARP_H_
#define ARP_H_

#include "sr_base_internal.h"
#include "router.h"
#include "ethernet.h"
#include "ll.h"


#define ARP_HRD_ETHERNET 	0x0001
#define ARP_PRO_IP 		0x0800
#define ARP_OP_REQUEST 		1
#define ARP_OP_REPLY		2


#define ARP_REQUEST_INTERVAL	1 //seconds
#define ARP_MAX_REQUESTS	5
#define ARP_TIMEOUT		300 //seconds

typedef struct Arp_Header{
	unsigned short  arp_hrd;             /* format of hardware address   */
	unsigned short  arp_pro;             /* format of protocol address   */
	unsigned char   arp_hln;             /* length of hardware address   */
	unsigned char   arp_pln;             /* length of protocol address   */
	unsigned short  arp_op;              /* ARP opcode (command)         */
	unsigned char   arp_sha[ETH_ADDR_LEN];   /* sender hardware address      */
	struct in_addr  arp_sip;             /* sender IP address            */
	unsigned char   arp_tha[ETH_ADDR_LEN];   /* target hardware address      */
	struct in_addr  arp_tip;             /* target IP address            */
	
} __attribute__ ((packed)) arp_header_t;


typedef struct Arp_Item{
	struct in_addr ip;			/* target IP address */
	unsigned char arp_ha[ETH_ADDR_LEN];	/* target hardware address */
	time_t ttl;				/* time expiration of entry */
	int is_static;
} __attribute__ ((packed)) arp_item_t;



#define IF_LEN 32

typedef struct Arp_QueueItem{
	char out_iface_name[IF_LEN];
	struct in_addr next_hop;
	int requests;
	time_t last_req_time;
	node_t* head;
	int is_static;
} __attribute__ ((packed)) arp_queue_item_t;

typedef arp_queue_item_t arp_qi_t;


typedef struct ARP_QueuePacket {
	uint8_t* packet;
	unsigned int len;
} arp_queue_packet_t;

typedef arp_queue_packet_t arp_qp_t;

arp_header_t* arp_getHeader(const uint8_t* packet);

void arp_processPacket(struct sr_instance *sr, const uint8_t *packet, unsigned int len, const char *interface);

void arp_processRequest( struct sr_instance *sr, const uint8_t *packet, unsigned int len, const char *interface);

void arp_processReply(struct sr_instance *sr, const uint8_t *packet, unsigned int len, const char *interface);

void arp_createHeader(arp_header_t* arp_header, uint8_t* arp_tha, uint32_t arp_tip, uint8_t* arp_sha, uint32_t arp_sip, uint16_t op);

void arp_sendReply(struct sr_instance *sr, const uint8_t *packet, unsigned int len, int interface_index);

void arp_updateCache(struct sr_instance* sr, struct in_addr* remote_ip, uint8_t* remote_mac, int is_static);

arp_item_t* arp_searchCache(router_t* router, struct in_addr* ip_addr);

void arp_updateHw(router_t* router);

void arp_sendRequest(struct sr_instance* sr, uint32_t tip /* Net byte order */, const char* interface);

void arp_qAddPacket(arp_qi_t* aqi, uint8_t* packet, unsigned int len);

arp_qi_t* arp_qSearch(router_t* router, struct in_addr* ip);

void arp_qAdd(struct sr_instance* sr, uint8_t* packet, unsigned int len, const char* out_iface_name, struct in_addr *next_hop);

void arp_checkQueue(struct sr_instance* sr, struct in_addr* dest_ip, unsigned char* dest_mac);

void arp_processQueue(struct sr_instance* sr);

void arp_expireCache(struct sr_instance* sr);

void* arp_thread(void *param);
	
#endif

