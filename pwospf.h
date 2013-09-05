/**
 * @file pwospf.h
 * @author Mohammad Reza Hosseini 
 * 
 * 
 */
#ifndef PWOSPF_H_
#define PWOSPF_H_

#include "ll.h"
#include "sr_base_internal.h"
#include "router.h"

#include <stdint.h>
#include <arpa/inet.h>


#define PWOSPF_HDR_LEN 			24

#define PWOSPF_VERSION			0x2
#define PWOSPF_TYPE_HELLO		0x1
#define PWOSPF_TYPE_LINK_STATE_UPDATE	0x4

#define PWOSPF_AREA_ID 			0x0
#define PWOSPF_HELLO_TIP 		0xe0000005

#define PWOSPF_NEIGHBOR_TIMEOUT 	5
#define PWOSPF_LSUINT 			30
#define PWOSPF_HELLO_PADDING 		0x0

#ifndef IF_LEN
#define IF_LEN	32
#endif


typedef struct pwospf_interface {
	struct in_addr subnet;
	struct in_addr mask;
	uint32_t router_id;
	uint32_t is_active:1;
} pwospf_iface_t;

typedef struct pwospf_router {
	uint32_t router_id;
	uint32_t area_id;
	// 	uint16_t lsu_int;
	uint16_t seq;
	time_t last_update;
	uint32_t distance;
	unsigned int shortest_path_found:1;
	node_t* interface_list;
	struct pwospf_router* prev_router;
} pwospf_router_t;



typedef struct pwospf_lsu_queue_entry {
	struct in_addr ip;
	char iface[IF_LEN];
	uint8_t *packet;
	unsigned int len;
} pwospf_lsu_item_t;


typedef struct PWOSPF_Header{
	uint8_t pwospf_ver;
	uint8_t pwospf_type;
	uint16_t pwospf_len;
	uint32_t pwospf_rid;
	uint32_t pwospf_aid;
	uint16_t pwospf_sum;
	uint16_t pwospf_atype;
	uint32_t pwospf_auth1;
	uint32_t pwospf_auth2;
} __attribute__ ((packed)) pwospf_header_t;


typedef struct PWOSPF_Hello_Header{
	struct in_addr pwospf_mask;
	uint16_t pwospf_hint;
	uint16_t pwospf_pad;
} __attribute__ ((packed)) pwospf_hello_header_t;


typedef struct PWOSFP_LSU_Header{
	uint16_t pwospf_seq;
	uint16_t pwospf_ttl;
	uint32_t pwospf_num;
} __attribute__ ((packed)) pwospf_lsu_header_t;


typedef struct pwospf_lsu_adv{
	struct in_addr pwospf_sub;
	struct in_addr pwospf_mask;
	uint32_t pwospf_rid;
} __attribute__ ((packed)) pwospf_lsu_adv_t;


void pwospf_processPacket(struct sr_instance* sr, const uint8_t * packet, unsigned int len, const char* interface);

int pwospf_isValid(router_t* router, const uint8_t *packet, unsigned int len);

pwospf_header_t* pwospf_getHeader(const uint8_t* packet);

pwospf_hello_header_t* pwospf_getHelloHeader(const uint8_t* packet);

pwospf_lsu_header_t* pwospf_getLsuHeader(const uint8_t* packet);

uint8_t* pwospf_getLsuData(const uint8_t* packet);

uint16_t pwospf_checksum(pwospf_header_t* pwospf_hdr);

pwospf_router_t* pwospf_searchList(uint32_t rid, node_t* pwospf_router_list);

void pwospf_propagate(router_t* router, char* exclude_this_interface);

void pwospf_processHello(struct sr_instance* sr, const uint8_t * packet, unsigned int len, const char* interface);

void pwospf_determineActiveIface(router_t*  router, pwospf_router_t* pwospf_router);

void pwospf_lsuFlood(router_t* router, char* exclude_this_interface);

void pwospf_lsuConstruct(router_t* rotuer, uint8_t** pwospf_packet, unsigned int* pwospf_packet_len);

void pwospf_lsuAdvConstruct(router_t* router, pwospf_lsu_adv_t** lsu_adv, uint32_t* pwospf_num);

void pwospf_createHeader(pwospf_header_t* pwospf_hdr, uint8_t type, uint16_t len, uint32_t rid, uint32_t aid);

void pwospf_createHelloHeader(pwospf_hello_header_t* hello, uint32_t mask, uint16_t helloint);

void pwospf_createLsuHeader(pwospf_lsu_header_t* lsu, uint16_t seq, uint32_t num);

void pwospf_lsuBroadcast(router_t* router, pwospf_header_t* pwospf_hdr, struct in_addr* src_ip);

void pwospf_processLsu(struct sr_instance* sr, const uint8_t * packet, unsigned int len, const char* interface);

int pwospf_populateInterfaceList(pwospf_router_t *router, uint8_t *packet, unsigned int len);

void pwospf_addNeighbor(router_t* router, const uint8_t* packet, unsigned int len);

void* pwospf_helloThread(void* param);

void* pwospf_lsuThread(void* param);

void pwospf_helloBroadcast(struct sr_instance* sr);
#endif
