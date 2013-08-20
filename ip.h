/**
* @file ip.h
* @author Mohammad Reza Hosseini 
* 
* 
*/
#ifndef IP_H_
#define IP_H_

#include "sr_base_internal.h"

#include <stdint.h>
#include <arpa/inet.h>

#define IP_PROTO_ICMP		0x0001  /* ICMP protocol */
#define IP_PROTO_TCP		0x0006  /* TCP protocol */
#define IP_PROTO_UDP		0x0011	/* UDP protocol */
#define IP_PROTO_PWOSPF		0x0059	/* PWOSPF protocol (OSPF)*/
#define	IP_FRAG_RF 		0x8000	/* reserved fragment flag */
#define	IP_FRAG_DF 		0x4000	/* dont fragment flag */
#define	IP_FRAG_MF 		0x2000	/* more fragments flag */
#define	IP_FRAG_OFFMASK 	0x1fff	/* mask for fragmenting bits */


typedef struct Ip_Header{
	unsigned int ip_hl:4;		/* header length */
	unsigned int ip_v:4;		/* version */
	uint8_t ip_tos;			/* type of service */
	uint16_t ip_len;		/* total length */
	uint16_t ip_id;			/* identification */
	uint16_t ip_off;		/* fragment offset field */
	uint8_t ip_ttl;			/* time to live */
	uint8_t ip_p;			/* protocol */
	uint16_t ip_sum;		/* checksum */
	struct in_addr ip_src, ip_dst;	/* source and dest address */
} __attribute__ ((packed)) ip_header_t ;


int ip_verifyChecksum(uint8_t *data, unsigned int data_length);

int ip_isValid(const uint8_t * packet, unsigned int len);

ip_header_t* ip_getHeader(const uint8_t* packet);

void ip_processPacket(struct sr_instance* sr, const uint8_t * packet, unsigned int len, const char* interface);

#endif
