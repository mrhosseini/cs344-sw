/**
 * @file ICMP.h
 * @author Mohammad Reza Hosseini 
 * 
 * 
 */
#ifndef ICMP_H_
#define ICMP_H_

#include "sr_base_internal.h"
#include "router.h"

#include <stdint.h>
#include <arpa/inet.h>

#define ICMP_TYPE_ECHO_REPLY			0x0
#define ICMP_TYPE_ECHO_REQUEST			0x8
#define ICMP_CODE_ECHO				0x0

#define ICMP_TYPE_DESTINATION_UNREACHABLE	0x3
#define ICMP_CODE_NET_UNREACHABLE		0x0
#define ICMP_CODE_HOST_UNREACHABLE		0x1
#define ICMP_CODE_PROTOCOL_UNREACHABLE		0x2
#define ICMP_CODE_PORT_UNREACHABLE 		0x3
#define ICMP_CODE_NET_UNKNOWN			0x6

#define ICMP_TYPE_TIME_EXCEEDED			0xB
#define ICMP_CODE_TTL_EXCEEDED			0x0


typedef struct ICMP_Header
{
	uint8_t icmp_type;
	uint8_t icmp_code;
	uint16_t icmp_sum;
} __attribute__ ((packed)) icmp_header_t ;



icmp_header_t* icmp_getHeader(const uint8_t* packet);

void icmp_create(icmp_header_t* icmp, uint8_t icmp_type, uint8_t icmp_code, uint8_t* payload, int payload_len);

uint16_t icmp_checksum(icmp_header_t* icmp, int payload_len);

void icmp_processPacket(struct sr_instance* sr, const uint8_t * packet, unsigned int len, const char* interface);

int icmp_sendPacket(struct sr_instance* sr, const uint8_t* src_packet, unsigned int len, uint8_t icmp_type, uint8_t icmp_code);

void icmp_processEchoReply(struct sr_instance* sr, const uint8_t* packet, unsigned int len);

#endif

