/**
 * @file ethernet.h
 * @author Mohammad Reza Hosseini 
 * 
 * 
 */
#ifndef ETHERNET_H_
#define ETHERNET_H_

#include <stdint.h>

#define ETH_ADDR_LEN	6
#define ETH_HDR_LEN	14

typedef struct Ethernet_Header{
	uint8_t d_addr[ETH_ADDR_LEN];
	uint8_t s_addr[ETH_ADDR_LEN];
	uint16_t type;
} __attribute__ ((packed)) eth_header_t;

uint16_t eth_getType(const uint8_t* packet);

void eth_createHeader(eth_header_t* eth_hdr, uint8_t* d_addr, uint8_t *s_addr, uint16_t type);

#endif
