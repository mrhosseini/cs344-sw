/**
* @file ethernet.c
* @author Mohammad Reza Hosseini 
* 
* 
*/
#include "ethernet.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

uint16_t eth_getType(const uint8_t* packet){
	/*
	 * ethernet header structure: sorce_addr[ 6 bytes], dest_addr[ 6 bytes], type [2 bytes]
	 * type is network byte order
	 */
	uint16_t type;
	memcpy((uint8_t*)&type, &packet[ETH_ADDR_LEN * 2], 2);
	return ntohs(type);
}

void eth_createHeader(eth_header_t* eth_hdr, uint8_t* d_addr, uint8_t *s_addr, uint16_t type){
	/*
	 * ethernet header structure: sorce_addr[ 6 bytes], dest_addr[ 6 bytes], type [2 bytes]
	 * type is network byte order
	 */
	if (d_addr) {
		memcpy(eth_hdr->d_addr, d_addr, ETH_ADDR_LEN);
	}
	memcpy(eth_hdr->s_addr, s_addr, ETH_ADDR_LEN);
	eth_hdr->type = htons(type);
	return;
}
