/**
 * @file netfpga.c
 * @author Mohammad Reza Hosseini 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 */

#include "netfpga.h"
#include "reg_defines.h"
#include "ll.h"


#include <stdio.h>
#include <string.h>
#include <unistd.h>


int netfpga_init(router_t* router){
	/* reset the router */
	writeReg(&router->netfpga, CPCI_REG_CTRL, 0x00010100);
	usleep(2000);
	
	/* enable DMA */
	//writeReg(&rs->netfpga, DMA_ENABLE_REG, 0x1);
	
	/*
	 * write 0's out to the rtable and arp table 
	 */
// 	write_arp_cache_to_hw(rs);
	arp_updateHw(router);
	netfpga_writeRTable(&router->netfpga, router->rtable);
	return 0;
}

int netfpga_getPortNum(const char* name){
	if (!strcmp(name, ETH0)){
		return 0;
	}
	else if (!strcmp(name, ETH1)){
		return 1;
	}
	else if (!strcmp(name, ETH2)){
		return 2;
	}
	else if (!strcmp(name, ETH3)){
		return 3;
	}
	return -1;
}

int netfpga_initInterfaces(router_t* router, interface_t* interface){
	
	/* 
	 * set this on hardware 
	 */
	unsigned int mac_hi = 0;
	mac_hi |= ((unsigned int)interface->addr[0]) << 8;
	mac_hi |= ((unsigned int)interface->addr[1]);
	unsigned int mac_lo = 0;
	mac_lo |= ((unsigned int)interface->addr[2]) << 24;
	mac_lo |= ((unsigned int)interface->addr[3]) << 16;
	mac_lo |= ((unsigned int)interface->addr[4]) << 8;
	mac_lo |= ((unsigned int)interface->addr[5]);
	
	int portNum = netfpga_getPortNum(interface->name);
	switch (portNum) {
		case 0:
			writeReg(&router->netfpga, ROUTER_OP_LUT_MAC_0_HI_REG, mac_hi);
			writeReg(&router->netfpga, ROUTER_OP_LUT_MAC_0_LO_REG, mac_lo);
			break;
		case 1:
			writeReg(&router->netfpga, ROUTER_OP_LUT_MAC_1_HI_REG, mac_hi);
			writeReg(&router->netfpga, ROUTER_OP_LUT_MAC_1_LO_REG, mac_lo);
			break;
		case 2:
			writeReg(&router->netfpga, ROUTER_OP_LUT_MAC_2_HI_REG, mac_hi);
			writeReg(&router->netfpga, ROUTER_OP_LUT_MAC_2_LO_REG, mac_lo);
			break;
		case 3:
			writeReg(&router->netfpga, ROUTER_OP_LUT_MAC_3_HI_REG, mac_hi);
			writeReg(&router->netfpga, ROUTER_OP_LUT_MAC_3_LO_REG, mac_lo);
			break;
		default:
			return 1;
	}
	
	/*
	 * TODO: is it enough or use scone approach?
	 */
	writeReg(&router->netfpga, ROUTER_OP_LUT_DST_IP_FILTER_TABLE_ENTRY_IP_REG, ntohl(interface->ip));
	writeReg(&router->netfpga, ROUTER_OP_LUT_DST_IP_FILTER_TABLE_WR_ADDR_REG, portNum);
	return 0;
}


void netfpga_writeArpCacheItem(struct nf2device* netfpga, arp_item_t* arp_item, int row){
	
	if(arp_item != NULL) {
		unsigned int mac_hi = 0;
		unsigned int mac_lo = 0;
		
		/*
		 * write the mac hi data
		 */
		mac_hi |= ((unsigned int)arp_item->arp_ha[0]) << 8;
		mac_hi |= ((unsigned int)arp_item->arp_ha[1]);
		writeReg(netfpga, ROUTER_OP_LUT_ARP_TABLE_ENTRY_MAC_HI_REG, mac_hi);
		
		/*
		 * write the mac lo data 
		 */
		mac_lo |= ((unsigned int)arp_item->arp_ha[2]) << 24;
		mac_lo |= ((unsigned int)arp_item->arp_ha[3]) << 16;
		mac_lo |= ((unsigned int)arp_item->arp_ha[4]) << 8;
		mac_lo |= ((unsigned int)arp_item->arp_ha[5]);
		writeReg(netfpga, ROUTER_OP_LUT_ARP_TABLE_ENTRY_MAC_LO_REG, mac_lo);
		
		/*
		 * write the next hop ip data 
		 */
		writeReg(netfpga, ROUTER_OP_LUT_ARP_TABLE_ENTRY_NEXT_HOP_IP_REG, ntohl(arp_item->ip.s_addr));
		
	} else {		
		/*
		 * zero out the rest of the rows 
		 */
		writeReg(netfpga, ROUTER_OP_LUT_ARP_TABLE_ENTRY_MAC_HI_REG, 0);
		writeReg(netfpga, ROUTER_OP_LUT_ARP_TABLE_ENTRY_MAC_LO_REG, 0);
		writeReg(netfpga, ROUTER_OP_LUT_ARP_TABLE_ENTRY_NEXT_HOP_IP_REG, 0);
	}
	
	/* set the row */
	writeReg(netfpga, ROUTER_OP_LUT_ARP_TABLE_WR_ADDR_REG, row);
}

void netfpga_writeRTable(struct nf2device* netfpga, node_t* rtable_head){
	/*
	 * naively iterate through the 32 slots in hardware updating all entries 
	 */
	int i = 0;
	node_t* cur = rtable_head;
	
	/*
	 * find first active entry before entering the loop 
	 */
	while (cur && !(((rtable_row_t*) cur->data)->is_active)){
		cur = cur->next;
	}
	
	for (i = 0; i < ROUTER_OP_LUT_ROUTE_TABLE_DEPTH; ++i) {
		
		if (cur) {
			rtable_row_t* row = (rtable_row_t*) cur->data;
			/*
			 * ip 
			 */
			writeReg(netfpga, ROUTER_OP_LUT_ROUTE_TABLE_ENTRY_IP_REG, ntohl(row->ip.s_addr));
			/*
			 * mask 
			 */
			writeReg(netfpga, ROUTER_OP_LUT_ROUTE_TABLE_ENTRY_MASK_REG, ntohl(row->mask.s_addr));
			/*
			 * next hop 
			 */
			writeReg(netfpga, ROUTER_OP_LUT_ROUTE_TABLE_ENTRY_NEXT_HOP_IP_REG, ntohl(row->gw.s_addr));
			/*
			 * port 
			 */
			writeReg(netfpga, ROUTER_OP_LUT_ROUTE_TABLE_ENTRY_OUTPUT_PORT_REG, netfpga_getPortId(row->iface));
			
			/*
			 * row number
			 */
			writeReg(netfpga, ROUTER_OP_LUT_ROUTE_TABLE_WR_ADDR_REG, i);
			
			/* advance at least once */
			cur = cur->next;
			
			/* find the next active entry */
			while (cur && !(((rtable_row_t*)cur->data)->is_active)) {
				cur = cur->next;
			}
		} else {
			/*
			 * write all 0
			 */
			
			/* 
			 * ip 
			 */
			writeReg(netfpga, ROUTER_OP_LUT_ROUTE_TABLE_ENTRY_IP_REG, 0);
			/* 
			 * mask 
			 */
			writeReg(netfpga, ROUTER_OP_LUT_ROUTE_TABLE_ENTRY_MASK_REG, 0);
			/*
			 * next hop 
			 */
			writeReg(netfpga, ROUTER_OP_LUT_ROUTE_TABLE_ENTRY_NEXT_HOP_IP_REG, 0);
			/*
			 * port 
			 */
			writeReg(netfpga, ROUTER_OP_LUT_ROUTE_TABLE_ENTRY_OUTPUT_PORT_REG, 0);
			/*
			 * row number
			 */
			writeReg(netfpga, ROUTER_OP_LUT_ROUTE_TABLE_WR_ADDR_REG, i);
		}
	}
}


unsigned int netfpga_getPortId(char* name) {
	if (strcmp(ETH0, name) == 0) {
		return 1;
	} else if (strcmp(ETH1, name) == 0) {
		return 4;
	} else if (strcmp(ETH2, name) == 0) {
		return 16;
	} else if (strcmp(ETH3, name) == 0) {
		return 64;
	} else if (strcmp(CPU0, name) == 0) {
		return 2;
	} else if (strcmp(CPU1, name) == 0) {
		return 8;
	} else if (strcmp(CPU2, name) == 0) {
		return 32;
	} else if (strcmp(CPU3, name) == 0) {
		return 128;
	} else {
		printf("FAILURE MATCHING NAME TO PORT ID\n");
	}
	
	return 0;
}
