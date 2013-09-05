/**
 * @file pwospf.h
 * @author Mohammad Reza Hosseini 
 * 
 * 
 */
#include "pwospf.h"
#include "router.h"
#include "ip.h"
#include "ethernet.h"
#include "dijkstra.h"

#include <assert.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void pwospf_processPacket(struct sr_instance* sr, const uint8_t * packet, unsigned int len, const char* interface){
	
	assert(sr);
	assert(packet);
	assert(interface);
	
	router_t* router = sr_get_subsystem(sr);
	
	/*
	 * Check if the packet is invalid, if so drop it 
	 */
	if (!pwospf_isValid(router, packet, len)){
		return;
	}
	
	pwospf_header_t* pwospf_hdr = pwospf_getHeader(packet);
	
	if (pwospf_hdr->pwospf_type == PWOSPF_TYPE_HELLO){
		pwospf_processHello(sr, packet, len, interface);
	} else if (pwospf_hdr->pwospf_type == PWOSPF_TYPE_LINK_STATE_UPDATE){
		pwospf_processLsu(sr, packet, len, interface);
	}
}


int pwospf_isValid(router_t* router, const uint8_t *packet, unsigned int len){
	
	pwospf_header_t* pwospf_hdr = pwospf_getHeader(packet);
	
	
	/*
	 * Check for PWOSPFV2 
	 */
	if(pwospf_hdr->pwospf_ver != 2) {
		return 0;
	}
	
	uint16_t pckt_sum = htons(pwospf_hdr->pwospf_sum);
	uint16_t sum = pwospf_checksum(pwospf_hdr);
	
	/*
	 * Check the checksum 
	 */
	if(pckt_sum != sum) {
		return 0;
	}
	
	/*
	 * Check authtype is set to 0 
	 */
	if(ntohs(pwospf_hdr->pwospf_atype) != 0) {
		return 0;
	}
	
	/*
	 * Check for area id 
	 */
	if(ntohl(pwospf_hdr->pwospf_aid) != router->area_id) {
		return 0;
	}
	
	/*
	 * if router id is equal to ours we need to dump the packet 
	 */
	if (ntohl(pwospf_hdr->pwospf_rid) == router->router_id) {
		return 0;
	}
	
	return 1;
}


pwospf_header_t* pwospf_getHeader(const uint8_t* packet){
	return (pwospf_header_t*) (packet + ETH_HDR_LEN + sizeof(ip_header_t));
}

pwospf_hello_header_t* pwospf_getHelloHeader(const uint8_t* packet){
	return (pwospf_hello_header_t*) (packet + ETH_HDR_LEN + sizeof(ip_header_t) + sizeof(pwospf_header_t));
}

pwospf_lsu_header_t* pwospf_getLsuHeader(const uint8_t* packet){
	return (pwospf_lsu_header_t*) (packet + ETH_HDR_LEN + sizeof(ip_header_t) + sizeof(pwospf_header_t));
}

uint8_t* pwospf_getLsuData(const uint8_t* packet){
	return (uint8_t*) (packet + ETH_HDR_LEN + sizeof(ip_header_t) + sizeof(pwospf_header_t) + sizeof(pwospf_lsu_header_t));
}

uint16_t pwospf_checksum(pwospf_header_t* pwospf_hdr){
	
	pwospf_hdr->pwospf_sum = 0;
	unsigned long sum = 0;
	uint16_t s_sum = 0;
	int numShorts = ntohs(pwospf_hdr->pwospf_len) / 2;
	int i = 0;
	uint16_t* s_ptr = (uint16_t*)pwospf_hdr;
	
	for (i = 0; i < numShorts; ++i) {
		/* 
		 * sum all except checksum and authentication fields 
		 */
		if ( i < 8 ||  11 < i ) {
			sum += ntohs(*s_ptr);
		}
		++s_ptr;
	}
	
	
	/*
	 * sum carries 
	 */
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	
	/*
	 * ones compliment 
	 */
	s_sum = sum & 0xFFFF;
	s_sum = (~s_sum);
	
	return s_sum;
}

void pwospf_processHello(struct sr_instance* sr, const uint8_t * packet, unsigned int len, const char* interface){
	router_t* router = sr_get_subsystem(sr);
	ip_header_t* iphdr = ip_getHeader(packet);
	pwospf_header_t* pwospf_hdr = pwospf_getHeader(packet);
	pwospf_hello_header_t* hello_hdr = pwospf_getHelloHeader(packet);
	int update_neighbors = 0;
	
	
	/*
	 * Drop the packet if the hello values don't match 
	 */
	if (router->pwospf_hello_interval != ntohs(hello_hdr->pwospf_hint)) {
		return;
	}
	
	/*
	 * We got a hello packet so we definitely need to unlock and relock interface in write mode 
	 */
	router_unlock(&router->lock_rtable);
	router_lockRead(&router->lock_rtable);
	router_lockMutex(&router->lock_pwospf_list);
	
	int interfaceIndex = router_getInterfaceIndex(router, interface);
	interface_t* iface = &router->if_list[interfaceIndex];
	
	
	/*
	 * Drop the packet if the masks don't match 
	 */
	if (router->if_list[interfaceIndex].mask != hello_hdr->pwospf_mask.s_addr) {
		return;
	}
	
	/*
	 * do we have a neighbor with this info ? 
	 */
	node_t* cur = router->if_list[interfaceIndex].neighbors;
	nbr_router_t* match = NULL;
	while (cur) {
		nbr_router_t* nbr = (nbr_router_t*)cur->data;
		if ((nbr->ip.s_addr == iphdr->ip_src.s_addr) &&
		    ( router->if_list[interfaceIndex].mask == hello_hdr->pwospf_mask.s_addr) &&
		    (nbr->router_id == pwospf_hdr->pwospf_rid)){
			match = nbr;
		}
		
		cur = cur->next;
	}
	
	/*
	 * if we didn't find this neighbor, update with this packet info 
	 */
	if (match == NULL){
		//printf("HELLO updated interface %s with a new neighbor\n", iface->addr);
		nbr_router_t* nbr = (nbr_router_t*) calloc(1, sizeof(nbr_router_t));
		time(&(nbr->last_rcvd_hello));
		nbr->ip.s_addr = iphdr->ip_src.s_addr;
		nbr->router_id = pwospf_hdr->pwospf_rid;
		
		node_t* n = node_create();
		n->data = nbr;
		if (router->if_list[interfaceIndex].neighbors == NULL){
			router->if_list[interfaceIndex].neighbors = n;
		} else {
			node_push_back(router->if_list[interfaceIndex].neighbors, n);
		}
		
		/*
		 * update our router's associated interface neighbor 
		 */
		pwospf_router_t* r = pwospf_searchList(router->router_id, router->pwospf_router_list);
		assert(r);
		
		
		/*
		 * find the pwospf_interface on our router so we can update the neighboring rid 
		 */
		node_t* cur = r->interface_list;
		int found = 0;
		while (cur) {
			pwospf_iface_t* interface = (pwospf_iface_t*)cur->data;
			/*
			 * check if we have an interface with a blank router id 
			 */
			if ((interface->subnet.s_addr == (iface->ip & iface->mask)) && (interface->mask.s_addr == iface->mask) && (interface->router_id == 0)) {
				interface->router_id = nbr->router_id;
				found = 1;
				break;
			}
			cur = cur->next;
		}
		if (!found) {
			/*
			 * add a new interface 
			 */
			pwospf_iface_t *interface = (pwospf_iface_t*)calloc(1, sizeof(pwospf_iface_t));
			interface->subnet.s_addr = (iface->ip & iface->mask);
			interface->mask.s_addr = iface->mask;
			interface->router_id = pwospf_hdr->pwospf_rid;
			node_t* n = node_create();
			n->data = interface;
			
			assert(r->interface_list);
			node_push_back(r->interface_list, n);
		}
		
		
		/*
		 * received a hello from a new neighbor interfaces
		 */
		update_neighbors = 1;
		
		
	} 
	else{
		/*
		 * Update an existing interface 
		 */
		
		/*
		 * this is an update from our neighbor 
		 */
		time(&(match->last_rcvd_hello));
	}
	
	
	/*
	 * Build packets to inform all our neighbors 
	 */
	if (update_neighbors == 1) {
		pwospf_propagate(router, NULL);
	}
	
	
	router_unlockMutex(&router->lock_pwospf_list);
	/* unlocking of the above will be automatically performed in process ip packet */
	
	
	/*
	 * Signal thread to send new information to all our neigbors 
	 */
	if (update_neighbors == 1) {
		pthread_cond_signal(&router->pwospf_lsu_bcast_cond);
	}
	
}


pwospf_router_t* pwospf_searchList(uint32_t rid, node_t* pwospf_router_list){
	node_t* cur = pwospf_router_list;
	while (cur) {
		pwospf_router_t* r = (pwospf_router_t*)cur->data;
		if (r->router_id == rid) {
			return r;
		}
		cur = cur->next;
	}
	
	return NULL;
}

void pwospf_propagate(router_t* router, char* exclude_this_interface){
	
	/*
	 * update the interface entries in every router entry 
	 */
	node_t* n = router->pwospf_router_list;
	while(n) {
		pwospf_router_t* pwospf_router = (pwospf_router_t*) n->data;
		pwospf_determineActiveIface(router, pwospf_router);
		
		n = n->next;
	}
	
	/*
	 * recompute fwd table 
	 */
	dijkstra_trigger(router);
	
	/*
	 * build a new IP-LSU update packet 
	 */
	pwospf_lsuFlood(router, exclude_this_interface);
}

void pwospf_determineActiveIface(router_t*  router, pwospf_router_t* pwospf_router){
	
	node_t *il_this_walker = pwospf_router->interface_list;
	while(il_this_walker) {
		
		pwospf_iface_t* pi_this = (pwospf_iface_t*) il_this_walker->data;
		pi_this->is_active = 0;
		
		pwospf_router_t* another_router = pwospf_searchList(pi_this->router_id, router->pwospf_router_list);
		if (another_router) {
			node_t* il_another_walker = another_router->interface_list;
			while (il_another_walker){
				pwospf_iface_t* pi_another = (pwospf_iface_t*) il_another_walker->data;
				
				if ( (pi_this->subnet.s_addr == pi_another->subnet.s_addr) &&
				     (pi_this->mask.s_addr == pi_another->mask.s_addr) &&
				     (!( (pi_this->router_id == 0) || (pi_another->router_id == 0) ) )
				){
					pi_this->is_active = 1;
					pi_another->is_active = 1;
				}
				
				il_another_walker = il_another_walker->next;
			}
		}	
		il_this_walker = il_this_walker->next;
	}
}

void pwospf_lsuFlood(router_t* router, char* exclude_this_interface){
	/*
	 * If the flag is set to not broadcast, exit 
	 */
	if (!router->pwospf_lsu_broadcast) {
		return;
	}
	
	/*
	 * SEND LSU PACKETS 
	 */
	uint8_t* pwospf_packet = 0;
	unsigned int pwospf_packet_len = 0;
	pwospf_header_t* pwospf_hdr = 0;
	
	pwospf_lsuConstruct(router, &pwospf_packet, &pwospf_packet_len);
	
	pwospf_hdr = (pwospf_header_t*) pwospf_packet;
	
	pwospf_lsuBroadcast(router, pwospf_hdr, NULL);
	free(pwospf_packet);
	
	/*
	 * update the last sent flood time 
	 */
	pwospf_router_t* our_router = pwospf_searchList(router->router_id, router->pwospf_router_list);
	time(&(our_router->last_update));
}


void pwospf_lsuConstruct(router_t* router, uint8_t** pwospf_packet, unsigned int* pwospf_packet_len){
	
	assert(router);
	assert(pwospf_packet);
	assert(pwospf_packet_len);
	
	pwospf_router_t* our_router = pwospf_searchList(router->router_id, router->pwospf_router_list);
	assert(our_router);
	
	/*
	 * build the advertisements 
	 */
	pwospf_lsu_adv_t *iface_adv = 0;
	uint32_t pwospf_num = 0;
	pwospf_lsuAdvConstruct(router, &iface_adv, &pwospf_num);
	
	
	/*
	 * allocate memory for the packet 
	 */
	unsigned int len = sizeof(pwospf_header_t) + sizeof(pwospf_lsu_header_t) + pwospf_num * sizeof(pwospf_lsu_adv_t);
	uint8_t* packet = (uint8_t*) calloc(len, sizeof(uint8_t));
	pwospf_header_t* pwospf_hdr = (pwospf_header_t*) packet;
	pwospf_lsu_header_t* lsu = (pwospf_lsu_header_t*) (packet + sizeof(pwospf_header_t));
	uint8_t* lsu_adv = packet + sizeof(pwospf_header_t) + sizeof(pwospf_lsu_header_t);
	
	
	/*
	 * populate the fields of the packet 
	 */
	pwospf_createHeader(pwospf_hdr, PWOSPF_TYPE_LINK_STATE_UPDATE, len, router->router_id, router->area_id);
	pwospf_createLsuHeader(lsu, our_router->seq, pwospf_num);
	memcpy(lsu_adv, iface_adv, pwospf_num * sizeof(pwospf_lsu_adv_t));
	
	
	/*
	 * populate the checksum 
	 */
	pwospf_hdr->pwospf_sum = htons(pwospf_checksum(pwospf_hdr));
	
	
	*pwospf_packet = packet;
	*pwospf_packet_len = len;
	free(iface_adv);
	
	
	/*
	 * update our router entry 
	 */
	time(&our_router->last_update);
	our_router->seq += 1;
}

void pwospf_lsuAdvConstruct(router_t* router, pwospf_lsu_adv_t** lsu_adv, uint32_t* pwospf_num){
	assert(lsu_adv);
	assert(pwospf_num);
	
	node_t* cur = NULL;
	pwospf_lsu_adv_t* iface_adv = 0;
	pwospf_lsu_adv_t* iface_adv_walker = 0;
	uint32_t num = 0;
	
	pwospf_router_t* r = pwospf_searchList(router->router_id, router->pwospf_router_list);
	assert(r);
	
	num = node_length(r->interface_list);
	iface_adv = (pwospf_lsu_adv_t*) calloc(num, sizeof(pwospf_lsu_adv_t));
	iface_adv_walker = iface_adv;
	
	cur = r->interface_list;
	while (cur) {
		pwospf_iface_t* iface = (pwospf_iface_t*)cur->data;
		
		iface_adv_walker->pwospf_sub.s_addr = iface->subnet.s_addr;
		iface_adv_walker->pwospf_mask.s_addr = iface->mask.s_addr;
		iface_adv_walker->pwospf_rid = iface->router_id;
		
		cur = cur->next;
		iface_adv_walker++;
	}
	
	*lsu_adv = iface_adv;
	*pwospf_num = num;
}


void pwospf_createHeader(pwospf_header_t* pwospf_hdr, uint8_t type, uint16_t len, uint32_t rid, uint32_t aid){
	bzero(pwospf_hdr, sizeof(pwospf_header_t));
	pwospf_hdr->pwospf_ver = PWOSPF_VERSION;
	pwospf_hdr->pwospf_type = type;
	pwospf_hdr->pwospf_len = htons(len);
	pwospf_hdr->pwospf_rid = rid;
	pwospf_hdr->pwospf_aid = htonl(aid);
}


void pwospf_createHelloHeader(pwospf_hello_header_t* hello, uint32_t mask, uint16_t helloint){
	bzero(hello, sizeof(pwospf_hello_header_t));
	hello->pwospf_mask.s_addr = mask;
	hello->pwospf_hint = htons(helloint);
	hello->pwospf_pad = 0x0;
}


void pwospf_createLsuHeader(pwospf_lsu_header_t* lsu, uint16_t seq, uint32_t num){
	bzero(lsu, sizeof(pwospf_lsu_header_t));
	lsu->pwospf_seq = htons(seq);
	lsu->pwospf_ttl = htons(64);
	lsu->pwospf_num = htonl(num);
}

void pwospf_lsuBroadcast(router_t* router, pwospf_header_t* pwospf_hdr, struct in_addr* src_ip){
	
	/*
	 * encapsulate the pwospf data in a new ip packet
	 * send it to every neighbor except *potentially* the one who sent the packet in the first place
	 */
// 	int send_on_this_interface = 1;
	int i = 0;
	for (i = 0; i < NUM_INTERFACES; i++){
		interface_t* iface = &router->if_list[i];
		
// 		if (iface->is_active && (iface->neighbors != NULL)) {
		if (iface->neighbors != NULL){
			node_t* cur = iface->neighbors ;
			while (cur) {
				nbr_router_t* nbr = (nbr_router_t*) cur->data;
				
				/*
				 * if we are rebroadcasting, don't send back to the person who sent to us 
				 */
				if (!src_ip || (src_ip->s_addr != nbr->ip.s_addr)){
					
					unsigned int len = sizeof(eth_header_t) + sizeof(ip_header_t) + ntohs(pwospf_hdr->pwospf_len);
					uint8_t* packet = (uint8_t*) malloc(len * sizeof(uint8_t));
					eth_header_t* eth_packet = (eth_header_t*) packet;
					ip_header_t* ip_packet = ip_getHeader(packet);
					pwospf_header_t* pwospf_packet = pwospf_getHeader(packet);
					bzero(packet, len);
					
					/*
					 * construct and put the packet on the sending queue 
					 */
					int foo = ntohs(pwospf_hdr->pwospf_len);
					memcpy(pwospf_packet, pwospf_hdr, foo);
					ip_createHeader(ip_packet, ntohs(pwospf_hdr->pwospf_len), IP_PROTO_PWOSPF, iface->ip, nbr->ip.s_addr);
					ip_packet->ip_sum = htons(ip_checksum(ip_packet));
					eth_createHeader(eth_packet, NULL, iface->addr, ETH_TYPE_IP);
					
					
					//print_packet(packet, len);
					
					/*
					 * put it on the queue 
					 */
					router_lockMutex(&router->lock_pwospf_queue);
					
					pwospf_lsu_item_t* lqi = (pwospf_lsu_item_t*) calloc(1, sizeof(pwospf_lsu_item_t));
					memcpy(lqi->iface, iface->name, IF_LEN);
					lqi->ip.s_addr = iface->ip;
					lqi->packet = packet;
					lqi->len = len;
					
					node_t* n = node_create();
					n->data = (void*) lqi;
					
					if(router->pwospf_lsu_queue == NULL) {
						router->pwospf_lsu_queue = n;
					}
					else {
						node_push_back(router->pwospf_lsu_queue, n);
					}
					
					router_unlockMutex(&router->lock_pwospf_queue);
				}
				cur = cur->next;
			}
		}
// 		send_on_this_interface = 1;
	} /* end of for */
}

void pwospf_processLsu(struct sr_instance* sr, const uint8_t * packet, unsigned int len, const char* interface){
	
	assert(sr);
	assert(packet);
	
	router_t* router = sr_get_subsystem(sr);
	pwospf_header_t* pwospf = pwospf_getHeader(packet);
	pwospf_lsu_header_t* lsu = pwospf_getLsuHeader(packet);
	pwospf_router_t* pwospf_router = 0;
	int update_neighbors = 0;
	int bcast_incoming_lsu_packet = 0;
	int rebroadcast_packet = 0;
	
	/*
	 * If our router id == the lsu update id, drop packet 
	 */
	if(router->router_id == pwospf->pwospf_rid) {
		return;
	}
	
	
	/*
	 * Lock rtable and router_list for writes 
	 */
	router_unlock(&router->lock_rtable);
	router_lockWrite(&router->lock_rtable);
	router_lockMutex(&router->lock_pwospf_list);
	
	
	/*
	 * Get the pwospf_router with the matching rid with this packet 
	 */
	pwospf_router = pwospf_searchList(pwospf->pwospf_rid, router->pwospf_router_list);
	
	if (pwospf_router){
		
		/*
		 * If the seq # match, drop packet, ow update this router's info 
		 */
		if ( (pwospf_router->seq != ntohs(lsu->pwospf_seq)) && ( ntohs(lsu->pwospf_seq) > pwospf_router->seq  ) ){
			rebroadcast_packet = 1;
			time(&(pwospf_router->last_update));
			pwospf_router->seq = htons(lsu->pwospf_seq);
			
			/*
			 * If contents differ from last LSU update, update our neighbors 
			 */
			if (pwospf_populateInterfaceList(pwospf_router, (uint8_t *)packet, len) == 1){
				update_neighbors = 1;
			}
		}
		
	} 
	else {
		rebroadcast_packet = 1;
		pwospf_addNeighbor(router, packet, len);
		
		/*
		 * new neighbor 
		 */
		update_neighbors = 1;
	}
	
	
	/*
	 * does it have a valid ttl? 
	 */
	uint16_t ttl = ntohs(lsu->pwospf_ttl) - 1;
	if ((rebroadcast_packet == 1) && (ttl > 0)){
		
		/*
		 * need to forward a copy of this lsu packet to the other neighbors 
		 */
		unsigned int bcasted_pwospf_packet_len = ntohs(pwospf->pwospf_len);
		uint8_t* bcasted_pwospf_packet = calloc(bcasted_pwospf_packet_len, sizeof(uint8_t));
		memcpy(bcasted_pwospf_packet, pwospf, bcasted_pwospf_packet_len);
		
		/*
		 * update ttl 
		 */
		pwospf_lsu_header_t* bcasted_lsu = (pwospf_lsu_header_t*) (bcasted_pwospf_packet + sizeof(pwospf_header_t));
		bcasted_lsu->pwospf_ttl = htons(ttl);
		
		/*
		 * recompute checksum 
		 */
		pwospf_header_t* bcasted_pwospf = (pwospf_header_t*) (bcasted_pwospf_packet);
		bcasted_pwospf->pwospf_sum = htons(pwospf_checksum(bcasted_pwospf));
		
		/*
		 * broadcast the packet to the other neighbors 
		 */
		ip_header_t* ip = ip_getHeader(packet);
		pwospf_lsuBroadcast(router, bcasted_pwospf, &ip->ip_src);
		free(bcasted_pwospf_packet);
		bcast_incoming_lsu_packet = 1;
	}
	
	/*
	 * lsu packet has changed our known world, build data to inform the other 3 neighbors 
	 */
	if (update_neighbors == 1) {
		pwospf_propagate(router, NULL);
	}
	
	
	/*
	 * unlock the pwospf_router_list 
	 */
	router_unlockMutex(&router->lock_pwospf_list);
	
	
	/*
	 * updated neighbor, signal to send the constructed lsu flood 
	 */
	if ( (update_neighbors == 1)  || (bcast_incoming_lsu_packet == 1) ){
		pthread_cond_signal(&router->pwospf_lsu_bcast_cond);
	}
}

int pwospf_populateInterfaceList(pwospf_router_t* router, uint8_t* packet, unsigned int len){
	
	pwospf_lsu_header_t* lsu = pwospf_getLsuHeader(packet);
	uint32_t pwospf_num = ntohl(lsu->pwospf_num);
	
	uint8_t* packet_adv = pwospf_getLsuData(packet);
	pwospf_lsu_adv_t* next_packet_adv = (pwospf_lsu_adv_t*) packet_adv;
	
	int changed_list = 0;
	int i;
	
	if (router->interface_list == NULL){
		
		/*
		 * add all advs to the interface list 
		 */
		for (i = 0; i < pwospf_num; i++){
			
			/*
			 * allocate memory for this ad 
			 */
			node_t* new_iface_list_node = node_create();
			pwospf_iface_t* new_iface_list_entry = (pwospf_iface_t*) calloc(1, sizeof(pwospf_iface_t));
			
			/*
			 * populate the new adv 
			 */
			new_iface_list_entry->subnet.s_addr = next_packet_adv->pwospf_sub.s_addr & next_packet_adv->pwospf_mask.s_addr;
			new_iface_list_entry->mask.s_addr =  next_packet_adv->pwospf_mask.s_addr;
			new_iface_list_entry->router_id = next_packet_adv->pwospf_rid;
			new_iface_list_entry->is_active = 0;
			
			
			/*
			 * insert the new adv into the list 
			 */
			new_iface_list_node->data = (void*) new_iface_list_entry;
			if (router->interface_list == NULL){
				router->interface_list = new_iface_list_node;
			}
			else {
				node_push_back(router->interface_list, new_iface_list_node);
			}
			
			
			/*
			 * move to the next adv 
			 */
			next_packet_adv += 1;
		} /* end of for loop */
		
		changed_list = 1;
	}	
	else {
		
		/*
		 * CHECK IF WE HAVE NEW ADVERTISEMENTS FROM THIS INCOMING PACKET 
		 */
		for (i = 0; i < pwospf_num; i++) {
			int is_new_adv = 1;
			
			/*
			 * iterate over the router's pwospf ifaces 
			 */
			node_t* interface_list_walker = router->interface_list;
			node_t* interface_list_next = NULL;
			while (interface_list_walker){
				interface_list_next = interface_list_walker->next;
				
				pwospf_iface_t* interface_list_entry = (pwospf_iface_t*) interface_list_walker->data;
				
				/*
				 * Compare this entries subnet & mask to the pckt adv 
				 */
				if ( (interface_list_entry->subnet.s_addr == (next_packet_adv->pwospf_sub.s_addr & next_packet_adv->pwospf_mask.s_addr)) &&
				     (interface_list_entry->mask.s_addr == next_packet_adv->pwospf_mask.s_addr) &&
				      interface_list_entry->router_id == next_packet_adv->pwospf_rid)
				{
					
					is_new_adv = 0;
					break;
				}
					
				/*
				 * move to the next interface entry 
				 */
				interface_list_walker = interface_list_next;
			}
			
			/*
			 * add the new adv to the list 
			 */
			if(is_new_adv) {
				
				/*
				 * allocate memory for this adv 
				 */
				node_t* new_iface_list_node = node_create();
				pwospf_iface_t* new_iface_list_entry = (pwospf_iface_t*) calloc(1, sizeof(pwospf_iface_t));
				
				/*
				 * populate the new adv 
				 */
				new_iface_list_entry->subnet.s_addr = next_packet_adv->pwospf_sub.s_addr & next_packet_adv->pwospf_sub.s_addr;
				new_iface_list_entry->mask.s_addr =  next_packet_adv->pwospf_mask.s_addr;
				new_iface_list_entry->router_id = next_packet_adv->pwospf_rid;
				new_iface_list_entry->is_active = 0;
				
				
				/*
				 * insert the new adv into the list 
				 */
				new_iface_list_node->data = (void*) new_iface_list_entry;
				node_push_back(router->interface_list, new_iface_list_node);
				
				changed_list = 1;
			}
			
			next_packet_adv += 1;
			
		} /* end of for loop */
		
		/*
		 * CHECK IF THERE ARE ANY MISSING ADVERTISEMENTS 
		 */
		node_t* interface_list_walker = router->interface_list;
		node_t* interface_list_next = NULL;
		while (interface_list_walker) {
			interface_list_next = interface_list_walker->next;
			pwospf_iface_t* interface_list_entry = (pwospf_iface_t*) interface_list_walker->data;
			
			/*
			 * see if there is a matching advertisement 
			 */
			packet_adv = pwospf_getLsuData(packet);
			next_packet_adv = (pwospf_lsu_adv_t*) packet_adv;
			int found = 0;
			
			for (i = 0; i < pwospf_num; i++) {
				/*
				 * Compare this entries subnet & mask to the pckt adv 
				 */
				if ((interface_list_entry->subnet.s_addr == (next_packet_adv->pwospf_sub.s_addr & next_packet_adv->pwospf_mask.s_addr)) &&
				    (interface_list_entry->mask.s_addr == next_packet_adv->pwospf_mask.s_addr) &&
				    (interface_list_entry->router_id == next_packet_adv->pwospf_rid)) 
				{
					
					found = 1;
					break;
				}
				next_packet_adv++;
			}
			
			if (!found) {
				node_remove(&(router->interface_list), interface_list_walker);
				changed_list = 1;
			}
			
			interface_list_walker = interface_list_next;
		}
		
	}
	
	return changed_list;
}


void pwospf_addNeighbor(router_t* router, const uint8_t* packet, unsigned int len){
	
	pwospf_header_t* pwospf = pwospf_getHeader(packet);
	pwospf_lsu_header_t* lsu = pwospf_getLsuHeader(packet);
	
	
	/*
	 * Unkwnown host: update database 
	 */
	pwospf_router_t* new_router = (pwospf_router_t*) calloc(1, sizeof(pwospf_router_t));
	new_router->router_id = pwospf->pwospf_rid;
	new_router->area_id = ntohl(pwospf->pwospf_aid);
	new_router->seq = ntohs(lsu->pwospf_seq);
	time(&new_router->last_update);
	new_router->distance = 0;
	new_router->shortest_path_found = 0;
	
	
	/*
	 * copy the LS advs into the interface list 
	 */
	pwospf_populateInterfaceList(new_router, (uint8_t*) packet, len);
	
	
	/*
	 * update the pwospf router list 
	 */
	node_t* n = node_create();
	n->data = (void*) new_router;
	if (router->pwospf_router_list == NULL){
		router->pwospf_router_list = n;
	}
	else{
		node_push_back(router->pwospf_router_list, n);
	}
}

void* pwospf_helloThread(void* param){
	assert(param);
	struct sr_instance* sr = (struct sr_instance*) param;
	router_t* router = sr_get_subsystem(sr);
	
	while(1){
		pwospf_helloBroadcast(sr);
		sleep(router->pwospf_hello_interval - 1);
	}
}


void* pwospf_lsuThread(void* param){
	
	assert(param);
	struct sr_instance* sr = (struct sr_instance*) param;
	router_t* router = sr_get_subsystem(sr);
	
	time_t now;
	int diff;
	
	sleep(5);
	while (1){
		router_lockMutex(&router->lock_pwospf_list);
		pwospf_router_t* our_router = pwospf_searchList(router->router_id, router->pwospf_router_list);
		router_unlockMutex(&router->lock_pwospf_list);
		
		time(&now);
		if (our_router) {
			diff = (int) difftime(now, our_router->last_update);
			
			/*
			 * send an lsu update if we haven't done so 
			 */
			if (diff > (router->pwospf_lsu_interval)) {
				
				router_lockMutex(&router->lock_pwospf_list);
// 				start_lsu_bcast_flood(rs, NULL);//TODO
				router_unlockMutex(&router->lock_pwospf_list);
				
				/*
				 * signal the lsu bcast thread to send the packets 
				 */
				pthread_cond_signal(&router->pwospf_lsu_bcast_cond);
			}
		}
		
		/*
		 * poll every 1 second 
		 */
		sleep(1);
	}
}


void pwospf_helloBroadcast(struct sr_instance* sr){
	
	assert(sr);
	
	router_t* router = sr_get_subsystem(sr);
	unsigned int len = sizeof(eth_header_t) + sizeof(ip_header_t) + sizeof(pwospf_header_t) + sizeof(pwospf_hello_header_t);
	uint8_t* packet = malloc(len * sizeof(char));
// 	iface_entry *ie = 0;
	eth_header_t* eth = (eth_header_t*) packet;
	ip_header_t* ip = ip_getHeader(packet);
	pwospf_header_t* pwospf = pwospf_getHeader(packet);
	pwospf_hello_header_t* hello = pwospf_getHelloHeader(packet);
	uint8_t default_addr[ETH_ADDR_LEN] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
	int interface_has_timedout = 0;
	
	/*
	 * send one hello packet per interface 
	 */
	int i = 0;
	for (i = 0; i < NUM_INTERFACES; i++){
// 		ie = (iface_entry *)iface_walker->data;
		interface_t* ie = &router->if_list[i];
		bzero(packet, len);
		
// 		if (ie->is_active & 0x1){
		if (1){
			
			/*
			 * construct the hello packet 
			 */
			pwospf_createHelloHeader(hello, ie->mask, router->pwospf_hello_interval);
			
			pwospf_createHeader(pwospf, PWOSPF_TYPE_HELLO, sizeof(pwospf_header_t) + sizeof(pwospf_hello_header_t), router->router_id, router->area_id);
			pwospf->pwospf_sum = htons(pwospf_checksum(pwospf));
			ip_createHeader(ip, sizeof(pwospf_header_t) + sizeof(pwospf_hello_header_t), IP_PROTO_PWOSPF, ie->ip, htonl(PWOSPF_HELLO_TIP));
			ip->ip_sum = htons(ip_checksum(ip));
			eth_createHeader(eth, default_addr, ie->addr, ETH_TYPE_IP);
			
			/*
			 * send hello packet and update the time sent 
			 */
			router_sendPacket(sr, packet, len, ie->name);
			time((time_t*) (&ie->last_sent_hello));
			
			
			/*
			 * disable timed out interface 
			* have to lock the router list because we update our pwospf router from inside 
			*/
			router_lockMutex(&router->lock_pwospf_list);
// 			if(determine_timedout_interface(rs, ie) == 1) { //TODO
// 				/* the outer loop checks all interfaces, so we need this if statement */
// 				interface_has_timedout = 1;
// 			}
			router_unlockMutex(&router->lock_pwospf_list);
		}
	}
	
	
	/*
	 * One of neighbor interfaces has timed out 
	 */
	if (interface_has_timedout == 1){
		
		/*
		 * flood with lsu updates 
		 */
		router_lockMutex(&router->lock_pwospf_list);
		pwospf_propagate(router, NULL);
		router_unlockMutex(&router->lock_pwospf_list);
		
		/*
		 * send it to every neighbor 
		 */
		pthread_cond_signal(&router->pwospf_lsu_bcast_cond);
	}
	free(packet);
}
