/**
 * @file dijkstra.c
 * @author Mohammad Reza Hosseini 
 * 
 * 
 */

#include "dijkstra.h"
#include "router.h"
#include "pwospf.h"
#include "rtable.h"

#include <sys/time.h>
#include <pthread.h>
#include <assert.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void dijkstra_trigger(router_t* router){
	/* no lock on this object, worst case it takes an extra second to run */
	router->dijkstra_dirty = 1;
	pthread_cond_signal(&router->dijkstra_cond);
}

void* dijkstra_thread(void* arg){
	router_t* router = (router_t*) arg;
	
	struct timespec wake_up_time;
	struct timeval now;
	int result = 0;
	
	
	router_lockMutex(&router->lock_dijkstra);
	while (1) {
		/*
		 * Determine the time when to wake up next 
		 */
		gettimeofday(&now, NULL);
		wake_up_time.tv_sec = now.tv_sec + 1;
		wake_up_time.tv_nsec = now.tv_usec + 1000;
		
		result = pthread_cond_timedwait(&router->dijkstra_cond, &router->lock_dijkstra, &wake_up_time);
		
		/*
		 * if we timed out, and the data is not dirty, go back to sleep 
		 */
		if (result == ETIMEDOUT){
			if (!router->dijkstra_dirty) {
				continue;
			}
		}
		router->dijkstra_dirty = 0;
		
		router_lockWrite(&router->lock_rtable);
		router_lockMutex(&router->lock_pwospf_list);
		
		/* nuke all the non static entries */
		//printf("---RTABLE BEFORE DIJKSTRA---\n");
		//char* rtable_printout;
		//int len;
		//sprint_rtable(rs, &rtable_printout, &len);
		//printf("%s\n", rtable_printout);
		//free(rtable_printout);
		
		node_t* cur = router->rtable;
		node_t* next = NULL;
		while (cur){
			next = cur->next;
			rtable_row_t* row = (rtable_row_t*)cur->data;
			if (!row->is_static) {
				node_remove(&(router->rtable), cur);
			}
			cur = next;
		}
		
		/*
		 * run dijkstra 
		 */
		node_t* dijkstra_rtable = dijkstra_computeRtable(router->router_id, router->pwospf_router_list, router->if_list);
		
		/*
		 * patch our list on to the end of the rtable 
		 */
		if (!(router->rtable)){
			router->rtable = dijkstra_rtable;
		} 
		else{
			cur = router->rtable;
			/*
			 * run to the end of the rtable 
			 */
			while (cur->next){
				cur = cur->next;
			}
			cur->next = dijkstra_rtable;
			if (dijkstra_rtable){
				dijkstra_rtable->prev = cur;
			}
		}
		
		/*
		 * write new rtable out to hardware 
		 */
		rtable_updated(router);
		
// 		char* rtable_printout;
// 		int len;
		printf("---RTABLE AFTER DIJKSTRA---\n");
// 		sprint_rtable(rs, &rtable_printout, &len);
// 		printf("%s\n", rtable_printout);
// 		free(rtable_printout);
		
		/*
		 * unlock everything 
		 */
		router_unlockMutex(&router->lock_pwospf_list);
		router_unlock(&router->lock_rtable);		
	}
	router_unlockMutex(&router->lock_dijkstra);
	
	return NULL;
}

node_t* dijkstra_computeRtable(uint32_t our_router_id, node_t* pwospf_router_list, interface_t* if_list){
	
	/*
	 * initialize all the entriest to their max distance, except us 
	 */
	node_t* cur = pwospf_router_list;
	pwospf_router_t* r = NULL;
	pwospf_router_t* r_shortest = NULL;
	
	while (cur) {
		r = (pwospf_router_t*) cur->data;
		if (r->router_id == our_router_id) {
			r->distance = 0;
			r->shortest_path_found = 1;
		} else if (r->router_id != 0) {
			r->distance = 0xFFFFFFFF;
			r->shortest_path_found = 0;
		}
		
		cur = cur->next;
	}
	
	/*
	 * Set our router as the shortest 
	 */
	r_shortest = pwospf_searchList(our_router_id, pwospf_router_list);
	
	while (r_shortest) {
		/*
		 * add this router to N' 
		 */
		r_shortest->shortest_path_found = 1;
		
		/*
		 * update the distances to our neighbors 
		 */
		dijkstra_updateNeighborDistance(r_shortest, pwospf_router_list);
		
		/*
		 * get the next router with the shortest distance 
		 */
		r_shortest = dijkstra_getShortest(pwospf_router_list);
	}
	
	/*
	 * now have the shortest path to each router, build the temporary route table 
	 */
	node_t* route_wrapper_list = dijkstra_buildRouteWrapperList(our_router_id, pwospf_router_list);
	//print_wrapper_list(route_wrapper_list);
	
	/*
	 * we now have a list of wrapped proper entries, but they need specific interface info,
	 * and need to lose the wrapping
	 */
	node_t* route_list = NULL;
	
	cur = route_wrapper_list;
	while (cur) {
		route_wrapper_t* wrapper = (route_wrapper_t*) cur->data;
		rtable_row_t* new_entry = (rtable_row_t*) calloc(1, sizeof(rtable_row_t));
		
		/* 
		 * just blast the entry information across 
		 */
		memcpy(new_entry, &(wrapper->entry), sizeof(rtable_row_t));
		
		/*
		 * get the new stuff 
		 */
		interface_t* iface = router_getInterfaceByRid(if_list, wrapper->next_rid);
		if (!iface) {
			iface = router_getInterfaceByMask(if_list, &(wrapper->entry.ip), &(wrapper->entry.mask));
			if (!iface) {
				/*
				 * most likely the default entry, assume its static, so just continue 
				 */
				free(new_entry);
				cur = cur->next;
				continue;
			}
		}
		assert(iface);
		
		memcpy(new_entry->iface, iface->name, IF_LEN);
		
		if (wrapper->directly_connected) {
			new_entry->gw.s_addr = 0;
		} else {
			nbr_router_t* nbr = router_getNbrByRid(iface, wrapper->next_rid);
			assert(nbr);
			new_entry->gw.s_addr = nbr->ip.s_addr;
		}
		
		new_entry->is_active = 1;
		new_entry->is_static = 0;
		
		/* 
		 * grab a new node, add it to the list 
		 */
		node_t* temp = node_create();
		temp->data = new_entry;
		
		if (!route_list) {
			route_list = temp;
		} else {
			node_push_back(route_list, temp);
		}
		
		cur = cur->next;
	}
	
	/*
	 * run through and free the wrapper list 
	 */
	cur = route_wrapper_list;
	while (cur) {
		node_t* next = cur->next;
		node_remove(&route_wrapper_list, cur);
		cur = next;
	}
	
	return route_list;
}

/**
 * Helper function to update distances of routers attached to w's interfaces
 */
void dijkstra_updateNeighborDistance(pwospf_router_t* w, node_t* pwospf_router_list){
	node_t* cur = w->interface_list;
	
	/* 
	 * iterate through each interface of this router 
	 */
	while (cur) {
		pwospf_iface_t* i = (pwospf_iface_t*) cur->data;
		if ((i->router_id != 0) && i->is_active){
			pwospf_router_t* v = pwospf_searchList(i->router_id, pwospf_router_list);
			
			/*
			 * if the distance to v is shorter through w, update it 
			 */
			/*
			 * ADDED: ensure V exists in our router list as well,
			 * it is possible that someone is reporting a router that is
			 * a neighbor that we have not received an LSU for yet 
			 */
			if ((v) && (!v->shortest_path_found) && ((w->distance+1) < v->distance)){
				v->distance = w->distance + 1;
				v->prev_router = w;
			}
		}
		cur = cur->next;
	}
}


pwospf_router_t* dijkstra_getShortest(node_t* pwospf_router_list){
	pwospf_router_t* shortest_router = NULL;
	uint32_t shortest_distance = 0xFFFFFFFF;
	
	node_t* cur = pwospf_router_list;
	while (cur) {
		pwospf_router_t* r = (pwospf_router_t*) cur->data;
		if ((!r->shortest_path_found) && (r->distance < shortest_distance)) {
			shortest_router = r;
			shortest_distance = r->distance;
		}
		cur = cur->next;
	}
	return shortest_router;
}

node_t* dijkstra_buildRouteWrapperList(uint32_t our_rid, node_t* pwospf_router_list){
	node_t* head = NULL;
	
	/* 
	 * iterate through the routers, adding their interfaces to the route list 
	 */
	node_t* cur = pwospf_router_list;
	while (cur) {
		pwospf_router_t* r = (pwospf_router_t*) cur->data;
		dijkstra_addRouteWrappers(our_rid, &head, r);
		cur = cur->next;
	}
	return head;
}

void dijkstra_addRouteWrappers(uint32_t our_rid, node_t** head, pwospf_router_t* r) {
	node_t* cur = r->interface_list;
	while (cur) {
		pwospf_iface_t* i = (pwospf_iface_t*)cur->data;
		
		/*
		 * check if we have an existing route matching this subnet and mask 
		 */
		node_t* temp_node = dijkstra_getRouteWrapper(*head, &(i->subnet), &(i->mask));
		if (temp_node) {
			
			/*
			 * if our distance is longer, just continue to the next interface 
			 */
			route_wrapper_t* wrapper = (route_wrapper_t*) temp_node->data;
			if (r->distance >= wrapper->distance) {
				cur = cur->next;
				continue;
			} else {
				/*
				 * replace the existing entries data with ours 
				 */
				wrapper->distance = r->distance;
				/*
				 * walk down until the next router is the source 
				 */
				pwospf_router_t* cur_router = r;
				if (!cur_router->prev_router) {
					wrapper->next_rid = i->router_id;
				} else {
					while (cur_router->prev_router->distance != 0) {
						cur_router = cur_router->prev_router;
					}
					
					wrapper->next_rid = cur_router->router_id;
				}
				
				/*
				 * set that this is directly connected to us 
				 */
				if (our_rid == r->router_id) {
					wrapper->directly_connected = 1;
				}
			}
		} else {
			node_t* new_node = node_create();
			
			/*
			 * no existing route wrapper, create a new one for this route 
			 */
			route_wrapper_t* new_route = (route_wrapper_t*)calloc(1, sizeof(route_wrapper_t));
			new_route->entry.ip.s_addr = i->subnet.s_addr & i->mask.s_addr;
			new_route->entry.mask.s_addr = i->mask.s_addr;
			new_route->distance = r->distance;
			
			/*
			 * walk down until the next router is the source 
			 */
			pwospf_router_t* cur_router = r;
			if (!cur_router->prev_router) {
				new_route->next_rid = i->router_id;
			} else {
				while (cur_router->prev_router->distance != 0) {
					cur_router = cur_router->prev_router;
				}
				new_route->next_rid = cur_router->router_id;
			}
			
			/*
			 * set that this is directly connected to us 
			 */
			if (our_rid == r->router_id) {
				new_route->directly_connected = 1;
			}
			
			/*
			 * point the node's data at our route wrapper 
			 */
			new_node->data = new_route;
			
			if (!(*head)) {
				(*head) = new_node;
			} else {
				node_push_back(*head, new_node);
			}
		}
		
		cur = cur->next;
	}
}

node_t* dijkstra_getRouteWrapper(node_t* head, struct in_addr* subnet, struct in_addr* mask){
	/*
	 * walk the route wrapper list looking for an entry matching this subnet and mask 
	 */
	node_t* cur = head;
	while (cur) {
		route_wrapper_t* wrapper = (route_wrapper_t*)cur->data;
		if ((wrapper->entry.ip.s_addr == (subnet->s_addr & mask->s_addr)) && (wrapper->entry.mask.s_addr == mask->s_addr)) {
			return cur;
		}
		cur = cur->next;
	}
	return NULL;
}
