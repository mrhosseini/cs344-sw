/**
 * @file dijkstra.c
 * @author Mohammad Reza Hosseini 
 * 
 * 
 */

#include "dijkstra.h"

void dijkstra_trigger(router_t* router){
	/* no lock on this object, worst case it takes an extra second to run */
	router->dijkstra_dirty = 1;
	pthread_cond_signal(&router->dijkstra_cond);
}