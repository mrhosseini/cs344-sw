/*-----------------------------------------------------------------------------
 * file:  sr_integration.c
 * date:  Tue Feb 03 11:29:17 PST 2004
 * Author: Martin Casado <casado@stanford.edu>
 *
 * Description:
 *
 * Methods called by the lowest-level of the network system to talk with
 * the network subsystem.
 *
 * This is the entry point of integration for the network layer.
 *
 *---------------------------------------------------------------------------*/

#include <stdlib.h>

#include <assert.h>

#include "sr_vns.h"
#include "sr_base_internal.h"
#include "router.h"
#include "rtable.h"

#ifdef _CPUMODE_
#include "sr_cpu_extension_nf2.h"
#endif

/*-----------------------------------------------------------------------------
 * Method: sr_integ_init(..)
 * Scope: global
 *
 *
 * First method called during router initialization.  Called before connecting
 * to VNS, reading in hardware information etc.
 *
 *---------------------------------------------------------------------------*/

void sr_integ_init(struct sr_instance* sr)
{
	printf(" ** sr_integ_init(..) called \n");
	router_init(sr);
	
} /* -- sr_integ_init -- */

/*-----------------------------------------------------------------------------
 * Method: sr_integ_hw_setup(..)
 * Scope: global
 *
 * Called after all initial hardware information (interfaces) have been
 * received.  Can be used to start subprocesses (such as dynamic-routing
 * protocol) which require interface information during initialization.
 *
 *---------------------------------------------------------------------------*/

void sr_integ_hw_setup(struct sr_instance* sr)
{
	printf(" ** sr_integ_hw(..) called \n");
	rtable_init(sr);
} /* -- sr_integ_hw_setup -- */

/*---------------------------------------------------------------------
 * Method: sr_integ_input(struct sr_instance*,
 *                        uint8_t* packet,
 *                        char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_integ_input(struct sr_instance* sr,
		    const uint8_t * packet/* borrowed */,
		    unsigned int len,
		    const char* interface/* borrowed */)
{
	/* -- INTEGRATION PACKET ENTRY POINT!-- */
	
	printf(" ** sr_integ_input(..) called \n");
	
	
	router_processPacket(sr, packet, len, interface);
	
// 	sr_integ_low_level_output(sr /* borrowed */,
// 				  packet /* borrowed */ ,
// 			   len,
// 			   interface /* borrowed */);
	
} /* -- sr_integ_input -- */

/*-----------------------------------------------------------------------------
 * Method: sr_integ_add_interface(..)
 * Scope: global
 *
 * Called for each interface read in during hardware initialization.
 * struct sr_vns_if is defined in sr_base_internal.h
 *
 *---------------------------------------------------------------------------*/

void sr_integ_add_interface(struct sr_instance* sr,
			    struct sr_vns_if* vns_if/* borrowed */)
{
	printf(" ** sr_integ_add_interface(..) called \n");
	
	router_t* router = (router_t*)sr_get_subsystem(sr);
	router_initInterfaces(router, &router->if_list[router->if_list_index], *vns_if);
	router->if_list_index ++;
	printf("\n name = %s", router->if_list[router->if_list_index -1].name);
	printf("\n addr = ");
	int i = 0;
	for (i = 0; i < 6; i++){
		printf("%02X:", router->if_list[router->if_list_index -1].addr[i]);
	}
	printf("\n speed = %d", router->if_list[router->if_list_index -1].speed);
	printf("\n ip = %0X", router->if_list[router->if_list_index -1].ip);
	printf("\n mask = %0X\n\n\n", router->if_list[router->if_list_index -1].mask);
	
} /* -- sr_integ_add_interface -- */

struct sr_instance* get_sr() {
	struct sr_instance* sr;
	
	sr = sr_get_global_instance( NULL );
	assert( sr );
	return sr;
}

/*-----------------------------------------------------------------------------
 * Method: sr_integ_low_level_output(..)
 * Scope: global
 *
 * Send a packet to VNS to be injected into the topology
 *
 *---------------------------------------------------------------------------*/

int sr_integ_low_level_output(struct sr_instance* sr /* borrowed */,
			      uint8_t* buf /* borrowed */ ,
			      unsigned int len,
			      const char* iface /* borrowed */)
{
	#ifdef _CPUMODE_
	return sr_cpu_output(sr, buf /*lent*/, len, iface);
	#else
	return sr_vns_send_packet(sr, buf /*lent*/, len, iface);
	#endif /* _CPUMODE_ */
} /* -- sr_vns_integ_output -- */

/*-----------------------------------------------------------------------------
 * Method: sr_integ_destroy(..)
 * Scope: global
 *
 * For memory deallocation pruposes on shutdown.
 *
 *---------------------------------------------------------------------------*/

void sr_integ_destroy(struct sr_instance* sr)
{
	printf(" ** sr_integ_destroy(..) called \n");
} /* -- sr_integ_destroy -- */

/*-----------------------------------------------------------------------------
 * Method: sr_integ_findsrcip(..)
 * Scope: global
 *
 * Called by the transport layer for outgoing packets generated by the
 * router.  Expects source address in network byte order.
 *
 *---------------------------------------------------------------------------*/

uint32_t sr_integ_findsrcip(uint32_t dest /* nbo */)
{
	fprintf(stderr, "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
	fprintf(stderr, "!!! Tranport layer called ip_findsrcip(..) this must be !!!\n");
	fprintf(stderr, "!!! defined to return the correct source address        !!!\n");
	fprintf(stderr, "!!! given a destination                                 !!!\n ");
	fprintf(stderr, "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
	
	assert(0);
	
	/* --
	 * e.g.
	 *
	 * struct sr_instance* sr = sr_get_global_instance();
	 * struct my_router* mr = (struct my_router*)
	 *                              sr_get_subsystem(sr);
	 * return my_findsrcip(mr, dest);
	 * -- */
	
	return 0;
} /* -- ip_findsrcip -- */

/*-----------------------------------------------------------------------------
 * Method: sr_integ_ip_output(..)
 * Scope: global
 *
 * Called by the transport layer for outgoing packets that need IP
 * encapsulation.
 *
 *---------------------------------------------------------------------------*/

uint32_t sr_integ_ip_output(uint8_t* payload /* given */,
			    uint8_t  proto,
			    uint32_t src, /* nbo */
			    uint32_t dest, /* nbo */
			    int len)
{
	fprintf(stderr, "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
	fprintf(stderr, "!!! Tranport layer called sr_integ_ip_output(..)        !!!\n");
	fprintf(stderr, "!!! this must be defined to handle the network          !!!\n ");
	fprintf(stderr, "!!! level functionality of transport packets            !!!\n ");
	fprintf(stderr, "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
	
	assert(0);
	
	/* --
	 * e.g.
	 *
	 * struct sr_instance* sr = sr_get_global_instance();
	 * struct my_router* mr = (struct my_router*)
	 *                              sr_get_subsystem(sr);
	 * return my_ip_output(mr, payload, proto, src, dest, len);
	 * -- */
	
	return 0;
} /* -- ip_integ_route -- */

/*-----------------------------------------------------------------------------
 * Method: sr_integ_close(..)
 * Scope: global
 *
 *  Called when the router is closing connection to VNS.
 *
 *---------------------------------------------------------------------------*/

void sr_integ_close(struct sr_instance* sr)
{
	printf(" ** sr_integ_close(..) called \n");
}  /* -- sr_integ_close -- */
