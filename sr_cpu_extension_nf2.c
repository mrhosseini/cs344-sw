/*-----------------------------------------------------------------------------
 * file:  sr_cpu_extension_nf2.c
 * date:  Mon Feb 09 16:58:30 PST 2004
 * Author: Martin Casado
 *
 * 2007-Apr-04 04:57:55 AM - Modified to support NetFPGA v2.1 /mc
 *
 * Description:
 *
 *---------------------------------------------------------------------------*/

#include "sr_cpu_extension_nf2.h"

#include "sr_base_internal.h"
#include "sr_vns.h"
#include "sr_dumper.h"

#include "router.h"
#include "functions.h"



#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

struct sr_ethernet_hdr
{
	#ifndef ETHER_ADDR_LEN
	#define ETHER_ADDR_LEN 6
	#endif
	uint8_t  ether_dhost[ETHER_ADDR_LEN];    /* destination ethernet address */
	uint8_t  ether_shost[ETHER_ADDR_LEN];    /* source ethernet address */
	uint16_t ether_type;                     /* packet type ID */
} __attribute__ ((packed)) ;

static char*    copy_next_field(FILE* fp, char*  line, char* buf);
static uint32_t asci_to_nboip(const char* ip);
static void     asci_to_ether(const char* addr, uint8_t mac[6]);


/*-----------------------------------------------------------------------------
 * Method: sr_cpu_init_hardware(..)
 * scope: global
 *
 * Read information for each of the router's interfaces from hwfile
 *
 * format of the file is (1 interface per line)
 *
 * <name ip mask hwaddr>
 *
 * e.g.
 *
 * eth0 192.168.123.10 255.255.255.0 ca:fe:de:ad:be:ef
 *
 *---------------------------------------------------------------------------*/


int sr_cpu_init_hardware(struct sr_instance* sr, const char* hwfile)
{
	struct sr_vns_if vns_if;
	FILE* fp = 0;
	char line[1024];
	char buf[SR_NAMELEN];
	char *tmpptr;
	
	
	if ( (fp = fopen(hwfile, "r") ) == 0 )
	{
		fprintf(stderr, "Error: could not open cpu hardware info file: %s\n",
			hwfile);
		return -1;
	}
	
	Debug(" < -- Reading hw info from file %s -- >\n", hwfile);
	while ( fgets( line, 1024, fp) )
	{
		line[1023] = 0; /* -- insurance :) -- */
		
		/* -- read interface name into buf -- */
		if(! (tmpptr = copy_next_field(fp, line, buf)) )
		{
			fclose(fp);
			fprintf(stderr, "Bad formatting in cpu hardware file\n");
			return 1;
		}
		Debug(" - Name [%s] ", buf);
		strncpy(vns_if.name, buf, SR_NAMELEN);
		/* -- read interface ip into buf -- */
		if(! (tmpptr = copy_next_field(fp, tmpptr, buf)) )
		{
			fclose(fp);
			fprintf(stderr, "Bad formatting in cpu hardware file\n");
			return 1;
		}
		Debug(" IP [%s] ", buf);
		vns_if.ip = asci_to_nboip(buf);
		
		/* -- read interface mask into buf -- */
		if(! (tmpptr = copy_next_field(fp, tmpptr, buf)) )
		{
			fclose(fp);
			fprintf(stderr, "Bad formatting in cpu hardware file\n");
			return 1;
		}
		Debug(" Mask [%s] ", buf);
		vns_if.mask = asci_to_nboip(buf);
		
		/* -- read interface hw address into buf -- */
		if(! (tmpptr = copy_next_field(fp, tmpptr, buf)) )
		{
			fclose(fp);
			fprintf(stderr, "Bad formatting in cpu hardware file\n");
			return 1;
		}
		Debug(" MAC [%s]\n", buf);
		asci_to_ether(buf, vns_if.addr);
		
		sr_integ_add_interface(sr, &vns_if);
		
	} /* -- while ( fgets ( .. ) ) -- */
	Debug(" < --                         -- >\n");
	
	fclose(fp);
	return 0;
	
} /* -- sr_cpu_init_hardware -- */

/*-----------------------------------------------------------------------------
 * Method: sr_cpu_input(..)
 * Scope: Local
 *
 *---------------------------------------------------------------------------*/

int sr_cpu_input(struct sr_instance* sr)
{
	/* REQUIRES */
	assert(sr);
	
	fprintf(stderr, "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
	fprintf(stderr, "!!!  sr_cpu_input(..) (sr_cpu_extension_nf2.c) called while running in cpu mode     !!!\n");
// 	fprintf(stderr, "!!!  you need to implement this function to read from the hardware                  !!!\n");
	fprintf(stderr, "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
	
	//while (1);
		
	router_t* router = (router_t*) sr_get_subsystem(sr);
	int i;
	char* internal_names[NUM_INTERFACES] = {"eth0", "eth1", "eth2", "eth3"};
	
	/* setup select */
	fd_set read_set;
	FD_ZERO(&read_set);
	int READ_BUF_SIZE = 16384;
	unsigned char readBuf[READ_BUF_SIZE];
	
	while (1) {
		for (i = 0; i < NUM_INTERFACES; ++i) {
			FD_SET(router->sockfd[i], &read_set);
		}
		
		struct timeval t;
		t.tv_usec = 500; // timeout every half a millisecond
		
		int nfd = array_max(router->sockfd, NUM_INTERFACES) + 1;
		if (select(nfd, &read_set, NULL, NULL, NULL) < 0) {
			perror("select");
			exit(1);
		}
		
		for (i = 0; i < NUM_INTERFACES; ++i) {
			if (FD_ISSET(router->sockfd[i], &read_set)) {
				printf("\n Something on %s \n", internal_names[i]);
				// assume each read is a full packet
				int read_bytes = read(router->sockfd[i], readBuf, READ_BUF_SIZE);
				
				/* log packet */
//				pthread_mutex_lock(rs->log_dumper_mutex); //TODO: lock
				sr_log_packet(sr, (unsigned char*)readBuf, read_bytes);
//				pthread_mutex_unlock(rs->log_dumper_mutex);
				
				/* send packet */
				sr_integ_input(sr, readBuf, read_bytes, internal_names[i]);
			}
		}
	}
	
	//assert(0);
	
	/*
	 * TODO: Read packet from the hardware and pass to sr_integ_input(..)
	 *       e.g.
	 *
	 *  sr_integ_input(sr,
	 *          packet,   * lent *
	 *          len,
	 *          "eth2" ); * lent *
	 */
	
	/*
	 * Note: To log incoming packets, use sr_log_packet from sr_dumper.[c,h]
	 */
	
	/* RETURN 1 on success, 0 on failure.
	 * Note: With a 0 result, the router will shut-down
	 */
	return 1;
	
} /* -- sr_cpu_input -- */

/*-----------------------------------------------------------------------------
 * Method: sr_cpu_output(..)
 * Scope: Global
 *
 *---------------------------------------------------------------------------*/

int sr_cpu_output(struct sr_instance* sr /* borrowed */,
		  uint8_t* buf /* borrowed */ ,
		  unsigned int len,
		  const char* iface /* borrowed */)
{
	/* REQUIRES */
	assert(sr);
	assert(buf);
	assert(iface);
	
	fprintf(stderr, "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
	fprintf(stderr, "!!! sr_cpu_output(..) (sr_cpu_extension_nf2.c) called while running in cpu mode !!!\n");
	fprintf(stderr, "!!! you need to implement this function to write to the hardware                !!!\n");
	fprintf(stderr, "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
	
	router_t* router = sr_get_subsystem(sr);
	int written_length = 0;
	int i = 0;
	
	/* log the packet */
// 	pthread_mutex_lock(rs->log_dumper_mutex);//TODO: lock
	sr_log_packet(sr, buf, len);
// 	pthread_mutex_unlock(rs->log_dumper_mutex);
	
	
	char* internal_names[4] = {"eth0", "eth1", "eth2", "eth3"};
	for (i = 0; i < 4; ++i) {
		if (strcmp(iface, internal_names[i]) == 0) {
			break;
		}
	}
	
	/* setup select */
	fd_set write_set;
	FD_ZERO(&write_set);
	
	while (written_length < len) {
		FD_SET(router->sockfd[i], &write_set);
		
		struct timeval t;
		t.tv_sec = 0;
		t.tv_usec = 500; // timeout every half a millisecond
		
		if (select(router->sockfd[i]+1, NULL, &write_set, NULL, NULL) < 0) {
			perror("select");
			exit(1);
		}
		
		if (FD_ISSET(router->sockfd[i], &write_set)) {
			int w = 0;
			if ((w = write(router->sockfd[i], &buf[written_length], len - written_length)) == -1) {
				perror("write");
				exit(1);
			}
			written_length += w;
		}
	}
	
	/* Return the length of the packet on success, -1 on failure */
	return len;
} /* -- sr_cpu_output -- */


/*-----------------------------------------------------------------------------
 * Method: copy_next_field(..)
 * Scope: Local
 *
 *---------------------------------------------------------------------------*/

static
char* copy_next_field(FILE* fp, char* line, char* buf)
{
	char* tmpptr = buf;
	while ( *line  && isspace((int)*line)) /* -- XXX: potential overrun here */
	{ line++; }
	if(! *line )
	{ return 0; }
	while ( *line && ! isspace((int)*line) && ((tmpptr - buf) < SR_NAMELEN))
	{ *tmpptr++ = *line++; }
	*tmpptr = 0;
	return line;
} /* -- copy_next_field -- */

/*-----------------------------------------------------------------------------
 * Method: asci_to_nboip(..)
 * Scope: Local
 *
 *---------------------------------------------------------------------------*/

static uint32_t asci_to_nboip(const char* ip)
{
	struct in_addr addr;
	
	if ( inet_pton(AF_INET, ip, &addr) <= 0 )
	{ return 0; } /* -- 0.0.0.0 unsupported so its ok .. yeah .. really -- */
	
	return addr.s_addr;
} /* -- asci_to_nboip -- */

/*-----------------------------------------------------------------------------
 * Method: asci_to_ether(..)
 * Scope: Local
 *
 * Look away .. please ... just look away
 *
 *---------------------------------------------------------------------------*/

static void asci_to_ether(const char* addr, uint8_t mac[6])
{
	uint32_t tmpint;
	const char* buf = addr;
	int i = 0;
	for( i = 0; i < 6; ++i )
	{
		if (i)
		{
			while (*buf && *buf != ':')
			{ buf++; }
			buf++;
		}
		sscanf(buf, "%x", &tmpint);
		mac[i] = tmpint & 0x000000ff;
	}
} /* -- asci_to_ether -- */
