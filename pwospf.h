/**
 * @file pwospf.h
 * @author Mohammad Reza Hosseini 
 * 
 * 
 */
#ifndef PWOSPF_H_
#define PWOSPF_H_


#define PWOSPF_HDR_LEN 			24

#define PWOSPF_VERSION			0x2
#define PWOSPF_TYPE_HELLO		0x1
#define PWOSPF_TYPE_LINK_STATE_UPDATE	0x4

#define PWOSPF_AREA_ID 			0x0
#define PWOSPF_HELLO_TIP 		0xe0000005

#define PWOSPF_NEIGHBOR_TIMEOUT 	5
#define PWOSPF_LSUINT 			30
#define PWOSPF_HELLO_PADDING 		0x0

#endif
