/*
 * packet.h
 *
 * DNS packet definitions
 *
 * a Net::DNS like library for C
 *
 * (c) NLnet Labs, 2004
 *
 * See the file LICENSE for the license
 */
#ifdef _PACKET_H
#else
#define _PACKET_H

#include <stdint.h>
#include "rdata.h"
#include "rr.h"

struct struct_header_type
{
	uint16_t id;		/* id of a packet */
	uint8_t qr:1;
	uint8_t aa:1;
	uint8_t tc:1;
	uint8_t rd:1;
	uint8_t cd:1;
	uint8_t ra:1;
	uint8_t ad:1;
	uint8_t opcode;
	uint8_t rcode;
	uint8_t qdcount;	/* question sec */
	uint8_t ancount;	/* answer sec */
	uint8_t nscount;	/* auth sec */
	uint8_t acount;		/* add sec */
};
typedef struct struct_header_type header_t;

struct struct_packet_type
{
	header_t *header;	/* header section */
	rrset_t	*question;	/* question section */
	rrset_t	*answer;	/* answer section */
	rrset_t	*authority;	/* auth section */
	rrset_t	*additional;	/* add section */
};
typedef struct struct_packet_type packet_t;
	
#endif /* _PACKET_H */
