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

#include "rdata.h"
#include "rr.h"

/**
 * \brief Header of a dns packet
 *
 * Contains the information about the packet itself
 */
struct type_struct_header
{
	/** \brief Id of a packet */
	uint16_t id;
	/** \brief Query bit (0=query, 1=answer) */
	uint8_t qr:1;
	/** \brief Authoritative answer */
	uint8_t aa:1;
	/** \brief Packet truncated */
	uint8_t tc:1;
	/** \brief Recursion desired */
	uint8_t rd:1;
	/** \brief Checking disabled */
	uint8_t cd:1;
	/** \brief Recursion available */
	uint8_t ra:1;
	/** \brief Authentic data */
	uint8_t ad:1;
	/** \brief Query type */
	uint8_t opcode;	 /* XXX 8 bits? */
	/** \brief Response code */
	uint8_t rcode;
	/** \brief question sec */
	uint16_t qdcount;
	/** \brief answer sec */
	uint16_t ancount;
	/** \brief auth sec */
	uint16_t nscount;
	/** \brief add sec */
	uint16_t acount;
};
typedef struct type_struct_header t_header;

/**
 * \brief DNS packet
 *
 * This structure contains a complete DNS packet (either a query or an answer)
 */
struct struct_packet_type
{
	/** \brief header section */
	t_header *header;
	/** \brief question section */
	t_rrset	*question;
	/** \brief answer section */
	t_rrset	*answer;
	/** \brief auth section */
	t_rrset	*authority;
	/** \brief add section */
	t_rrset	*additional;
};
typedef struct type_struct_packet t_packet;
	
#endif /* _PACKET_H */
