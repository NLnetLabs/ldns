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

#ifndef _LDNS_PACKET_H
#define _LDNS_PACKET_H

#include <ldns/rr.h>

/**
 * \brief Header of a dns packet
 *
 * Contains the information about the packet itself
 */
struct type_struct_header
{
	/** \brief Id of a packet */
	uint16_t _id;
	/** \brief Query bit (0=query, 1=answer) */
	uint8_t _qr:1;
	/** \brief Authoritative answer */
	uint8_t _aa:1;
	/** \brief Packet truncated */
	uint8_t _tc:1;
	/** \brief Recursion desired */
	uint8_t _rd:1;
	/** \brief Checking disabled */
	uint8_t _cd:1;
	/** \brief Recursion available */
	uint8_t _ra:1;
	/** \brief Authentic data */
	uint8_t _ad:1;
	/** \brief Query type */
	uint8_t _opcode;	 /* XXX 8 bits? */
	/** \brief Response code */
	uint8_t _rcode;
	/** \brief question sec */
	uint16_t _qdcount;
	/** \brief answer sec */
	uint16_t _ancount;
	/** \brief auth sec */
	uint16_t _nscount;
	/** \brief add sec */
	uint16_t _arcount;
};
typedef struct type_struct_header t_header;

/**
 * \brief DNS packet
 *
 * This structure contains a complete DNS packet (either a query or an answer)
 */
struct type_struct_packet
{
	/** \brief header section */
	t_header *_header;
	/** \brief question section */
	t_rrset	*_question;
	/** \brief answer section */
	t_rrset	*_answer;
	/** \brief auth section */
	t_rrset	*_authority;
	/** \brief add section */
	t_rrset	*_additional;
};
typedef struct type_struct_packet t_packet;

/* prototypes */
uint16_t packet_id(t_packet *);
uint8_t packet_qr(t_packet *);
uint8_t packet_aa(t_packet *);
uint8_t packet_tc(t_packet *);
uint8_t packet_rd(t_packet *);
uint8_t packet_cd(t_packet *);
uint8_t packet_ra(t_packet *);
uint8_t packet_ad(t_packet *);
uint8_t packet_opcode(t_packet *);
uint8_t packet_rcode(t_packet *);
uint16_t packet_qdcount(t_packet *);
uint16_t packet_ancount(t_packet *);
uint16_t packet_nscount(t_packet *);
uint16_t packet_arcount(t_packet *);

void packet_set_id(t_packet *, uint16_t);
void packet_set_qr(t_packet *, uint8_t);
void packet_set_aa(t_packet *, uint8_t);
void packet_set_tc(t_packet *, uint8_t);
void packet_set_rd(t_packet *, uint8_t);
void packet_set_cd(t_packet *, uint8_t);
void packet_set_ra(t_packet *, uint8_t);
void packet_set_ad(t_packet *, uint8_t);
void packet_set_opcode(t_packet *, uint8_t);
void packet_set_rcode(t_packet *, uint8_t);
void packet_set_qdcount(t_packet *, uint16_t);
void packet_set_ancount(t_packet *, uint16_t);
void packet_set_nscount(t_packet *, uint16_t);
void packet_set_arcount(t_packet *, uint16_t);

/**
 * Allocates and initializes a t_packet structure
 *
 * @return pointer to the new packet
 */
t_packet *dns_packet_new();

/**
 * Converts the data on the uint8_t bytearray (in wire format) to a DNS packet
 *
 * @param data pointer to the buffer with the data
 * @param packet pointer to the structure to hold the packet
 * @return the number of bytes read from the wire
 */
size_t dns_wire2packet(uint8_t *data, t_packet *packet);

#endif  /* !_LDNS_PACKET_H */
