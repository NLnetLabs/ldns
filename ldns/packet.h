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

#include <ldns/common.h>
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
	bool _qr;
	/** \brief Authoritative answer */
	bool _aa;
	/** \brief Packet truncated */
	bool _tc;
	/** \brief Recursion desired */
	bool _rd;
	/** \brief Checking disabled */
	bool _cd;
	/** \brief Recursion available */
	bool _ra;
	/** \brief Authentic data */
	bool _ad;
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
bool packet_qr(t_packet *);
bool packet_aa(t_packet *);
bool packet_tc(t_packet *);
bool packet_rd(t_packet *);
bool packet_cd(t_packet *);
bool packet_ra(t_packet *);
bool packet_ad(t_packet *);
uint8_t packet_opcode(t_packet *);
uint8_t packet_rcode(t_packet *);
uint16_t packet_qdcount(t_packet *);
uint16_t packet_ancount(t_packet *);
uint16_t packet_nscount(t_packet *);
uint16_t packet_arcount(t_packet *);

void packet_set_id(t_packet *, uint16_t);
void packet_set_qr(t_packet *, bool);
void packet_set_aa(t_packet *, bool);
void packet_set_tc(t_packet *, bool);
void packet_set_rd(t_packet *, bool);
void packet_set_cd(t_packet *, bool);
void packet_set_ra(t_packet *, bool);
void packet_set_ad(t_packet *, bool);
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
