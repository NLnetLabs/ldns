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
typedef struct type_struct_header ldns_header_type;

/**
 * \brief DNS packet
 *
 * This structure contains a complete DNS packet (either a query or an answer)
 */
struct type_struct_packet
{
	/** \brief header section */
	ldns_header_type *_header;
	/** \brief question section */
	t_rrset	*_question;
	/** \brief answer section */
	t_rrset	*_answer;
	/** \brief auth section */
	t_rrset	*_authority;
	/** \brief add section */
	t_rrset	*_additional;
};
typedef struct type_struct_packet ldns_packet_type;

/* prototypes */
uint16_t packet_id(ldns_packet_type *);
bool packet_qr(ldns_packet_type *);
bool packet_aa(ldns_packet_type *);
bool packet_tc(ldns_packet_type *);
bool packet_rd(ldns_packet_type *);
bool packet_cd(ldns_packet_type *);
bool packet_ra(ldns_packet_type *);
bool packet_ad(ldns_packet_type *);
uint8_t packet_opcode(ldns_packet_type *);
uint8_t packet_rcode(ldns_packet_type *);
uint16_t packet_qdcount(ldns_packet_type *);
uint16_t packet_ancount(ldns_packet_type *);
uint16_t packet_nscount(ldns_packet_type *);
uint16_t packet_arcount(ldns_packet_type *);

void packet_set_id(ldns_packet_type *, uint16_t);
void packet_set_qr(ldns_packet_type *, bool);
void packet_set_aa(ldns_packet_type *, bool);
void packet_set_tc(ldns_packet_type *, bool);
void packet_set_rd(ldns_packet_type *, bool);
void packet_set_cd(ldns_packet_type *, bool);
void packet_set_ra(ldns_packet_type *, bool);
void packet_set_ad(ldns_packet_type *, bool);
void packet_set_opcode(ldns_packet_type *, uint8_t);
void packet_set_rcode(ldns_packet_type *, uint8_t);
void packet_set_qdcount(ldns_packet_type *, uint16_t);
void packet_set_ancount(ldns_packet_type *, uint16_t);
void packet_set_nscount(ldns_packet_type *, uint16_t);
void packet_set_arcount(ldns_packet_type *, uint16_t);

/**
 * Allocates and initializes a ldns_packet_type structure
 *
 * @return pointer to the new packet
 */
ldns_packet_type *ldns_packet_new();

/**
 * Frees the packet structure and all data that it contains
 *
 * @param packet The packet structure to free
 */
void ldns_packet_free(ldns_packet_type *packet);

/**
 * Converts the data on the uint8_t bytearray (in wire format) to a DNS packet
 *
 * @param data pointer to the buffer with the data
 * @param len the length of the data buffer (in bytes)
 * @param packet pointer to the structure to hold the packet
 * @return the number of bytes read from the wire
 */
size_t ldns_wire2packet(ldns_packet_type *packet, const uint8_t *data, size_t len);

#endif  /* !_LDNS_PACKET_H */
