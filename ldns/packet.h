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

#include <ldns/error.h>
#include <ldns/common.h>
#include <ldns/rr.h>

/**
 * \brief Header of a dns packet
 *
 * Contains the information about the packet itself
 */
struct ldns_struct_hdr
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
typedef struct ldns_struct_hdr ldns_hdr;

/**
 * \brief DNS packet
 *
 * This structure contains a complete DNS packet (either a query or an answer)
 */
struct ldns_struct_pkt
{
	/** \brief header section */
	ldns_hdr *_header;
	/** \brief question section */
	ldns_rrset	*_question;
	/** \brief answer section */
	ldns_rrset	*_answer;
	/** \brief auth section */
	ldns_rrset	*_authority;
	/** \brief add section */
	ldns_rrset	*_additional;
};
typedef struct ldns_struct_pkt ldns_pkt;

/* prototypes */
uint16_t pkt_id(ldns_pkt *);
bool pkt_qr(ldns_pkt *);
bool pkt_aa(ldns_pkt *);
bool pkt_tc(ldns_pkt *);
bool pkt_rd(ldns_pkt *);
bool pkt_cd(ldns_pkt *);
bool pkt_ra(ldns_pkt *);
bool pkt_ad(ldns_pkt *);
uint8_t pkt_opcode(ldns_pkt *);
uint8_t pkt_rcode(ldns_pkt *);
uint16_t pkt_qdcount(ldns_pkt *);
uint16_t pkt_ancount(ldns_pkt *);
uint16_t pkt_nscount(ldns_pkt *);
uint16_t pkt_arcount(ldns_pkt *);

void pkt_set_id(ldns_pkt *, uint16_t);
void pkt_set_qr(ldns_pkt *, bool);
void pkt_set_aa(ldns_pkt *, bool);
void pkt_set_tc(ldns_pkt *, bool);
void pkt_set_rd(ldns_pkt *, bool);
void pkt_set_cd(ldns_pkt *, bool);
void pkt_set_ra(ldns_pkt *, bool);
void pkt_set_ad(ldns_pkt *, bool);
void pkt_set_opcode(ldns_pkt *, uint8_t);
void pkt_set_rcode(ldns_pkt *, uint8_t);
void pkt_set_qdcount(ldns_pkt *, uint16_t);
void pkt_set_ancount(ldns_pkt *, uint16_t);
void pkt_set_nscount(ldns_pkt *, uint16_t);
void pkt_set_arcount(ldns_pkt *, uint16_t);

/**
 * Allocates and initializes a ldns_pkt structure
 *
 * @return pointer to the new packet
 */
ldns_pkt *ldns_pkt_new();

/**
 * Frees the packet structure and all data that it contains
 *
 * @param packet The packet structure to free
 */
void ldns_pkt_free(ldns_pkt *packet);

#endif  /* !_LDNS_PACKET_H */
