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
	/* extra items needed in a packet */
	/** \brief the size in bytes of the pkt */
	uint16_t _answersize;
	/** \brief the server ip */
	ldns_rdf *_answerfrom;
	/** \brief query duration */
	uint32_t _querytime;
	/** \brief query data */
	/** \brief question section */
	ldns_rr_list	*_question;
	/** \brief answer section */
	ldns_rr_list	*_answer;
	/** \brief auth section */
	ldns_rr_list	*_authority;
	/** \brief add section */
	ldns_rr_list	*_additional;
};
typedef struct ldns_struct_pkt ldns_pkt;

/**
 * The sections of a packet
 */
enum ldns_enum_pkt_section {
	LDNS_SECTION_QUESTION = 0,
	LDNS_SECTION_ANSWER = 1,
	LDNS_SECTION_AUTHORITY = 2,
	LDNS_SECTION_ADDITIONAL = 3
};
typedef enum ldns_enum_pkt_section ldns_pkt_section;	

/* prototypes */
uint16_t ldns_pkt_id(ldns_pkt *);
bool ldns_pkt_qr(ldns_pkt *);
bool ldns_pkt_aa(ldns_pkt *);
bool ldns_pkt_tc(ldns_pkt *);
bool ldns_pkt_rd(ldns_pkt *);
bool ldns_pkt_cd(ldns_pkt *);
bool ldns_pkt_ra(ldns_pkt *);
bool ldns_pkt_ad(ldns_pkt *);
uint8_t ldns_pkt_opcode(ldns_pkt *);
uint8_t ldns_pkt_rcode(ldns_pkt *);
uint16_t ldns_pkt_qdcount(ldns_pkt *);
uint16_t ldns_pkt_ancount(ldns_pkt *);
uint16_t ldns_pkt_nscount(ldns_pkt *);
uint16_t ldns_pkt_arcount(ldns_pkt *);

ldns_rr_list *ldns_pkt_question(ldns_pkt *packet);
ldns_rr_list *ldns_pkt_answer(ldns_pkt *packet);
ldns_rr_list *ldns_pkt_authority(ldns_pkt *packet);
ldns_rr_list *ldns_pkt_additional(ldns_pkt *packet);

void ldns_pkt_set_id(ldns_pkt *, uint16_t);
void ldns_pkt_set_qr(ldns_pkt *, bool);
void ldns_pkt_set_aa(ldns_pkt *, bool);
void ldns_pkt_set_tc(ldns_pkt *, bool);
void ldns_pkt_set_rd(ldns_pkt *, bool);
void ldns_pkt_set_cd(ldns_pkt *, bool);
void ldns_pkt_set_ra(ldns_pkt *, bool);
void ldns_pkt_set_ad(ldns_pkt *, bool);
void ldns_pkt_set_opcode(ldns_pkt *, uint8_t);
void ldns_pkt_set_rcode(ldns_pkt *, uint8_t);
void ldns_pkt_set_qdcount(ldns_pkt *, uint16_t);
void ldns_pkt_set_ancount(ldns_pkt *, uint16_t);
void ldns_pkt_set_nscount(ldns_pkt *, uint16_t);
void ldns_pkt_set_arcount(ldns_pkt *, uint16_t);
void ldns_pkt_set_answerfrom(ldns_pkt *, ldns_rdf *);
void ldns_pkt_set_querytime(ldns_pkt *, uint32_t);

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

/**
 * Creates a query packet for the given name, type, class
 */
ldns_pkt * ldns_pkt_query_new_frm_str(char *, ldns_rr_type, ldns_rr_class);
ldns_pkt * ldns_pkt_query_new(ldns_rdf *, ldns_rr_type, ldns_rr_class);

#define MAX_PACKET_SIZE         65535

#endif  /* !_LDNS_PACKET_H */
