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
	ldns_rdf *_answerfrom;
	char *_when;
	/** \brief query duration */
	uint32_t _querytime;
	/** \brief the packet size */
	size_t _size;
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
	LDNS_SECTION_ADDITIONAL = 3,
	LDNS_SECTION_ANY = 4  /* bogus section, if not interested */
};
typedef enum ldns_enum_pkt_section ldns_pkt_section;	

/**
 * the different types of packets
 * \todo Do we need this??? MIEK
 */
enum ldns_enum_pkt_type {
	LDNS_PACKET_QUESTION,
	LDNS_PACKET_REFERRAL,
	LDNS_PACKET_ANSWER,
	LDNS_PACKET_NXDOMAIN,
	LDNS_PACKET_NODATA
};
typedef enum ldns_enum_pkt_type ldns_pkt_type;

/* prototypes */
uint16_t ldns_pkt_id(ldns_pkt *);
bool ldns_pkt_qr(ldns_pkt *);
bool ldns_pkt_aa(ldns_pkt *);
bool ldns_pkt_tc(ldns_pkt *);
bool ldns_pkt_rd(ldns_pkt *);
bool ldns_pkt_cd(ldns_pkt *);
bool ldns_pkt_ra(ldns_pkt *);
bool ldns_pkt_ad(ldns_pkt *);
bool ldns_pkt_set_flags(ldns_pkt *, uint16_t);
uint8_t ldns_pkt_opcode(ldns_pkt *);
uint8_t ldns_pkt_rcode(ldns_pkt *);
uint16_t ldns_pkt_qdcount(ldns_pkt *);
uint16_t ldns_pkt_ancount(ldns_pkt *);
uint16_t ldns_pkt_nscount(ldns_pkt *);
uint16_t ldns_pkt_arcount(ldns_pkt *);
ldns_rdf *ldns_pkt_answerfrom(ldns_pkt *packet);
char *ldns_pkt_when(ldns_pkt *packet);
uint32_t ldns_pkt_querytime(ldns_pkt *);
size_t ldns_pkt_size(ldns_pkt *);

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
void ldns_pkt_set_size(ldns_pkt *, size_t);
void ldns_pkt_set_when(ldns_pkt *, char *);
void ldns_pkt_set_xxcount(ldns_pkt *, ldns_pkt_section, uint16_t);

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
ldns_pkt * ldns_pkt_query_new_frm_str(const char *, ldns_rr_type, ldns_rr_class, uint16_t);
ldns_pkt * ldns_pkt_query_new(ldns_rdf *, ldns_rr_type, ldns_rr_class, uint16_t);

#define MAX_PACKETLEN         65535

/* allow flags to be given to mk_query */
#define LDNS_QR		1
#define LDNS_AA		2
#define LDNS_TC		4
#define LDNS_RD		8
#define LDNS_CD		16
#define LDNS_RA		32
#define LDNS_AD		64

#endif  /* !_LDNS_PACKET_H */
