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
 *  Header of a dns packet
 *
 * Contains the information about the packet itself
 */
struct ldns_struct_hdr
{
	/**  Id of a packet */
	uint16_t _id;
	/**  Query bit (0=query, 1=answer) */
	bool _qr;
	/**  Authoritative answer */
	bool _aa;
	/**  Packet truncated */
	bool _tc;
	/**  Recursion desired */
	bool _rd;
	/**  Checking disabled */
	bool _cd;
	/**  Recursion available */
	bool _ra;
	/**  Authentic data */
	bool _ad;
	/**  Query type */
	uint8_t _opcode;	 /* XXX 8 bits? */
	/**  Response code */
	uint8_t _rcode;
	/**  question sec */
	uint16_t _qdcount;
	/**  answer sec */
	uint16_t _ancount;
	/**  auth sec */
	uint16_t _nscount;
	/**  add sec */
	uint16_t _arcount;
};
typedef struct ldns_struct_hdr ldns_hdr;

/**
 * DNS packet
 *
 * This structure contains a complete DNS packet (either a query or an answer)
 */
struct ldns_struct_pkt
{
	/**  header section */
	ldns_hdr *_header;
	/* extra items needed in a packet */
	/**  the size in bytes of the pkt */
	uint16_t _answersize;
	ldns_rdf *_answerfrom;
	char *_when;
	/**  query duration */
	uint32_t _querytime;
	/**  the packet size */
	size_t _size;
	/** optional tsig rr */
	ldns_rr *_tsig_rr;
	/** EDNS0 values */
	uint16_t _edns_udp_size;
	uint8_t _edns_extended_rcode;
	uint8_t _edns_version;
	uint16_t _edns_z;
	ldns_rdf *_edns_data;
	/**  query data */
	/**  question section */
	ldns_rr_list	*_question;
	/**  answer section */
	ldns_rr_list	*_answer;
	/**  auth section */
	ldns_rr_list	*_authority;
	/**  add section */
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
	/** bogus section, if not interested */
	LDNS_SECTION_ANY = 4,
	/** used to get all non-question rrs from a packet */
	LDNS_SECTION_ANY_NOQUESTION = 5
};
typedef enum ldns_enum_pkt_section ldns_pkt_section;	

/**
 * The different types of packets
 */
enum ldns_enum_pkt_type {
	LDNS_PACKET_QUESTION,
	LDNS_PACKET_REFERRAL,
	LDNS_PACKET_ANSWER,
	LDNS_PACKET_NXDOMAIN,
	LDNS_PACKET_NODATA,
	LDNS_PACKET_UNKNOWN
};
typedef enum ldns_enum_pkt_type ldns_pkt_type;

/* prototypes */
/* read */
uint16_t ldns_pkt_id(const ldns_pkt *p);
bool ldns_pkt_qr(const ldns_pkt *p);
bool ldns_pkt_aa(const ldns_pkt *p);
bool ldns_pkt_tc(const ldns_pkt *p);
bool ldns_pkt_rd(const ldns_pkt *p);
bool ldns_pkt_cd(const ldns_pkt *p);
bool ldns_pkt_ra(const ldns_pkt *p);
bool ldns_pkt_ad(const ldns_pkt *p);

uint8_t ldns_pkt_opcode(const ldns_pkt *p);
uint8_t ldns_pkt_rcode(const ldns_pkt *p);
uint16_t ldns_pkt_qdcount(const ldns_pkt *p);
uint16_t ldns_pkt_ancount(const ldns_pkt *p);
uint16_t ldns_pkt_nscount(const ldns_pkt *p);
uint16_t ldns_pkt_arcount(const ldns_pkt *p);
ldns_rdf *ldns_pkt_answerfrom(const ldns_pkt *p);
char *ldns_pkt_when(const ldns_pkt *p);
uint32_t ldns_pkt_querytime(const ldns_pkt *p);
size_t ldns_pkt_size(const ldns_pkt *p);
ldns_rr *ldns_pkt_tsig(const ldns_pkt *p);

ldns_rr_list *ldns_pkt_question(const ldns_pkt *p);
ldns_rr_list *ldns_pkt_answer(const ldns_pkt *p);
ldns_rr_list *ldns_pkt_authority(const ldns_pkt *p);
ldns_rr_list *ldns_pkt_additional(const ldns_pkt *p);
ldns_rr_list *ldns_pkt_xxsection(ldns_pkt *p, ldns_pkt_section s);
ldns_rr_list *ldns_pkt_rr_list_by_name(ldns_pkt *p, ldns_rdf *r, ldns_pkt_section s);
ldns_rr_list *ldns_pkt_rr_list_by_type(ldns_pkt *p, ldns_rr_type t, ldns_pkt_section s);
ldns_rr_list *ldns_pkt_rr_list_by_name_and_type(ldns_pkt *packet, ldns_rdf *ownername, ldns_rr_type type, ldns_pkt_section sec);

/**
 * sets the flags in a packet.
 * \param[in] pkt the packet to operate on
 * \param[in] flags ORed values: LDNS_QR| LDNS_AR for instance
 * \return true on success otherwise false
 */
bool ldns_pkt_set_flags(ldns_pkt *pkt, uint16_t flags);

void ldns_pkt_set_id(ldns_pkt *p, uint16_t id);
void ldns_pkt_set_qr(ldns_pkt *p, bool b);
void ldns_pkt_set_aa(ldns_pkt *p, bool b);
void ldns_pkt_set_tc(ldns_pkt *p, bool b);
void ldns_pkt_set_rd(ldns_pkt *p, bool b);
void ldns_pkt_set_cd(ldns_pkt *p, bool b);
void ldns_pkt_set_ra(ldns_pkt *p, bool b);
void ldns_pkt_set_ad(ldns_pkt *p, bool b);
void ldns_pkt_set_opcode(ldns_pkt *p, uint8_t c);
void ldns_pkt_set_rcode(ldns_pkt *p, uint8_t c);
void ldns_pkt_set_qdcount(ldns_pkt *p, uint16_t c);
void ldns_pkt_set_ancount(ldns_pkt *p, uint16_t c);
void ldns_pkt_set_nscount(ldns_pkt *p, uint16_t c);
void ldns_pkt_set_arcount(ldns_pkt *p, uint16_t c);
void ldns_pkt_set_answerfrom(ldns_pkt *p, ldns_rdf *r);
void ldns_pkt_set_querytime(ldns_pkt *p, uint32_t t);
void ldns_pkt_set_size(ldns_pkt *p, size_t s);
void ldns_pkt_set_when(ldns_pkt *p, char *w);
void ldns_pkt_set_xxcount(ldns_pkt *p, ldns_pkt_section s, uint16_t x);
void ldns_pkt_set_tsig(ldns_pkt *p, ldns_rr *t);

/**
 * looks inside the packet to determine
 * what kind of packet it is, AUTH, NXDOMAIN, REFERRAL, etc.
 * \param[in] p the packet to examine
 * \return the type of packet
 */
ldns_pkt_type ldns_pkt_reply_type(ldns_pkt *p);

uint16_t ldns_pkt_edns_udp_size(const ldns_pkt *packet);
uint8_t ldns_pkt_edns_extended_rcode(const ldns_pkt *packet);
uint8_t ldns_pkt_edns_version(const ldns_pkt *packet);
uint16_t ldns_pkt_edns_z(const ldns_pkt *packet);
ldns_rdf *ldns_pkt_edns_data(const ldns_pkt *packet);
bool ldns_pkt_edns_do(const ldns_pkt *packet);
void ldns_pkt_set_edns_do(ldns_pkt *packet, bool value);

/**
 * returns true if this packet needs and EDNS rr to be sent.
 * At the moment the only reason is an expected packet
 * size larger than 512 bytes, but for instance dnssec would
 * be a good reason too.
 *
 * \param[in] packet the packet to check
 * \return true if packet needs edns rr
 */
bool ldns_pkt_edns(const ldns_pkt *packet);
void ldns_pkt_set_edns_udp_size(ldns_pkt *packet, uint16_t s);
void ldns_pkt_set_edns_extended_rcode(ldns_pkt *packet, uint8_t c);
void ldns_pkt_set_edns_version(ldns_pkt *packet, uint8_t v);
void ldns_pkt_set_edns_z(ldns_pkt *packet, uint16_t z);
void ldns_pkt_set_edns_data(ldns_pkt *packet, ldns_rdf *data);

/**
 * allocates and initializes a ldns_pkt structure.
 * \return pointer to the new packet
 */
ldns_pkt *ldns_pkt_new();

/**
 * frees the packet structure and all data that it contains.
 * \param[in] packet The packet structure to free
 * \return void
 */
void ldns_pkt_free(ldns_pkt *packet);

/**
 * creates a query packet for the given name, type, class.
 * \param[in] rr_name the name to query for (as string)
 * \param[in] rr_type the type to query for
 * \param[in] rr_class the class to query for
 * \param[in] flags packet flags
 * \return ldns_pkt* a pointer to the new pkt
 */
ldns_pkt *ldns_pkt_query_new_frm_str(const char *rr_name, ldns_rr_type rr_type, ldns_rr_class rr_class , uint16_t flags);

/**
 * creates a packet with a query in it for the given name, type and class.
 * \param[in] rr_name the name to query for
 * \param[in] rr_type the type to query for
 * \param[in] rr_class the class to query for
 * \param[in] flags packet flags
 * \return ldns_pkt* a pointer to the new pkt
 */
ldns_pkt *ldns_pkt_query_new(ldns_rdf *rr_name, ldns_rr_type rr_type, ldns_rr_class rr_class, uint16_t flags);

/**
 * clones the given packet, creating a fully allocated copy
 *
 * \param[in] pkt the packet to clone
 * \return ldns_pkt* pointer to the new packet
 */
ldns_pkt *ldns_pkt_deep_clone(ldns_pkt *pkt);

#define LDNS_MAX_PACKETLEN         65535

/* allow flags to be given to mk_query */
#define LDNS_QR		1
#define LDNS_AA		2
#define LDNS_TC		4
#define LDNS_RD		8
#define LDNS_CD		16
#define LDNS_RA		32
#define LDNS_AD		64

#endif  /* !_LDNS_PACKET_H */
