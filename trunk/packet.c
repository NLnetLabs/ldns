/*
 * packet.c
 *
 * dns packet implementation
 *
 * a Net::DNS like library for C
 *
 * (c) NLnet Labs, 2004
 *
 * See the file LICENSE for the license
 */

#include <config.h>

#include <ldns/packet.h>

#include "util.h"

/*
 * Set of macro's to deal with the dns message header as specified
 * in RFC1035 in portable way.
 *
 */

/*
 *
 *                                    1  1  1  1  1  1
 *      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                      ID                       |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                    QDCOUNT                    |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                    ANCOUNT                    |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                    NSCOUNT                    |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                    ARCOUNT                    |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 */

/* The length of the header */
#define	QHEADERSZ	12

/* First octet of flags */
#define	RD_MASK		0x01U
#define	RD_SHIFT	0
#define	RD(wirebuf)	(*(wirebuf+2) & RD_MASK)
#define	RD_SET(wirebuf)	(*(wirebuf+2) |= RD_MASK)
#define	RD_CLR(wirebuf)	(*(wirebuf+2) &= ~RD_MASK)

#define TC_MASK		0x02U
#define TC_SHIFT	1
#define	TC(wirebuf)	(*(wirebuf+2) & TC_MASK)
#define	TC_SET(wirebuf)	(*(wirebuf+2) |= TC_MASK)
#define	TC_CLR(wirebuf)	(*(wirebuf+2) &= ~TC_MASK)

#define	AA_MASK		0x04U
#define	AA_SHIFT	2
#define	AA(wirebuf)	(*(wirebuf+2) & AA_MASK)
#define	AA_SET(wirebuf)	(*(wirebuf+2) |= AA_MASK)
#define	AA_CLR(wirebuf)	(*(wirebuf+2) &= ~AA_MASK)

#define	OPCODE_MASK	0x78U
#define	OPCODE_SHIFT	3
#define	OPCODE(wirebuf)	((*(wirebuf+2) & OPCODE_MASK) >> OPCODE_SHIFT)
#define	OPCODE_SET(wirebuf, opcode) \
	(*(wirebuf+2) = ((*(wirebuf+2)) & ~OPCODE_MASK) | ((opcode) << OPCODE_SHIFT))

#define	QR_MASK		0x80U
#define	QR_SHIFT	7
#define	QR(wirebuf)	(*(wirebuf+2) & QR_MASK)
#define	QR_SET(wirebuf)	(*(wirebuf+2) |= QR_MASK)
#define	QR_CLR(wirebuf)	(*(wirebuf+2) &= ~QR_MASK)

/* Second octet of flags */
#define	RCODE_MASK	0x0fU
#define	RCODE_SHIFT	0
#define	RCODE(wirebuf)	(*(wirebuf+3) & RCODE_MASK)
#define	RCODE_SET(wirebuf, rcode) \
	(*(wirebuf+3) = ((*(wirebuf+3)) & ~RCODE_MASK) | (rcode))

#define	CD_MASK		0x10U
#define	CD_SHIFT	4
#define	CD(wirebuf)	(*(wirebuf+3) & CD_MASK)
#define	CD_SET(wirebuf)	(*(wirebuf+3) |= CD_MASK)
#define	CD_CLR(wirebuf)	(*(wirebuf+3) &= ~CD_MASK)

#define	AD_MASK		0x20U
#define	AD_SHIFT	5
#define	AD(wirebuf)	(*(wirebuf+3) & AD_MASK)
#define	AD_SET(wirebuf)	(*(wirebuf+3) |= AD_MASK)
#define	AD_CLR(wirebuf)	(*(wirebuf+3) &= ~AD_MASK)

#define	Z_MASK		0x40U
#define	Z_SHIFT		6
#define	Z(wirebuf)	(*(wirebuf+3) & Z_MASK)
#define	Z_SET(wirebuf)	(*(wirebuf+3) |= Z_MASK)
#define	Z_CLR(wirebuf)	(*(wirebuf+3) &= ~Z_MASK)

#define	RA_MASK		0x80U
#define	RA_SHIFT	7
#define	RA(wirebuf)	(*(wirebuf+3) & RA_MASK)
#define	RA_SET(wirebuf)	(*(wirebuf+3) |= RA_MASK)
#define	RA_CLR(wirebuf)	(*(wirebuf+3) &= ~RA_MASK)

/* Query ID */
#define	ID(wirebuf)		(ntohs(*(uint16_t *)(wirebuf)))

/* Counter of the question section */
#define QDCOUNT_OFF		4
/*
#define	QDCOUNT(wirebuf)		(ntohs(*(uint16_t *)(wirebuf+QDCOUNT_OFF)))
*/
#define	QDCOUNT(wirebuf)		(read_uint16(wirebuf+QDCOUNT_OFF))

/* Counter of the answer section */
#define ANCOUNT_OFF		6
#define	ANCOUNT(wirebuf)		(read_uint16(wirebuf+ANCOUNT_OFF))

/* Counter of the authority section */
#define NSCOUNT_OFF		8
#define	NSCOUNT(wirebuf)		(read_uint16(wirebuf+NSCOUNT_OFF))

/* Counter of the additional section */
#define ARCOUNT_OFF		10
#define	ARCOUNT(wirebuf)		(read_uint16(wirebuf+ARCOUNT_OFF))

/* Access functions 
 * do this as functions to get type checking
 */


/* read */
uint16_t
pkt_id(ldns_pkt *packet)
{
	return packet->_header->_id;
}

bool
pkt_qr(ldns_pkt *packet)
{
	return packet->_header->_qr;
}

bool
pkt_aa(ldns_pkt *packet)
{
	return packet->_header->_aa;
}

bool
pkt_tc(ldns_pkt *packet)
{
	return packet->_header->_tc;
}

bool
pkt_rd(ldns_pkt *packet)
{
	return packet->_header->_rd;
}

bool
pkt_cd(ldns_pkt *packet)
{
	return packet->_header->_cd;
}

bool
pkt_ra(ldns_pkt *packet)
{
	return packet->_header->_ra;
}

bool
pkt_ad(ldns_pkt *packet)
{
	return packet->_header->_ad;
}

uint8_t
pkt_opcode(ldns_pkt *packet)
{
	return packet->_header->_opcode;
}

uint8_t
pkt_rcode(ldns_pkt *packet)
{
	return packet->_header->_rcode;
}

uint16_t
pkt_qdcount(ldns_pkt *packet)
{
	return packet->_header->_qdcount;
}

uint16_t
pkt_ancount(ldns_pkt *packet)
{
	return packet->_header->_ancount;
}

uint16_t
pkt_nscount(ldns_pkt *packet)
{
	return packet->_header->_nscount;
}

uint16_t
pkt_arcount(ldns_pkt *packet)
{
	return packet->_header->_arcount;
}


/* write */
void
pkt_set_id(ldns_pkt *packet, uint16_t id)
{
	packet->_header->_id = id;
}

void
pkt_set_qr(ldns_pkt *packet, bool qr)
{
	packet->_header->_qr = qr;
}

void
pkt_set_aa(ldns_pkt *packet, bool aa)
{
	packet->_header->_aa = aa;
}

void
pkt_set_tc(ldns_pkt *packet, bool tc)
{
	packet->_header->_tc = tc;
}

void
pkt_set_rd(ldns_pkt *packet, bool rd)
{
	packet->_header->_rd = rd;
}

void
pkt_set_cd(ldns_pkt *packet, bool cd)
{
	packet->_header->_cd = cd;
}

void
pkt_set_ra(ldns_pkt *packet, bool ra)
{
	packet->_header->_ra = ra;
}

void
pkt_set_ad(ldns_pkt *packet, bool ad)
{
	packet->_header->_ad = ad;
}

void
pkt_set_opcode(ldns_pkt *packet, uint8_t opcode)
{
	packet->_header->_opcode = opcode;
}

void
pkt_set_rcode(ldns_pkt *packet, uint8_t rcode)
{
	packet->_header->_rcode = rcode;
}

void
pkt_set_qdcount(ldns_pkt *packet, uint16_t qdcount)
{
	packet->_header->_qdcount = qdcount;
}

void
pkt_set_ancount(ldns_pkt *packet, uint16_t ancount)
{
	packet->_header->_ancount = ancount;
}

void
pkt_set_nscount(ldns_pkt *packet, uint16_t nscount)
{
	packet->_header->_nscount = nscount;
}

void
pkt_set_arcount(ldns_pkt *packet, uint16_t arcount)
{
	packet->_header->_arcount = arcount;
}


/* Create/destroy/convert functions
 */
 
ldns_pkt *
ldns_pkt_new()
{
	ldns_pkt *packet;
	packet = MALLOC(ldns_pkt);
	if (!packet) {
		return NULL;
	}

	packet->_header = MALLOC(ldns_hdr);
	if (!packet->_header) {
		FREE(packet);
		return NULL;
	}

	packet->_question = NULL;
	packet->_answer = NULL;
	packet->_authority = NULL;
	packet->_additional = NULL;
	return packet;
}

void
ldns_pkt_free(ldns_pkt *packet)
{
	FREE(packet->_header);
	if (packet->_question) {
		/*ldns_rrset_destroy(packet->_question);*/
	}
	if (packet->_answer) {
		/*ldns_rrset_destroy(packet->_answer);*/
		FREE(packet->_answer);
	}
	if (packet->_authority) {
		/*ldns_rrset_destroy(packet->_authority);*/
		FREE(packet->_authority);
	}
	if (packet->_additional) {
		/*ldns_rrset_destroy(packet->_additional);*/
		FREE(packet->_authority);
	}
	FREE(packet);
}

static size_t
ldns_wire2pkt_hdr(ldns_pkt *packet,
			const uint8_t *wire,
			size_t max,
			size_t *pos)
{
	if (*pos + QHEADERSZ >= max) {
		/* TODO: set t_status error.  */
		return 0;
	} else {

		pkt_set_id(packet, ID(wire));

		pkt_set_qr(packet, QR(wire));
		pkt_set_opcode(packet, OPCODE(wire));
		pkt_set_aa(packet, AA(wire));
		pkt_set_tc(packet, TC(wire));
		pkt_set_rd(packet, RD(wire));
		pkt_set_ra(packet, RA(wire));
		pkt_set_ad(packet, AD(wire));
		pkt_set_cd(packet, CD(wire));
		pkt_set_rcode(packet, RCODE(wire));	 

		pkt_set_qdcount(packet, QDCOUNT(wire));
		pkt_set_ancount(packet, ANCOUNT(wire));
		pkt_set_nscount(packet, NSCOUNT(wire));
		pkt_set_arcount(packet, ARCOUNT(wire));

		*pos += QHEADERSZ;
		/* TODO t_status succ.  */
		return 0;
	}
}

/* TODO: error check, return status (of this and of wire2rrs) */
size_t
ldns_wire2pkt(ldns_pkt *packet, const uint8_t *wire, size_t max)
{
	size_t pos = 0;
	uint16_t i;
	ldns_rr *rr;
	size_t ret;
	
	pos += ldns_wire2pkt_hdr(packet, wire, max, &pos);

	/* TODO: section enum :) */
	for (i = 0; i < pkt_qdcount(packet); i++) {
		rr = ldns_rr_new();
		ret = ldns_wire2rr(rr, wire, max, &pos, 0);
	}
	for (i = 0; i < pkt_ancount(packet); i++) {
		rr = ldns_rr_new();
		ret = ldns_wire2rr(rr, wire, max, &pos, 1);
	}
	for (i = 0; i < pkt_nscount(packet); i++) {
		rr = ldns_rr_new();
		ret = ldns_wire2rr(rr, wire, max, &pos, 2);
	}
	for (i = 0; i < pkt_arcount(packet); i++) {
		rr = ldns_rr_new();
		ret = ldns_wire2rr(rr, wire, max, &pos, 3);
	}

	return pos;
}
