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
#define	QDCOUNT(wirebuf)		(ntohs(*(uint16_t *)(wirebuf+QDCOUNT_OFF)))

/* Counter of the answer section */
#define ANCOUNT_OFF		6
#define	ANCOUNT(wirebuf)		(ntohs(*(uint16_t *)(wirebuf+ANCOUNT_OFF)))

/* Counter of the authority section */
#define NSCOUNT_OFF		8
#define	NSCOUNT(wirebuf)		(ntohs(*(uint16_t *)(wirebuf+NSCOUNT_OFF)))

/* Counter of the additional section */
#define ARCOUNT_OFF		10
#define	ARCOUNT(wirebuf)		(ntohs(*(uint16_t *)(wirebuf+ARCOUNT_OFF)))

/* Access functions 
 * do this as functions to get type checking
 */


/* read */
uint16_t
packet_id(ldns_packet_type *packet)
{
	return packet->_header->_id;
}

bool
packet_qr(ldns_packet_type *packet)
{
	return packet->_header->_qr;
}

bool
packet_aa(ldns_packet_type *packet)
{
	return packet->_header->_aa;
}

bool
packet_tc(ldns_packet_type *packet)
{
	return packet->_header->_tc;
}

bool
packet_rd(ldns_packet_type *packet)
{
	return packet->_header->_rd;
}

bool
packet_cd(ldns_packet_type *packet)
{
	return packet->_header->_cd;
}

bool
packet_ra(ldns_packet_type *packet)
{
	return packet->_header->_ra;
}

bool
packet_ad(ldns_packet_type *packet)
{
	return packet->_header->_ad;
}

uint8_t
packet_opcode(ldns_packet_type *packet)
{
	return packet->_header->_opcode;
}

uint8_t
packet_rcode(ldns_packet_type *packet)
{
	return packet->_header->_rcode;
}

uint16_t
packet_qdcount(ldns_packet_type *packet)
{
	return packet->_header->_qdcount;
}

uint16_t
packet_ancount(ldns_packet_type *packet)
{
	return packet->_header->_ancount;
}

uint16_t
packet_nscount(ldns_packet_type *packet)
{
	return packet->_header->_nscount;
}

uint16_t
packet_arcount(ldns_packet_type *packet)
{
	return packet->_header->_arcount;
}


/* write */
void
packet_set_id(ldns_packet_type *packet, uint16_t id)
{
	packet->_header->_id = id;
}

void
packet_set_qr(ldns_packet_type *packet, bool qr)
{
	packet->_header->_qr = qr;
}

void
packet_set_aa(ldns_packet_type *packet, bool aa)
{
	packet->_header->_aa = aa;
}

void
packet_set_tc(ldns_packet_type *packet, bool tc)
{
	packet->_header->_tc = tc;
}

void
packet_set_rd(ldns_packet_type *packet, bool rd)
{
	packet->_header->_rd = rd;
}

void
packet_set_cd(ldns_packet_type *packet, bool cd)
{
	packet->_header->_cd = cd;
}

void
packet_set_ra(ldns_packet_type *packet, bool ra)
{
	packet->_header->_ra = ra;
}

void
packet_set_ad(ldns_packet_type *packet, bool ad)
{
	packet->_header->_ad = ad;
}

void
packet_set_opcode(ldns_packet_type *packet, uint8_t opcode)
{
	packet->_header->_opcode = opcode;
}

void
packet_set_rcode(ldns_packet_type *packet, uint8_t rcode)
{
	packet->_header->_rcode = rcode;
}

void
packet_set_qdcount(ldns_packet_type *packet, uint16_t qdcount)
{
	packet->_header->_qdcount = qdcount;
}

void
packet_set_ancount(ldns_packet_type *packet, uint16_t ancount)
{
	packet->_header->_ancount = ancount;
}

void
packet_set_nscount(ldns_packet_type *packet, uint16_t nscount)
{
	packet->_header->_nscount = nscount;
}

void
packet_set_arcount(ldns_packet_type *packet, uint16_t arcount)
{
	packet->_header->_arcount = arcount;
}


/* Create/destroy/convert functions
 */
 
ldns_packet_type *
ldns_packet_new()
{
	ldns_packet_type *packet;
	packet = MALLOC(ldns_packet_type);
	if (!packet) {
		return NULL;
	}

	packet->_header = MALLOC(ldns_header_type);
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

static size_t
ldns_wire2packet_header(ldns_packet_type *packet,
			const uint8_t *wire,
			size_t max,
			size_t *pos)
{
	if (*pos + QHEADERSZ >= max) {
		/* TODO: set t_status error.  */
		return 0;
	} else {

		packet_set_id(packet, ID(wire));

		packet_set_qr(packet, QR(wire));
		packet_set_opcode(packet, OPCODE(wire));
		packet_set_aa(packet, AA(wire));
		packet_set_tc(packet, TC(wire));
		packet_set_rd(packet, RD(wire));
		packet_set_ra(packet, RA(wire));
		packet_set_ad(packet, AD(wire));
		packet_set_cd(packet, CD(wire));
		packet_set_rcode(packet, RCODE(wire));	 

		packet_set_qdcount(packet, QDCOUNT(wire));
		packet_set_ancount(packet, ANCOUNT(wire));
		packet_set_nscount(packet, NSCOUNT(wire));
		packet_set_arcount(packet, ARCOUNT(wire));

		*pos += QHEADERSZ;
		
		/* TODO t_status succ.  */
		return 0;
	}
}

size_t
ldns_wire2packet(ldns_packet_type *packet, const uint8_t *wire, size_t max)
{
	size_t pos = 0;

	pos += ldns_wire2packet_header(packet, wire, max, &pos);

	/* TODO: rrs :) */

	return pos;
}
