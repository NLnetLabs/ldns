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

/* Access functions 
 * do this as functions to get type checking
 */


/* read */
uint16_t
ldns_pkt_id(ldns_pkt *packet)
{
	return packet->_header->_id;
}

bool
ldns_pkt_qr(ldns_pkt *packet)
{
	return packet->_header->_qr;
}

bool
ldns_pkt_aa(ldns_pkt *packet)
{
	return packet->_header->_aa;
}

bool
ldns_pkt_tc(ldns_pkt *packet)
{
	return packet->_header->_tc;
}

bool
ldns_pkt_rd(ldns_pkt *packet)
{
	return packet->_header->_rd;
}

bool
ldns_pkt_cd(ldns_pkt *packet)
{
	return packet->_header->_cd;
}

bool
ldns_pkt_ra(ldns_pkt *packet)
{
	return packet->_header->_ra;
}

bool
ldns_pkt_ad(ldns_pkt *packet)
{
	return packet->_header->_ad;
}

uint8_t
ldns_pkt_opcode(ldns_pkt *packet)
{
	return packet->_header->_opcode;
}

uint8_t
ldns_pkt_rcode(ldns_pkt *packet)
{
	return packet->_header->_rcode;
}

uint16_t
ldns_pkt_qdcount(ldns_pkt *packet)
{
	return packet->_header->_qdcount;
}

uint16_t
ldns_pkt_ancount(ldns_pkt *packet)
{
	return packet->_header->_ancount;
}

uint16_t
ldns_pkt_nscount(ldns_pkt *packet)
{
	return packet->_header->_nscount;
}

uint16_t
ldns_pkt_arcount(ldns_pkt *packet)
{
	return packet->_header->_arcount;
}


/* write */
void
ldns_pkt_set_id(ldns_pkt *packet, uint16_t id)
{
	packet->_header->_id = id;
}

void
ldns_pkt_set_qr(ldns_pkt *packet, bool qr)
{
	packet->_header->_qr = qr;
}

void
ldns_pkt_set_aa(ldns_pkt *packet, bool aa)
{
	packet->_header->_aa = aa;
}

void
ldns_pkt_set_tc(ldns_pkt *packet, bool tc)
{
	packet->_header->_tc = tc;
}

void
ldns_pkt_set_rd(ldns_pkt *packet, bool rd)
{
	packet->_header->_rd = rd;
}

void
ldns_pkt_set_cd(ldns_pkt *packet, bool cd)
{
	packet->_header->_cd = cd;
}

void
ldns_pkt_set_ra(ldns_pkt *packet, bool ra)
{
	packet->_header->_ra = ra;
}

void
ldns_pkt_set_ad(ldns_pkt *packet, bool ad)
{
	packet->_header->_ad = ad;
}

void
ldns_pkt_set_opcode(ldns_pkt *packet, uint8_t opcode)
{
	packet->_header->_opcode = opcode;
}

void
ldns_pkt_set_rcode(ldns_pkt *packet, uint8_t rcode)
{
	packet->_header->_rcode = rcode;
}

void
ldns_pkt_set_qdcount(ldns_pkt *packet, uint16_t qdcount)
{
	packet->_header->_qdcount = qdcount;
}

void
ldns_pkt_set_ancount(ldns_pkt *packet, uint16_t ancount)
{
	packet->_header->_ancount = ancount;
}

void
ldns_pkt_set_nscount(ldns_pkt *packet, uint16_t nscount)
{
	packet->_header->_nscount = nscount;
}

void
ldns_pkt_set_arcount(ldns_pkt *packet, uint16_t arcount)
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

