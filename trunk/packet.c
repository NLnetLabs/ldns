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
packet_id(t_packet *packet)
{
	return packet->_header->_id;
}

bool
packet_qr(t_packet *packet)
{
	return packet->_header->_qr;
}

bool
packet_aa(t_packet *packet)
{
	return packet->_header->_aa;
}

bool
packet_tc(t_packet *packet)
{
	return packet->_header->_tc;
}

bool
packet_rd(t_packet *packet)
{
	return packet->_header->_rd;
}

bool
packet_cd(t_packet *packet)
{
	return packet->_header->_cd;
}

bool
packet_ra(t_packet *packet)
{
	return packet->_header->_ra;
}

bool
packet_ad(t_packet *packet)
{
	return packet->_header->_ad;
}

uint8_t
packet_opcode(t_packet *packet)
{
	return packet->_header->_opcode;
}

uint8_t
packet_rcode(t_packet *packet)
{
	return packet->_header->_rcode;
}

uint16_t
packet_qdcount(t_packet *packet)
{
	return packet->_header->_qdcount;
}

uint16_t
packet_ancount(t_packet *packet)
{
	return packet->_header->_ancount;
}

uint16_t
packet_nscount(t_packet *packet)
{
	return packet->_header->_nscount;
}

uint16_t
packet_arcount(t_packet *packet)
{
	return packet->_header->_arcount;
}


/* write */
void
packet_set_id(t_packet *packet, uint16_t id)
{
	packet->_header->_id = id;
}

void
packet_set_qr(t_packet *packet, bool qr)
{
	packet->_header->_qr = qr;
}

void
packet_set_aa(t_packet *packet, bool aa)
{
	packet->_header->_aa = aa;
}

void
packet_set_tc(t_packet *packet, bool tc)
{
	packet->_header->_tc = tc;
}

void
packet_set_rd(t_packet *packet, bool rd)
{
	packet->_header->_rd = rd;
}

void
packet_set_cd(t_packet *packet, bool cd)
{
	packet->_header->_cd = cd;
}

void
packet_set_ra(t_packet *packet, bool ra)
{
	packet->_header->_ra = ra;
}

void
packet_set_ad(t_packet *packet, bool ad)
{
	packet->_header->_ad = ad;
}

void
packet_set_opcode(t_packet *packet, uint8_t opcode)
{
	packet->_header->_opcode = opcode;
}

void
packet_set_rcode(t_packet *packet, uint8_t rcode)
{
	packet->_header->_rcode = rcode;
}

void
packet_set_qdcount(t_packet *packet, uint16_t qdcount)
{
	packet->_header->_qdcount = qdcount;
}

void
packet_set_ancount(t_packet *packet, uint16_t ancount)
{
	packet->_header->_ancount = ancount;
}

void
packet_set_nscount(t_packet *packet, uint16_t nscount)
{
	packet->_header->_nscount = nscount;
}

void
packet_set_arcount(t_packet *packet, uint16_t arcount)
{
	packet->_header->_arcount = arcount;
}


/* Create/destroy/convert functions
 */
 
t_packet *
dns_packet_new()
{
	t_packet *packet;
	MALLOC(packet, t_packet);
	if (!packet) {
		return NULL;
	}

	MALLOC(packet->_header, t_header);
	if (!packet->_header) {
		return NULL;
	}

	packet->_question = NULL;
	packet->_answer = NULL;
	packet->_authority = NULL;
	packet->_additional = NULL;
	return packet;
}

size_t
dns_wire2packet_header(uint8_t *wire, size_t pos, t_packet *packet)
{
	size_t len = 0;
	uint16_t int16;
	uint8_t int8;

	memcpy(&int16, &wire[pos + len], 2);
	packet_set_id(packet, ntohs(int16));
	len += 2;

	memcpy(&int8, &wire[pos + len], 1);
	packet_set_qr(packet, (int8 & (uint8_t) 0x80) >> 7);
	packet_set_opcode(packet, (int8 & (uint8_t) 0x78) >> 3);
	packet_set_aa(packet, (int8 & (uint8_t) 0x04) >> 2);
	packet_set_tc(packet, (int8 & (uint8_t) 0x02) >> 1);
	packet_set_rd(packet, (int8 & (uint8_t) 0x01));
	len++;

	memcpy(&int8, &wire[pos + len], 1);
	packet_set_ra(packet, (int8 & (uint8_t) 0x80) >> 7);
	packet_set_ad(packet, (int8 & (uint8_t) 0x20) >> 5);
	packet_set_cd(packet, (int8 & (uint8_t) 0x10) >> 4);
	packet_set_rcode(packet, (int8 & (uint8_t) 0x0f));	 
	len++;

	memcpy(&int16, &wire[pos + len], 2);
	packet_set_qdcount(packet, ntohs(int16));
	len += 2;

	memcpy(&int16, &wire[pos + len], 2);
	packet_set_ancount(packet, ntohs(int16));
	len += 2;

	memcpy(&int16, &wire[pos + len], 2);
	packet_set_nscount(packet, ntohs(int16));
	len += 2;

	memcpy(&int16, &wire[pos + len], 2);
	packet_set_arcount(packet, ntohs(int16));
	len += 2;

	return len;
}

size_t
dns_wire2packet(uint8_t *wire, t_packet *packet)
{
	size_t pos = 0;

	pos += dns_wire2packet_header(wire, pos, packet);

	/* TODO: rrs :) */

	return pos;
}
