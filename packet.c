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

#include "config.h"

#include "rdata.h"
#include "rr.h"
#include "prototype.h"
#include "packet.h"
#include "util.h"

/* Access functions 
 * do this as functions to get type checking
 */

/* read */
uint16_t
packet_id(t_packet *packet)
{
	return packet->header->id;
}

uint8_t
packet_qr(t_packet *packet)
{
	return packet->header->qr;
}

uint8_t
packet_aa(t_packet *packet)
{
	return packet->header->aa;
}

uint8_t
packet_tc(t_packet *packet)
{
	return packet->header->tc;
}

uint8_t
packet_rd(t_packet *packet)
{
	return packet->header->rd;
}

uint8_t
packet_cd(t_packet *packet)
{
	return packet->header->cd;
}

uint8_t
packet_ra(t_packet *packet)
{
	return packet->header->ra;
}

uint8_t
packet_ad(t_packet *packet)
{
	return packet->header->ad;
}

uint8_t
packet_opcode(t_packet *packet)
{
	return packet->header->opcode;
}

uint8_t
packet_rcode(t_packet *packet)
{
	return packet->header->rcode;
}

uint16_t
packet_qdcount(t_packet *packet)
{
	return packet->header->qdcount;
}

uint16_t
packet_ancount(t_packet *packet)
{
	return packet->header->ancount;
}

uint16_t
packet_nscount(t_packet *packet)
{
	return packet->header->nscount;
}

uint16_t
packet_arcount(t_packet *packet)
{
	return packet->header->arcount;
}


/* write */
void
packet_set_id(t_packet *packet, uint16_t id)
{
	packet->header->id = id;
}

void
packet_set_qr(t_packet *packet, uint8_t qr)
{
	packet->header->qr = qr;
}

void
packet_set_aa(t_packet *packet, uint8_t aa)
{
	packet->header->aa = aa;
}

void
packet_set_tc(t_packet *packet, uint8_t tc)
{
	packet->header->tc = tc;
}

void
packet_set_rd(t_packet *packet, uint8_t rd)
{
	packet->header->rd = rd;
}

void
packet_set_cd(t_packet *packet, uint8_t cd)
{
	packet->header->cd = cd;
}

void
packet_set_ra(t_packet *packet, uint8_t ra)
{
	packet->header->ra = ra;
}

void
packet_set_ad(t_packet *packet, uint8_t ad)
{
	packet->header->ad = ad;
}

void
packet_set_opcode(t_packet *packet, uint8_t opcode)
{
	packet->header->opcode = opcode;
}

void
packet_set_rcode(t_packet *packet, uint8_t rcode)
{
	packet->header->rcode = rcode;
}

void
packet_set_qdcount(t_packet *packet, uint16_t qdcount)
{
	packet->header->qdcount = qdcount;
}

void
packet_set_ancount(t_packet *packet, uint16_t ancount)
{
	packet->header->ancount = ancount;
}

void
packet_set_nscount(t_packet *packet, uint16_t nscount)
{
	packet->header->nscount = nscount;
}

void
packet_set_arcount(t_packet *packet, uint16_t arcount)
{
	packet->header->arcount = arcount;
}


/* Create/destroy/convert functions
 */
 
t_packet *
dns_packet_new()
{
	t_packet *packet;
	MALLOC(packet, t_packet);
	if (!packet) 
		return NULL;

	MALLOC(packet_header, t_header);
	if (!packet->header)
		return NULL;
	
	packet->question = NULL;
	packet->answer = NULL;
	packet->authority = NULL;
	packet->additional = NULL;
	return packet;
}

size_t
dns_wire2packet_header(uint8_t *wire, size_t pos, t_packet *packet)
{
	size_t len = 0;
	uint16_t int16;
	uint8_t int8;
	
	memcpy(&int16, &wire[pos+len], 2);
	packet_set_id(packet, ntohs(int16));
	len += 2;

	memcpy(&int8, &wire[pos+len], 1);
	packet_set_qr(packet, (int8 & (uint8_t) 0x80) >> 7);
	packet_set_opcode(packet, (int8 & (uint8_t) 0x78) >> 3);
	packet_set_aa(packet, (int8 & (uint8_t) 0x04) >> 2);
	packet_set_tc(packet, (int8 & (uint8_t) 0x02) >> 1);
	packet_set_rd(packet, (int8 & (uint8_t) 0x01));
	len++;
	
	memcpy(&int8, &wire[pos+len], 1);
	packet_set_ra(packet, (int8 & (uint8_t) 0x80) >> 7);
	packet_set_ad(packet, (int8 & (uint8_t) 0x20) >> 5);
	packet_set_cd(packet, (int8 & (uint8_t) 0x10) >> 4);
	packet_set_rcode(packet, (int8 & (uint8_t) 0x0f)); 	
	len++;

	memcpy(&int16, &wire[pos+len], 2);
	packet_set_qdcount(packet, ntohs(int16));
	len += 2;

	memcpy(&int16, &wire[pos+len], 2);
	packet_set_ancount(packet, ntohs(int16));
	len += 2;

	memcpy(&int16, &wire[pos+len], 2);
	packet_set_nscount(packet, ntohs(int16));
	len += 2;

	memcpy(&int16, &wire[pos+len], 2);
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

