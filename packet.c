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
#include <ldns/str2host.h>
#include <ldns/host2str.h>

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

ldns_rr_list *
ldns_pkt_question(ldns_pkt *packet)
{
	return packet->_question;
}

ldns_rr_list *
ldns_pkt_answer(ldns_pkt *packet)
{
	return packet->_answer;
}

ldns_rr_list *
ldns_pkt_authority(ldns_pkt *packet)
{
	return packet->_authority;
}

ldns_rr_list *
ldns_pkt_additional(ldns_pkt *packet)
{
	return packet->_additional;
}

size_t
ldns_pkt_size(ldns_pkt *packet)
{
	return packet->_size;
}

uint32_t 
ldns_pkt_querytime(ldns_pkt *packet)
{
	return packet->_querytime;
}

ldns_rdf *
ldns_pkt_answerfrom(ldns_pkt *packet)
{
	return packet->_answerfrom;
}

char *
ldns_pkt_when(ldns_pkt *packet)
{
	return packet->_when;
}

uint16_t
ldns_pkt_xxcount(ldns_pkt *packet, ldns_pkt_section s)
{
	switch(s) {
		case LDNS_SECTION_QUESTION:
			return ldns_pkt_qdcount(packet);
		case LDNS_SECTION_ANSWER:
			return ldns_pkt_ancount(packet);
		case LDNS_SECTION_AUTHORITY:
			return ldns_pkt_nscount(packet);
		case LDNS_SECTION_ADDITIONAL:
			return ldns_pkt_arcount(packet);
	}
	return 0;
}

ldns_rr_list *
ldns_pkt_xxsection(ldns_pkt *packet, ldns_pkt_section s)
{
	switch(s) {
		case LDNS_SECTION_QUESTION:
			return ldns_pkt_question(packet);
		case LDNS_SECTION_ANSWER:
			return ldns_pkt_answer(packet);
		case LDNS_SECTION_AUTHORITY:
			return ldns_pkt_authority(packet);
		case LDNS_SECTION_ADDITIONAL:
			return ldns_pkt_additional(packet);
	}
	return NULL;
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

void
ldns_pkt_set_querytime(ldns_pkt *packet, uint32_t time) 
{
	packet->_querytime = time;
}

void
ldns_pkt_set_answerfrom(ldns_pkt *packet, ldns_rdf *answerfrom)
{
	/* TODO if exists free? */
	packet->_answerfrom = answerfrom;
}

void
ldns_pkt_set_when(ldns_pkt *packet, char *when)
{
	/* TODO if exists free? */
	packet->_when = when;
}

void
ldns_pkt_set_size(ldns_pkt *packet, size_t s)
{
	packet->_size = s;
}

void
ldns_pkt_set_xxcount(ldns_pkt *packet, ldns_pkt_section s, uint16_t count)
{
	switch(s) {
		case LDNS_SECTION_QUESTION:
			ldns_pkt_set_qdcount(packet, count);
			break;
		case LDNS_SECTION_ANSWER:
			ldns_pkt_set_ancount(packet, count);
			break;
		case LDNS_SECTION_AUTHORITY:
			ldns_pkt_set_nscount(packet, count);
			break;
		case LDNS_SECTION_ADDITIONAL:
			ldns_pkt_set_arcount(packet, count);
			break;
	}
}


/** 
 * push an rr on a packet
 * \param[in] packet packet to operatore on
 * \param[in] section where to put it
 * \param[in] rr rr to push
 * \return ldns_status status
 */
bool
ldns_pkt_push_rr(ldns_pkt *packet, ldns_pkt_section section, ldns_rr *rr)
{
	ldns_rr_list *rrs;

	/* get the right rr list for this section */
	rrs = ldns_pkt_xxsection(packet, section);
	if (!rrs) {
		return false;
	}
	/* push the rr */
	ldns_rr_list_push_rr(rrs, rr);
	
	/* TODO: move this to separate function? */
	switch(section) {
		case LDNS_SECTION_QUESTION:
			ldns_pkt_set_qdcount(packet, ldns_pkt_qdcount(packet) + 1);
			break;
		case LDNS_SECTION_ANSWER:
			ldns_pkt_set_ancount(packet, ldns_pkt_ancount(packet) + 1);
			break;
		case LDNS_SECTION_AUTHORITY:
			ldns_pkt_set_nscount(packet, ldns_pkt_nscount(packet) + 1);
			break;
		case LDNS_SECTION_ADDITIONAL:
			ldns_pkt_set_arcount(packet, ldns_pkt_arcount(packet) + 1);
			break;
	}
	return true;
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

	packet->_question = ldns_rr_list_new();
	packet->_answer = ldns_rr_list_new();
	packet->_authority = ldns_rr_list_new();
	packet->_additional = ldns_rr_list_new();

	/* default everything to false */
	ldns_pkt_set_qr(packet, false);
	ldns_pkt_set_aa(packet, false);
	ldns_pkt_set_tc(packet, false);
	ldns_pkt_set_rd(packet, false);
	ldns_pkt_set_ra(packet, false);
	ldns_pkt_set_ad(packet, false);

	ldns_pkt_set_opcode(packet, 0);
	ldns_pkt_set_id(packet, 0);
	ldns_pkt_set_size(packet, 0);
	ldns_pkt_set_querytime(packet, 0);
	ldns_pkt_set_answerfrom(packet, NULL);
	ldns_pkt_set_when(packet, NULL);
	ldns_pkt_set_xxcount(packet, LDNS_SECTION_QUESTION, 0);
	ldns_pkt_set_xxcount(packet, LDNS_SECTION_ANSWER, 0);
	ldns_pkt_set_xxcount(packet, LDNS_SECTION_AUTHORITY, 0);
	ldns_pkt_set_xxcount(packet, LDNS_SECTION_ADDITIONAL, 0);
	
	return packet;
}

void
ldns_pkt_free(ldns_pkt *packet)
{
	FREE(packet->_header);
	if (packet->_question) {
		ldns_rr_list_free(packet->_question);
	}
	if (packet->_answer) {
		ldns_rr_list_free(packet->_answer);
	}
	if (packet->_authority) {
		ldns_rr_list_free(packet->_authority);
	}
	if (packet->_additional) {
		ldns_rr_list_free(packet->_additional);
	}
	FREE(packet);
}

/**
 * Set the flags in a packet
 * \param[in] packet the packet to operate on
 * \param[in] flags ORed values: LDNS_QR| LDNS_AR for instance
 * \return true on success otherwise false
 */
bool
ldns_pkt_set_flags(ldns_pkt *packet, uint16_t flags)
{
	if (!packet) {
		return false;
	}
	if ((flags & LDNS_QR) == LDNS_QR) {
		ldns_pkt_set_qr(packet, true);
	}
	if ((flags & LDNS_AA) == LDNS_AA) {
		ldns_pkt_set_aa(packet, true);
	}
	if ((flags & LDNS_RD) == LDNS_RD) {
		ldns_pkt_set_rd(packet, true);
	}
	if ((flags & LDNS_TC) == LDNS_TC) {
		ldns_pkt_set_tc(packet, true);
	}
	if ((flags & LDNS_CD) == LDNS_CD) {
		ldns_pkt_set_cd(packet, true);
	}
	if ((flags & LDNS_RA) == LDNS_RA) {
		ldns_pkt_set_ra(packet, true);
	}
	if ((flags & LDNS_AD) == LDNS_AD) {
		ldns_pkt_set_ad(packet, true);
	}
	return true;
}

ldns_pkt *
ldns_pkt_query_new_frm_str(const char *name, ldns_rr_type rr_type, ldns_rr_class rr_class,
		uint16_t flags)
{
	ldns_pkt *packet;
	ldns_rr *question_rr;
	ldns_rdf *name_rdf;

	packet = ldns_pkt_new();
	if (!packet) {
		return NULL;
	}
	
	if (!ldns_pkt_set_flags(packet, flags)) {
		return NULL;
	}
	
	question_rr = ldns_rr_new();
	if (!question_rr) {
		return NULL;
	}

	if (rr_type == 0) {
		rr_type = LDNS_RR_TYPE_A;
	}
	if (rr_class == 0) {
		rr_class = LDNS_RR_CLASS_IN;
	}

	if (ldns_str2rdf_dname(&name_rdf, name) == LDNS_STATUS_OK) {
		ldns_rr_set_owner(question_rr, name_rdf);
		ldns_rr_set_type(question_rr, rr_type);
		ldns_rr_set_class(question_rr, rr_class);
		
		ldns_pkt_push_rr(packet, LDNS_SECTION_QUESTION, question_rr);
	} else {
		ldns_rr_free(question_rr);
		ldns_pkt_free(packet);
		return NULL;
	}
	
	ldns_pkt_set_answerfrom(packet, NULL);
	
	return packet;
}

/**
 * Create a packet with a query in it
 * \param[in] name the name to query for
 * \param[in] type the type to query for
 * \param[in] class the class to query for
 * \return ldns_pkt* a pointer to the new pkt
 */
ldns_pkt *
ldns_pkt_query_new(ldns_rdf *rr_name, ldns_rr_type rr_type, ldns_rr_class rr_class,
		uint16_t flags)
{
	ldns_pkt *packet;
	ldns_rr *question_rr;

	packet = ldns_pkt_new();
	if (!packet) {
		return NULL;
	}

	if (!ldns_pkt_set_flags(packet, flags)) {
		return NULL;
	}
	
	question_rr = ldns_rr_new();
	if (!question_rr) {
		return NULL;
	}

	if (rr_type == 0) {
		rr_type = LDNS_RR_TYPE_A;
	}
	if (rr_class == 0) {
		rr_class = LDNS_RR_CLASS_IN;
	}

	ldns_rr_set_owner(question_rr, rr_name);
	ldns_rr_set_type(question_rr, rr_type);
	ldns_rr_set_class(question_rr, rr_class);
	
	ldns_pkt_push_rr(packet, LDNS_SECTION_QUESTION, question_rr);

	return packet;
}

/**
 * look inside the packet to determine
 * what kind of packet it is, AUTH, NXDOMAIN, REFERRAL, etc.
 * \param[in] p the packet to examine
 * \return the type of packet
 * \todo there are no packet types!
 */
void
ldns_pkt_reply_type(ldns_pkt *p)
{
	/* i'm looking in the packet */
	/* for now only print so parameter is used :p */
	printf("Determining packet type of packet:\n");
	ldns_pkt_print(stdout, p);
}
