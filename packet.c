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
ldns_pkt_id(const ldns_pkt *packet)
{
	return packet->_header->_id;
}

bool
ldns_pkt_qr(const ldns_pkt *packet)
{
	return packet->_header->_qr;
}

bool
ldns_pkt_aa(const ldns_pkt *packet)
{
	return packet->_header->_aa;
}

bool
ldns_pkt_tc(const ldns_pkt *packet)
{
	return packet->_header->_tc;
}

bool
ldns_pkt_rd(const ldns_pkt *packet)
{
	return packet->_header->_rd;
}

bool
ldns_pkt_cd(const ldns_pkt *packet)
{
	return packet->_header->_cd;
}

bool
ldns_pkt_ra(const ldns_pkt *packet)
{
	return packet->_header->_ra;
}

bool
ldns_pkt_ad(const ldns_pkt *packet)
{
	return packet->_header->_ad;
}

uint8_t
ldns_pkt_opcode(const ldns_pkt *packet)
{
	return packet->_header->_opcode;
}

uint8_t
ldns_pkt_rcode(const ldns_pkt *packet)
{
	return packet->_header->_rcode;
}

uint16_t
ldns_pkt_qdcount(const ldns_pkt *packet)
{
	return packet->_header->_qdcount;
}

uint16_t
ldns_pkt_ancount(const ldns_pkt *packet)
{
	return packet->_header->_ancount;
}

uint16_t
ldns_pkt_nscount(const ldns_pkt *packet)
{
	return packet->_header->_nscount;
}

uint16_t
ldns_pkt_arcount(const ldns_pkt *packet)
{
	return packet->_header->_arcount;
}

ldns_rr_list *
ldns_pkt_question(const ldns_pkt *packet)
{
	return packet->_question;
}

ldns_rr_list *
ldns_pkt_answer(const ldns_pkt *packet)
{
	return packet->_answer;
}

ldns_rr_list *
ldns_pkt_authority(const ldns_pkt *packet)
{
	return packet->_authority;
}

ldns_rr_list *
ldns_pkt_additional(const ldns_pkt *packet)
{
	return packet->_additional;
}

/* return ALL section concatenated */
ldns_rr_list *
ldns_pkt_all(ldns_pkt *packet)
{
	/* mem leaks?? :( */
	ldns_rr_list *all;

	all = ldns_rr_list_cat(
			ldns_pkt_xxsection(packet, LDNS_SECTION_QUESTION),
			ldns_pkt_xxsection(packet, LDNS_SECTION_ANSWER));
	all = ldns_rr_list_cat(all,
			ldns_pkt_xxsection(packet, LDNS_SECTION_AUTHORITY));
	all = ldns_rr_list_cat(all,
			ldns_pkt_xxsection(packet, LDNS_SECTION_ADDITIONAL));
	return all;
}

size_t
ldns_pkt_size(const ldns_pkt *packet)
{
	return packet->_size;
}

uint32_t 
ldns_pkt_querytime(const ldns_pkt *packet)
{
	return packet->_querytime;
}

ldns_rdf *
ldns_pkt_answerfrom(const ldns_pkt *packet)
{
	return packet->_answerfrom;
}

char *
ldns_pkt_when(const ldns_pkt *packet)
{
	return packet->_when;
}

/* return only those rr that share the ownername */
ldns_rr_list *
ldns_pkt_rr_list_by_name(ldns_pkt *packet, ldns_rdf *ownername, ldns_pkt_section sec)
{
	ldns_rr_list *rrs;
	ldns_rr_list *new;
	ldns_rr_list *ret;
	uint16_t i;

	rrs = ldns_pkt_xxsection(packet, sec);
	new = ldns_rr_list_new();
	ret = NULL;

	for(i = 0; i < ldns_rr_list_rr_count(rrs); i++) {
		if (ldns_rdf_compare(ldns_rr_owner(
						ldns_rr_list_rr(rrs, i)), 
					ownername) == 0) {
			/* owner names match */
			ldns_rr_list_push_rr(new, ldns_rr_list_rr(rrs, i));
			ret = new;
		}
	}
	return ret;
}

/* return only those rr that share a type */
ldns_rr_list *
ldns_pkt_rr_list_by_type(ldns_pkt *packet, ldns_rr_type type, ldns_pkt_section sec)
{
	ldns_rr_list *rrs;
	ldns_rr_list *new;
	ldns_rr_list *ret;
	uint16_t i;

	rrs = ldns_pkt_xxsection(packet, sec);
	new = ldns_rr_list_new();
	ret = NULL;

	for(i = 0; i < ldns_rr_list_rr_count(rrs); i++) {
		if (type == ldns_rr_get_type(ldns_rr_list_rr(rrs, i))) {
			/* types match */
			ldns_rr_list_push_rr(new, ldns_rr_list_rr(rrs, i));
			ret = new;
		}
	}
	return ret;
}

/** 
 * check to see if an rr exist in the packet
 * \param[in] pkt the packet to examine
 * \param[in] sec in which section to look
 * \param[in] rr the rr to look for
 */
bool
ldns_pkt_rr(ldns_pkt *pkt, ldns_pkt_section sec, ldns_rr *rr)
{
	ldns_rr_list *rrs;
	uint16_t rr_count;
	uint16_t i;

	rrs = ldns_pkt_xxsection(pkt, sec);
	if (!rrs) {
		return NULL;
	}
	rr_count = ldns_rr_list_rr_count(rrs);
	
	/* walk the rrs and compare them with rr */	
	for(i = 0; i < rr_count; i++) {
		if (ldns_rr_compare(ldns_rr_list_rr(rrs, i), rr) == 0) {
			/* a match */
			return true;
		}
	}
	return false;
}

uint16_t
ldns_pkt_xxcount(const ldns_pkt *packet, ldns_pkt_section s)
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
	case LDNS_SECTION_ANY:
		return ldns_pkt_qdcount(packet) +
			ldns_pkt_ancount(packet) +
			ldns_pkt_nscount(packet) +
			ldns_pkt_arcount(packet);
	default:
		abort();
	}
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
	case LDNS_SECTION_ANY:
		return ldns_pkt_all(packet);
	default:
		abort();
	}
}

ldns_rr *ldns_pkt_tsig(const ldns_pkt *pkt) {
	return pkt->_tsig_rr;
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
		case LDNS_SECTION_ANY:
			break;
	}
}

void ldns_pkt_set_tsig(ldns_pkt *pkt, ldns_rr *rr)
{
	pkt->_tsig_rr = rr;
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
		case LDNS_SECTION_ANY:
			break;
	}
	return true;
}

/** 
 * push an rr on a packet, provided the RR is not there.
 * \param[in] packet packet to operatore on
 * \param[in] section where to put it
 * \param[in] rr rr to push
 * \return ldns_status status
 */
bool
ldns_pkt_safe_push_rr(ldns_pkt *pkt, ldns_pkt_section sec, ldns_rr *rr)
{

	/* check to see if its there */
	if (ldns_pkt_rr(pkt, sec, rr)) {
		/* already there */
		return false;
	}
	return ldns_pkt_push_rr(pkt, sec, rr);
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
	
	packet->_tsig_rr = NULL;
	
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
	if (packet->_tsig_rr) {
		ldns_rr_free(packet->_tsig_rr);
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
	
	packet->_tsig_rr = NULL;
	
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
	
	packet->_tsig_rr = NULL;
	
	ldns_pkt_push_rr(packet, LDNS_SECTION_QUESTION, question_rr);

	return packet;
}

/**
 * look inside the packet to determine
 * what kind of packet it is, AUTH, NXDOMAIN, REFERRAL, etc.
 * \param[in] p the packet to examine
 * \return the type of packet
 */
ldns_pkt_type
ldns_pkt_reply_type(ldns_pkt *p)
{
	/* check for NXDOMAIN */

	/* check DNSSEC records... */

	if (ldns_pkt_ancount(p) == 0 && ldns_pkt_arcount(p) == 0
			&& ldns_pkt_nscount(p) == 1) {
		if (ldns_pkt_rr_list_by_type(p, LDNS_RR_TYPE_SOA, 
					LDNS_SECTION_AUTHORITY)) {
			/* there is a SOA */
			return LDNS_PACKET_NODATA;
		} else {
			/* I have no idea ... */
		}
	}

	if (ldns_pkt_ancount(p) == 0 & ldns_pkt_nscount(p) > 0) {
		if (ldns_pkt_rr_list_by_type(p, LDNS_RR_TYPE_NS,
					LDNS_SECTION_AUTHORITY)) {
			/* there are nameservers here */
			return LDNS_PACKET_REFERRAL;
		} else {
			/* I have no idea */
		}
	}
	
	/* if we cannot determine the packet type, we say it's an 
	 * answer...
	 */
	return LDNS_PACKET_ANSWER;
}
