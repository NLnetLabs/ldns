/*
 * host2str.c
 *
 * conversion routines from the host format
 * to the presentation format (strings)
 *
 * a Net::DNS like library for C
 *
 * (c) NLnet Labs, 2004
 *
 * See the file LICENSE for the license
 */
#include <config.h>

#include <limits.h>

#include <sys/socket.h>
#include <arpa/inet.h>

#include <ldns/host2str.h>

#include "util.h"

/* TODO: general rdata2str or dname2str, with error
         checks and return status etc */
/* this is temp function for debugging wire2rr */
/* do NOT pass compressed data here :p */
ldns_status
ldns_rdf2buffer_dname(ldns_buffer *output, ldns_rdf *dname)
{
	/* can we do with 1 pos var? or without at all? */
	uint8_t src_pos = 0;
	uint8_t len;
	len = dname->_data[src_pos];
	while (len > 0) {
		src_pos++;
		ldns_buffer_write(output, &(dname->_data[src_pos]), len);
		src_pos += len;
		len = dname->_data[src_pos];
		ldns_buffer_printf(output, ".");
	}
	
	return LDNS_STATUS_OK;
}

ldns_status
ldns_rdf2buffer_int8(ldns_buffer *output, ldns_rdf *rdf)
{
	uint8_t data = ldns_rdf_data(rdf)[0];
	ldns_buffer_printf(output, "%lu", (unsigned long) data);
	return LDNS_STATUS_OK;
}

ldns_status
ldns_rdf2buffer_int16(ldns_buffer *output, ldns_rdf *rdf)
{
	uint16_t data = read_uint16(ldns_rdf_data(rdf));
	ldns_buffer_printf(output, "%lu", (unsigned long) data);
	return LDNS_STATUS_OK;
}

ldns_status
ldns_rdf2buffer_int32(ldns_buffer *output, ldns_rdf *rdf)
{
	uint32_t data = read_uint32(ldns_rdf_data(rdf));
	ldns_buffer_printf(output, "%lu", (unsigned long) data);
	return LDNS_STATUS_OK;
}

ldns_status
ldns_rdf2buffer_int48(ldns_buffer *output, ldns_rdf *rdf)
{
	/* TODO */
	ldns_buffer_printf(output, "INT48 TODO");
	return LDNS_STATUS_OK;
}

/** 
 * convert A address 
 */
ldns_status
ldns_rdf2buffer_a(ldns_buffer *output, ldns_rdf *rdf)
{
	char str[INET_ADDRSTRLEN];
	
	if (inet_ntop(AF_INET, ldns_rdf_data(rdf), str, INET_ADDRSTRLEN)) {
		if (ldns_buffer_printf(output, "%s", str) >= 0) {
			return LDNS_STATUS_OK;
		}
	}
	return LDNS_STATUS_INTERNAL_ERR;
}

/** 
 * convert AAAA address 
 */
ldns_status
ldns_rdf2buffer_aaaa(ldns_buffer *output, ldns_rdf *rdf)
{
	char str[INET6_ADDRSTRLEN];

	if (inet_ntop(AF_INET6, ldns_rdf_data(rdf), str, sizeof(str))) {
		if (ldns_buffer_printf(output, "%s", str) >= 0) {
			return LDNS_STATUS_OK;
		}
	}

	return LDNS_STATUS_INTERNAL_ERR;
}

ldns_status
ldns_rdf2buffer_str(ldns_buffer *output, ldns_rdf *rdf)
{
	const uint8_t *data = ldns_rdf_data(rdf);
	uint8_t length = data[0];
	size_t i;

	ldns_buffer_printf(output, "\"");
	for (i = 1; i <= length; ++i) {
		char ch = (char) data[i];
		if (isprint(ch)) {
			if (ch == '"' || ch == '\\') {
				ldns_buffer_printf(output, "\\");
			}
			ldns_buffer_printf(output, "%c", ch);
		} else {
			ldns_buffer_printf(output, "\\%03u",
				      (unsigned) ch);
		}
	}
	ldns_buffer_printf(output, "\"");
	return LDNS_STATUS_OK;
}

/**
 * Returns string representation of the specified rdf
 * Data is not static
 */
ldns_status
ldns_rdf2buffer(ldns_buffer *buffer, ldns_rdf *rdf)
{
	ldns_status res;
	
	switch(ldns_rdf_get_type(rdf)) {
	case LDNS_RDF_TYPE_NONE:
		break;
	case LDNS_RDF_TYPE_DNAME:
		res = ldns_rdf2buffer_dname(buffer, rdf);
		break;
	case LDNS_RDF_TYPE_INT8:
		res = ldns_rdf2buffer_int8(buffer, rdf);
		break;
	case LDNS_RDF_TYPE_INT16:
		res = ldns_rdf2buffer_int16(buffer, rdf);
		break;
	case LDNS_RDF_TYPE_INT32:
		res = ldns_rdf2buffer_int32(buffer, rdf);
		break;
	case LDNS_RDF_TYPE_INT48:
		res = ldns_rdf2buffer_int48(buffer, rdf);
		break;
	case LDNS_RDF_TYPE_A:
		res = ldns_rdf2buffer_a(buffer, rdf);
		break;
	case LDNS_RDF_TYPE_AAAA:
		break;
	case LDNS_RDF_TYPE_STR:
		res = ldns_rdf2buffer_str(buffer, rdf);
		break;
	case LDNS_RDF_TYPE_APL:
		break;
	case LDNS_RDF_TYPE_B64:
		break;
	case LDNS_RDF_TYPE_HEX:
		break;
	case LDNS_RDF_TYPE_NSEC: 
		break;
	case LDNS_RDF_TYPE_TYPE: 
		break;
	case LDNS_RDF_TYPE_CLASS:
		break;
	case LDNS_RDF_TYPE_CERT:
		break;
	case LDNS_RDF_TYPE_ALG:
		break;
	case LDNS_RDF_TYPE_UNKNOWN:
		break;
	case LDNS_RDF_TYPE_TIME:
		break;
	case LDNS_RDF_TYPE_SERVICE:
		break;
	case LDNS_RDF_TYPE_LOC:
		break;
	}

	return LDNS_STATUS_OK;
}

ldns_status
ldns_rr2buffer(ldns_buffer *output, ldns_rr *rr)
{
	ldns_status status = LDNS_STATUS_OK;
	
	if (ldns_rr_owner(rr)) {
		status = ldns_rdf2buffer_dname(output, ldns_rr_owner(rr));
	}
	
	if (status != LDNS_STATUS_OK) {
		printf("error in rr2buf %d\n", status);
	}
	
	return status;
}

/**
 * Prints the header in default format in the given buffer
 */
ldns_status
ldns_pktheader2buffer(ldns_buffer *output, ldns_pkt *pkt)
{
	/* TODO: strings for known names instead of numbers, flags etc */
	ldns_buffer_printf(output, ";; ->>HEADER<<- ");
	ldns_buffer_printf(output, "opcode: %u, ", ldns_pkt_opcode(pkt));
	ldns_buffer_printf(output, "status: %u, ", ldns_pkt_rcode(pkt));
	ldns_buffer_printf(output, "id %lu\n", ldns_pkt_id(pkt));

	ldns_buffer_printf(output, ";; flags: ");
	if (ldns_pkt_qr(pkt)) {
		ldns_buffer_printf(output, "qr ");
	}
	if (ldns_pkt_aa(pkt)) {
		ldns_buffer_printf(output, "aa ");
	}
	if (ldns_pkt_tc(pkt)) {
		ldns_buffer_printf(output, "tc ");
	}
	if (ldns_pkt_rd(pkt)) {
		ldns_buffer_printf(output, "rd ");
	}
	if (ldns_pkt_cd(pkt)) {
		ldns_buffer_printf(output, "cd ");
	}
	if (ldns_pkt_ra(pkt)) {
		ldns_buffer_printf(output, "ra ");
	}
	if (ldns_pkt_ad(pkt)) {
		ldns_buffer_printf(output, "ad ");
	}
	ldns_buffer_printf(output, "; ");
	ldns_buffer_printf(output, "QUERY: %u, ", ldns_pkt_qdcount(pkt));
	ldns_buffer_printf(output, "ANSWER: %u, ", ldns_pkt_ancount(pkt));
	ldns_buffer_printf(output, "AUTHORITY: %u, ", ldns_pkt_nscount(pkt));
	ldns_buffer_printf(output, "ADDITIONAL: %u, ", ldns_pkt_arcount(pkt));

	return LDNS_STATUS_OK;
}

/* TODO check status returns */

ldns_status
ldns_pkt2buffer(ldns_buffer *output, ldns_pkt *pkt)
{
	uint16_t i;
	ldns_status status = LDNS_STATUS_OK;
	
	status = ldns_pktheader2buffer(output, pkt);
	
	if (status != LDNS_STATUS_OK) {
		printf("error in pkt2buf %d\n", status);
	}
	
	ldns_buffer_printf(output, ";; QUESTION SECTION:\n;; ");
	for (i = 0; i < ldns_pkt_qdcount(pkt); i++) {
		status = ldns_rr2buffer(output, 
		               ldns_rrset_rr(ldns_pkt_question(pkt), i));
		ldns_buffer_printf(output, "\n");
	}
	
	ldns_buffer_printf(output, ";; ANSWER SECTION:\n");
	for (i = 0; i < ldns_pkt_ancount(pkt); i++) {
		status = ldns_rr2buffer(output, 
		               ldns_rrset_rr(ldns_pkt_answer(pkt), i));
		ldns_buffer_printf(output, "\n");
	}
	
	ldns_buffer_printf(output, ";; AUTHORITY SECTION:\n");
	for (i = 0; i < ldns_pkt_nscount(pkt); i++) {
		status = ldns_rr2buffer(output, 
		               ldns_rrset_rr(ldns_pkt_authority(pkt), i));
		ldns_buffer_printf(output, "\n");
	}
	
	ldns_buffer_printf(output, ";; ADDITIONAL SECTION:\n");
	for (i = 0; i < ldns_pkt_arcount(pkt); i++) {
		status = ldns_rr2buffer(output, 
		               ldns_rrset_rr(ldns_pkt_additional(pkt), i));
		ldns_buffer_printf(output, "\n");
	}
	
	return status;
}

/*
 * Zero terminate the buffer and fix it to the size of the string.
 */
static char *
buffer2str(ldns_buffer *buffer)
{
	if (!ldns_buffer_reserve(buffer, 1)) {
		return NULL;
	}
	ldns_buffer_write_u8(buffer, (uint8_t) '\0');
	if (!ldns_buffer_set_capacity(buffer, ldns_buffer_position(buffer))) {
		return NULL;
	}
	return ldns_buffer_export(buffer);
}

char *
ldns_rdf2str(ldns_rdf *rdf)
{
	char *result = NULL;
	ldns_buffer *tmp_buffer = ldns_buffer_new(1000);

	if (ldns_rdf2buffer(tmp_buffer, rdf) == LDNS_STATUS_OK) {
		/* export and return string, destroy rest */
		result = buffer2str(tmp_buffer);
	}
	
	ldns_buffer_free(tmp_buffer);
	return result;
}

char *
ldns_rr2str(ldns_rr *rr)
{
	char *result = NULL;
	ldns_buffer *tmp_buffer = ldns_buffer_new(1000);

	if (ldns_rr2buffer(tmp_buffer, rr) == LDNS_STATUS_OK) {
		/* export and return string, destroy rest */
		result = buffer2str(tmp_buffer);
	}
	
	ldns_buffer_free(tmp_buffer);
	return result;
}

char *
ldns_pkt2str(ldns_pkt *pkt)
{
	char *result = NULL;
	ldns_buffer *tmp_buffer = ldns_buffer_new(1000);

	if (ldns_pkt2buffer(tmp_buffer, pkt) == LDNS_STATUS_OK) {
		/* export and return string, destroy rest */
		result = buffer2str(tmp_buffer);
	}

	ldns_buffer_free(tmp_buffer);
	return result;
}
