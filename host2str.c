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

#include <util.h>

/* lookup tables partly stolen from nsd, is there better way?
   are these used somewhere else? */

/* Taken from RFC 2538, section 2.1.  */
ldns_lookup_table ldns_certificate_types[] = {
        { 1, "PKIX" },  /* X.509 as per PKIX */
        { 2, "SPKI" },  /* SPKI cert */
        { 3, "PGP" },   /* PGP cert */
        { 253, "URI" }, /* URI private */
        { 254, "OID" }, /* OID private */
        { 0, NULL }
};

/* Taken from RFC 2535, section 7.  */
ldns_lookup_table ldns_algorithms[] = {
        { 1, "RSAMD5" },
        { 2, "DS" },
        { 3, "DSA" },
        { 4, "ECC" },
        { 5, "RSASHA1" },       /* XXX: Where is this specified? */
        { 252, "INDIRECT" },
        { 253, "PRIVATEDNS" },
        { 254, "PRIVATEOID" },
        { 0, NULL }
};

/* rr types (TODO: maybe these should be in rr.c? add enum? */
ldns_lookup_table ldns_rr_classes[] = {
	{ LDNS_RR_CLASS_IN, "IN" },
	{ LDNS_RR_CLASS_CHAOS, "CH" },
	{ LDNS_RR_CLASS_HS, "HS" },
	{ LDNS_RR_CLASS_ANY, "ANY" },
	{ 0, NULL }
};

/* if these are used elsewhere, move to packet.c? */
ldns_lookup_table ldns_rcodes[] = {
	{ 0, "NOERROR" },
	{ 1, "FORMERR" },
	{ 2, "SERVFAIL" },
	{ 3, "NAMEERR" },
	{ 4, "NOTIMPL" },
	{ 5, "REFUSED" },
	{ 0, NULL }
};

ldns_lookup_table ldns_opcodes[] = {
	{ 0, "QUERY" },
	{ 1, "IQUERY" },
	{ 2, "STATUS" },
	{ 0, NULL }
};

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
	
	return ldns_buffer_status(output);
}

ldns_status
ldns_rdf2buffer_int8(ldns_buffer *output, ldns_rdf *rdf)
{
	uint8_t data = ldns_rdf_data(rdf)[0];
	ldns_buffer_printf(output, "%lu", (unsigned long) data);
	return ldns_buffer_status(output);
}

ldns_status
ldns_rdf2buffer_int16(ldns_buffer *output, ldns_rdf *rdf)
{
	uint16_t data = read_uint16(ldns_rdf_data(rdf));
	ldns_buffer_printf(output, "%lu", (unsigned long) data);
	return ldns_buffer_status(output);
}

ldns_status
ldns_rdf2buffer_int32(ldns_buffer *output, ldns_rdf *rdf)
{
	uint32_t data = read_uint32(ldns_rdf_data(rdf));
	ldns_buffer_printf(output, "%lu", (unsigned long) data);
	return ldns_buffer_status(output);
}

ldns_status
ldns_rdf2buffer_int48(ldns_buffer *output, ldns_rdf *rdf)
{
	/* TODO */
	ldns_buffer_printf(output, "INT48 TODO");
	return ldns_buffer_status(output);
}

/** 
 * convert A address 
 */
ldns_status
ldns_rdf2buffer_a(ldns_buffer *output, ldns_rdf *rdf)
{
	char str[INET_ADDRSTRLEN];
	
	if (inet_ntop(AF_INET, ldns_rdf_data(rdf), str, INET_ADDRSTRLEN)) {
		ldns_buffer_printf(output, "%s", str);
	}
	return ldns_buffer_status(output);
}

/** 
 * convert AAAA address 
 */
ldns_status
ldns_rdf2buffer_aaaa(ldns_buffer *output, ldns_rdf *rdf)
{
	char str[INET6_ADDRSTRLEN];

	if (inet_ntop(AF_INET6, ldns_rdf_data(rdf), str, sizeof(str))) {
		ldns_buffer_printf(output, "%s", str);
	}

	return ldns_buffer_status(output);
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
			ldns_buffer_printf(output, "\\%03u", (unsigned) ch);
		}
	}
	ldns_buffer_printf(output, "\"");
	return ldns_buffer_status(output);
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

/* TODO status */
ldns_status
ldns_rr2buffer(ldns_buffer *output, ldns_rr *rr)
{
	uint16_t i;
	ldns_status status = LDNS_STATUS_OK;
	ldns_lookup_table *lt;
	const ldns_rr_descriptor *descriptor;
	
	if (ldns_rr_owner(rr)) {
		status = ldns_rdf2buffer_dname(output, ldns_rr_owner(rr));
	}
	if (status != LDNS_STATUS_OK) {
		return status;
	}
	
 	lt = ldns_lookup_by_id(ldns_rr_classes, ldns_rr_get_class(rr));
	if (lt) {
		ldns_buffer_printf(output, "\t%s\t", lt->name);
	} else {
		ldns_buffer_printf(output, "\tCLASS%d\t", ldns_rr_get_class(rr));
	}

	descriptor = ldns_rr_descript(ldns_rr_get_type(rr));

	if (descriptor->_name) {
		ldns_buffer_printf(output, "%s\t", descriptor->_name);
	} else {
		ldns_buffer_printf(output, "TYPE%d\t", ldns_rr_get_type(rr));
	}
	

	for (i = 0; i < ldns_rr_rd_count(rr); i++) {
		status = ldns_rdf2buffer(output, ldns_rr_rdf(rr, i));
		ldns_buffer_printf(output, " ");
	}
	
	return ldns_buffer_status(output);
}

/**
 * Prints the header in default format in the given buffer
 */
ldns_status
ldns_pktheader2buffer(ldns_buffer *output, ldns_pkt *pkt)
{
	/* TODO: strings for known names instead of numbers, flags etc */
	const char *opcode_str, *rcode_str;
	ldns_lookup_table *opcode = ldns_lookup_by_id(ldns_opcodes,
			                    (int) ldns_pkt_opcode(pkt));
	ldns_lookup_table *rcode = ldns_lookup_by_id(ldns_rcodes,
			                    (int) ldns_pkt_rcode(pkt));

	if (opcode) {
		opcode_str = opcode->name;
	} else {
		opcode_str = "??";
	}
	if (rcode) {
		rcode_str = rcode->name;
	} else {
		rcode_str = "??";
	}
	
	ldns_buffer_printf(output, ";; ->>HEADER<<- ");
	ldns_buffer_printf(output, "opcode: %s, ", opcode_str);
	ldns_buffer_printf(output, "rcode: %s, ", rcode_str);
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

	return ldns_buffer_status(output);
}
/* TODO check status returns */

ldns_status
ldns_pkt2buffer(ldns_buffer *output, ldns_pkt *pkt)
{
	uint16_t i;
	ldns_status status = LDNS_STATUS_OK;
	
	if (ldns_buffer_status_ok(output)) {
		status = ldns_pktheader2buffer(output, pkt);
		if (status != LDNS_STATUS_OK) {
			/*printf("error in pkt2buf %d\n", status);*/
			return status;
		}
		
		ldns_buffer_printf(output, "\n");
		
		ldns_buffer_printf(output, ";; QUESTION SECTION:\n;; ");

		for (i = 0; i < ldns_pkt_qdcount(pkt); i++) {
			status = ldns_rr2buffer(output, 
				       ldns_rr_list_rr(ldns_pkt_question(pkt), i));
			if (status != LDNS_STATUS_OK) {
				return status;
			}

			ldns_buffer_printf(output, "\n");
		}
		ldns_buffer_printf(output, "\n");
		
		ldns_buffer_printf(output, ";; ANSWER SECTION:\n");
		for (i = 0; i < ldns_pkt_ancount(pkt); i++) {
			status = ldns_rr2buffer(output, 
				       ldns_rr_list_rr(ldns_pkt_answer(pkt), i));
			if (status != LDNS_STATUS_OK) {
				return status;
			}

			ldns_buffer_printf(output, "\n");
		}
		ldns_buffer_printf(output, "\n");
		
		ldns_buffer_printf(output, ";; AUTHORITY SECTION:\n");

		for (i = 0; i < ldns_pkt_nscount(pkt); i++) {
			status = ldns_rr2buffer(output, 
				       ldns_rr_list_rr(ldns_pkt_authority(pkt), i));
			if (status != LDNS_STATUS_OK) {
				return status;
			}
			ldns_buffer_printf(output, "\n");
		}
		ldns_buffer_printf(output, "\n");
		
		ldns_buffer_printf(output, ";; ADDITIONAL SECTION:\n");
		for (i = 0; i < ldns_pkt_arcount(pkt); i++) {
			status = ldns_rr2buffer(output, 
				       ldns_rr_list_rr(ldns_pkt_additional(pkt), i));
			if (status != LDNS_STATUS_OK) {
				return status;
			}

			ldns_buffer_printf(output, "\n");
		}
		ldns_buffer_printf(output, "\n");
		
	} else {
		return ldns_buffer_status(output);
	}
	return status;
}

/*
 * Zero terminate the buffer and fix it to the size of the string.
 */
char *
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
