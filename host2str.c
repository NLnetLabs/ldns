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

/** 
 * convert A address 
 */
ldns_status
ldns_rdf2buffer_a(ldns_buffer *output, ldns_rdf *rd)
{
	char r[INET_ADDRSTRLEN];
	ldns_status result = LDNS_STATUS_INTERNAL_ERR;
	
	if (inet_ntop(AF_INET, ldns_rdf_data(rd), r, INET_ADDRSTRLEN)) {
		if (ldns_buffer_printf(output, "%s", r) >= 0) {
			result = LDNS_STATUS_OK;
		}
	}

	return result;
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
		break;
	case LDNS_RDF_TYPE_INT16:
		break;
	case LDNS_RDF_TYPE_INT32:
		break;
	case LDNS_RDF_TYPE_INT48:
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

char *
ldns_rdf2str(ldns_rdf *rdf)
{
	char *result = NULL;
	ldns_buffer *tmp_buffer = ldns_buffer_new(1000);

	if (ldns_rdf2buffer(tmp_buffer, rdf) == LDNS_STATUS_OK) {
		/* export and return string, destroy rest */
		if (ldns_buffer_reserve(tmp_buffer, 1)) {
			ldns_buffer_write_u8(tmp_buffer, '\0');
			result = (char *) ldns_buffer_export(tmp_buffer);
		}
		ldns_buffer_free(tmp_buffer);
	}
	
	return result;
}



