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
char *
ldns_dname2str(ldns_rdf *dname)
{
	/* can we do with 1 pos var? or without at all? */
	uint8_t src_pos = 0;
	uint8_t dest_pos = 0;
	uint8_t len;
	char *dest = XMALLOC(char, MAXDOMAINLEN);
	char *res;
	len = dname->_data[src_pos];
	while (len > 0) {
		src_pos++;
		memcpy(&dest[dest_pos], &(dname->_data[src_pos]), len);
		dest_pos += len;
		src_pos += len;
		len = dname->_data[src_pos];
		dest[dest_pos] = '.';
		dest_pos++;
	}
	dest[dest_pos] = '\0';
	res = XMALLOC(char, sizeof(dest));
	memcpy(res, dest, sizeof(dest));
	
	return dest;
}

int
rdata_text_to_string(ldns_buffer *output, ldns_rdf *rdf)
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
	return 1;
}

/**
 * Returns string representation of the specified rdf
 * Data is not static
 */
char *
ldns_rdf2str(ldns_rdf *rdf)
{
	char *res = NULL;

	switch(ldns_rdf_get_type(rdf)) {
	case LDNS_RDF_TYPE_NONE:
		res = XMALLOC(char, 5);
		snprintf(res, 5, "NONE");
		break;
	case LDNS_RDF_TYPE_DNAME:
		res = ldns_dname2str(rdf);
		break;
	case LDNS_RDF_TYPE_INT8:
		res = XMALLOC(char, 5);
		snprintf(res, 5, "INT8");
		break;
	case LDNS_RDF_TYPE_INT16:
		res = XMALLOC(char, 6);
		snprintf(res, 6, "INT16");
		break;
	case LDNS_RDF_TYPE_INT32:
		res = XMALLOC(char, 6);
		snprintf(res, 6, "INT32");
		break;
	case LDNS_RDF_TYPE_INT48:
		res = XMALLOC(char, 6);
		snprintf(res, 6, "INT48");
		break;
	case LDNS_RDF_TYPE_A:
		res = ldns_conv_a(rdf);
		break;
	case LDNS_RDF_TYPE_AAAA:
		res = XMALLOC(char, 5);
		snprintf(res, 5, "NONE");
		break;
	case LDNS_RDF_TYPE_STR:
		res = XMALLOC(char, 5);
		snprintf(res, 5, "NONE");
		break;
	case LDNS_RDF_TYPE_APL:
		res = XMALLOC(char, 5);
		snprintf(res, 5, "NONE");
		break;
	case LDNS_RDF_TYPE_B64:
		res = XMALLOC(char, 5);
		snprintf(res, 5, "NONE");
		break;
	case LDNS_RDF_TYPE_HEX:
		res = XMALLOC(char, 5);
		snprintf(res, 5, "NONE");
		break;
	case LDNS_RDF_TYPE_NSEC: 
		res = XMALLOC(char, 5);
		snprintf(res, 5, "NONE");
		break;
	case LDNS_RDF_TYPE_TYPE: 
		res = XMALLOC(char, 5);
		snprintf(res, 5, "NONE");
		break;
	case LDNS_RDF_TYPE_CLASS:
		res = XMALLOC(char, 5);
		snprintf(res, 5, "NONE");
		break;
	case LDNS_RDF_TYPE_CERT:
		res = XMALLOC(char, 5);
		snprintf(res, 5, "NONE");
		break;
	case LDNS_RDF_TYPE_ALG:
		res = XMALLOC(char, 5);
		snprintf(res, 5, "NONE");
		break;
	case LDNS_RDF_TYPE_UNKNOWN:
		res = XMALLOC(char, 5);
		snprintf(res, 5, "NONE");
		break;
	case LDNS_RDF_TYPE_TIME:
		res = XMALLOC(char, 5);
		snprintf(res, 5, "NONE");
		break;
	case LDNS_RDF_TYPE_SERVICE:
		res = XMALLOC(char, 5);
		snprintf(res, 5, "NONE");
		break;
	case LDNS_RDF_TYPE_LOC:
		res = XMALLOC(char, 5);
		snprintf(res, 5, "NONE");
		break;
	}
	return res;
}

/** 
 * convert A address 
 */
char *
ldns_conv_a(ldns_rdf *rd)
{
	char *r;

	r = XMALLOC(char, INET_ADDRSTRLEN);

	if (!inet_ntop(AF_INET, ldns_rdf_data(rd), r, INET_ADDRSTRLEN)) {
		/* somehting is wrong */
		/* TODO NULL HERE??? */
		return NULL;
	}
	return r;
}
