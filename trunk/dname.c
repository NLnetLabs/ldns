/*
 * dname.c
 *
 * dname specific rdata implementations
 * A dname is a rdf structure with type LDNS_RDF_TYPE_DNAME
 *
 * a Net::DNS like library for C
 *
 * (c) NLnet Labs, 2004
 *
 * See the file LICENSE for the license
 */

#include <config.h>

#include <ldns/rdata.h>
#include <ldns/error.h>
#include <ldns/str2host.h>
#include <ldns/dns.h>

#include "util.h"
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>


/**
 * concatenate two dnames together
 * \param[in] rd1 the leftside
 * \param[in] rd2 the rightside
 * \return a new rdf with leftside/rightside
 */
ldns_rdf *
ldns_dname_concat(ldns_rdf *rd1, ldns_rdf *rd2)
{
	ldns_rdf *new;
	uint16_t new_size;
	uint8_t *buf;

	if (ldns_rdf_get_type(rd1) != LDNS_RDF_TYPE_DNAME ||
			ldns_rdf_get_type(rd2) != LDNS_RDF_TYPE_DNAME)
	{
		return NULL;
	}

	/* we overwrite the nullbyte of rd1 */
	new_size = ldns_rdf_size(rd1) + ldns_rdf_size(rd2) - 1;
	buf = XMALLOC(uint8_t, new_size);
	if (!buf) {
		return NULL;
	}

	/* put the two dname's after each other */
	memcpy(buf, ldns_rdf_data(rd1), ldns_rdf_size(rd1) - 1);
	memcpy(buf + ldns_rdf_size(rd1) - 1,
			ldns_rdf_data(rd2), ldns_rdf_size(rd2));
	
	new = ldns_rdf_new_frm_data(new_size, LDNS_RDF_TYPE_DNAME,
			buf);

	FREE(buf);
	return new;
}

/**
 * count the number of labels inside a LDNS_RDF_DNAME type
 * rdf
 * \param[in] *r the rdf
 * \return the number of labels
 */     
uint8_t         
ldns_rdf_dname_label_count(ldns_rdf *r)
{       
        uint8_t src_pos;
        uint8_t len;
        uint8_t i;
        size_t r_size;

        i = 0; src_pos = 0;
        r_size = ldns_rdf_size(r);

        if (ldns_rdf_get_type(r) != LDNS_RDF_TYPE_DNAME) {
                return 0;
        } else {
                len = ldns_rdf_data(r)[src_pos]; /* start of the label */

                /* single root label */
                if (1 == r_size) {
                        return 0; 
                } else {
                        while ((len > 0) && src_pos < r_size) {
                                src_pos++;
                                src_pos += len;
                                len = ldns_rdf_data(r)[src_pos];
                                i++;
                        }
                }
                return i;
        }
}

/**
 * Create a new dname rdf from a string
 * \param[in] str string to use
 * \param[in] t   type to use
 * \return ldns_rdf*
 */
ldns_rdf *
ldns_dname_new_frm_str(const char *str)
{
	return 
		ldns_rdf_new_frm_str(str, LDNS_RDF_TYPE_DNAME);
}
