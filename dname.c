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

#include <ldns/config.h>

#include <ldns/dns.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>


ldns_rdf *
ldns_dname_cat_clone(ldns_rdf *rd1, ldns_rdf *rd2)
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
	buf = LDNS_XMALLOC(uint8_t, new_size);
	if (!buf) {
		return NULL;
	}

	/* put the two dname's after each other */
	memcpy(buf, ldns_rdf_data(rd1), ldns_rdf_size(rd1) - 1);
	memcpy(buf + ldns_rdf_size(rd1) - 1,
			ldns_rdf_data(rd2), ldns_rdf_size(rd2));
	
	new = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_DNAME, new_size, buf);

	LDNS_FREE(buf);
	return new;
}

/* pointer copy only */
/* this is a bitch - do we free rd1 and then copy new to rd1
 * or do we modify rd1 inplace?
 * I guess the latter is better... MG... ?
 */
ldns_rdf *
ldns_dname_cat(ldns_rdf *rd1, ldns_rdf *rd2)
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
	buf = LDNS_XMALLOC(uint8_t, new_size);
	if (!buf) {
		return NULL;
	}

	/* put the two dname's after each other */
	memcpy(buf, ldns_rdf_data(rd1), ldns_rdf_size(rd1) - 1);
	memcpy(buf + ldns_rdf_size(rd1) - 1,
			ldns_rdf_data(rd2), ldns_rdf_size(rd2));
	
	new = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_DNAME, new_size, buf);

	LDNS_FREE(buf);
	return new;
}

ldns_rdf *
ldns_dname_left_chop(ldns_rdf *d)
{
	uint8_t label_pos;
	ldns_rdf *chop;

	if (ldns_rdf_get_type(d) != LDNS_RDF_TYPE_DNAME) {
		return NULL;
	}
	if (ldns_dname_label_count(d) == 0) {
		/* root label */
		return NULL;
	}
	/* 05blaat02nl00 */
	label_pos = ldns_rdf_data(d)[0];

	chop = ldns_dname_new_frm_data(
			ldns_rdf_size(d) - label_pos,
			ldns_rdf_data(d) + label_pos + 1);
	return chop;
}

uint8_t         
ldns_dname_label_count(ldns_rdf *r)
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

ldns_rdf *
ldns_dname_new_frm_str(const char *str)
{
	return ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, str);
}

ldns_rdf *
ldns_dname_new_frm_data(uint16_t size, const void *data)
{
	return ldns_rdf_new_frm_data(LDNS_RDF_TYPE_DNAME, size, data);
}

void
ldns_dname2canonical(const ldns_rdf *rd)
{
	uint8_t *rdd;
	uint16_t i;

	if (ldns_rdf_get_type(rd) != LDNS_RDF_TYPE_DNAME) {
		return;
	}

	rdd = (uint8_t*)ldns_rdf_data(rd);
	for (i = 0; i < ldns_rdf_size(rd); i++, rdd++) {
		*rdd = (uint8_t)LDNS_DNAME_NORMALIZE((int)*rdd);
	}
}
