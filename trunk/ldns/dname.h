/*
 * 
 * dname.h
 *
 * dname definitions
 *
 * a Net::DNS like library for C
 *
 * (c) NLnet Labs, 2004
 *
 * See the file LICENSE for the license
 */

#ifndef _LDNS_DNAME_H
#define _LDNS_DNAME_H

#include <ldns/common.h>


/* prototypes */
uint8_t         ldns_rdf_dname_label_count(ldns_rdf *);
ldns_rdf	*ldns_dname_new_frm_str(const char *);
ldns_rdf 	*ldns_dname_concat(ldns_rdf *, ldns_rdf *);

#endif	/* !_LDNS_DNAME_H */
