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
#include <ldns/rdata.h>

#define LDNS_DNAME_NORMALIZE        tolower

/**
 * concatenate two dnames together
 * \param[in] rd1 the leftside
 * \param[in] rd2 the rightside
 * \return a new rdf with leftside/rightside
 */
ldns_rdf 	*ldns_dname_cat(ldns_rdf *rd1, ldns_rdf *rd2);
/**
 * chop one label off a dname. so 
 * wwww.nlnetlabs.nl, becomes nlnetlabs.nl
 * \param[in] d the dname to chop
 * \return the remaining dname
 */
ldns_rdf	*ldns_dname_left_chop(ldns_rdf *d);
/**
 * count the number of labels inside a LDNS_RDF_DNAME type rdf.
 * \param[in] *r the rdf
 * \return the number of labels
 */     
uint8_t         ldns_dname_label_count(ldns_rdf *r);

/**
 * Create a new dname rdf from a string
 * \param[in] str string to use
 * \return ldns_rdf*
 */
ldns_rdf	*ldns_dname_new_frm_str(const char *str);

/**
 * Create a new dname rdf from data (the data is copied)
 * \param[in] size the size of the data
 * \param[in] *data pointer to the actual data
 * \return ldns_rdf*
 */
ldns_rdf	*ldns_dname_new_frm_data(uint16_t size, const void *data);
/**
 * Put a dname into canonical fmt - ie. lowercase it
 * \param[in] rdf the dname to lowercase
 * \return void
 */
void		ldns_dname2canonical(const ldns_rdf *rdf);

#endif	/* !_LDNS_DNAME_H */
