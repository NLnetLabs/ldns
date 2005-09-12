/*
 * dname.h
 *
 * dname definitions
 *
 * a Net::DNS like library for C
 *
 * (c) NLnet Labs, 2004, 2005
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
ldns_rdf *ldns_dname_cat_clone(ldns_rdf *rd1, ldns_rdf *rd2);
/**
 * concatenates rd2 after rd1 (rd2 is copied, rd1 is modified)
 * \param[in] rd1 the leftside
 * \param[in] rd2 the rightside
 * \return LDNS_STATUS_OK on success
 */
ldns_status 	ldns_dname_cat(ldns_rdf *rd1, ldns_rdf *rd2);
/**
 * chop one label off a dname. so 
 * wwww.nlnetlabs.nl, becomes nlnetlabs.nl
 * \param[in] d the dname to chop
 * \return the remaining dname
 */
ldns_rdf *ldns_dname_left_chop(ldns_rdf *d);
/**
 * count the number of labels inside a LDNS_RDF_DNAME type rdf.
 * \param[in] *r the rdf
 * \return the number of labels
 */     
uint8_t  ldns_dname_label_count(const ldns_rdf *r);

/**
 * Create a new dname rdf. Copies pointers!
 * \param[in] str string to use
 * \return ldns_rdf*
 */
ldns_rdf *ldns_dname_new_frm_str(const char *str);

/**
 * Create a new dname rdf from a string
 * \param[in] s the size of the new dname 
 * \param[in] *data pointer to the actual data
 * \return ldns_rdf*
 */
ldns_rdf *ldns_dname_new(uint16_t s, void *data);

/**
 * Create a new dname rdf from data (the data is copied)
 * \param[in] size the size of the data
 * \param[in] *data pointer to the actual data
 * \return ldns_rdf*
 */
ldns_rdf *ldns_dname_new_frm_data(uint16_t size, const void *data);

/**
 * Put a dname into canonical fmt - ie. lowercase it
 * \param[in] rdf the dname to lowercase
 * \return void
 */
void ldns_dname2canonical(const ldns_rdf *rdf);

/**
 * test wether the name sub falls under parent (i.e. is a subdomain
 * of parent.
 * \param[in] sub the name to test
 * \param[in] parent the parent's name
 * \return true if sub falls under parent, otherwise false
 */
bool ldns_dname_is_subdomain(const ldns_rdf *sub, const ldns_rdf *parent);

/**
 * Checks whether the given dname string is absolute (i.e. ends with a '.')
 * \param[in] *dname_str a string representing the dname
 * \return true or false
 */
bool ldns_dname_str_absolute(const char *dname_str);

/**
 * look inside the rdf and if it is an LDNS_RDF_TYPE_DNAME
 * try and retrieve a specific label. The labels are numbered
 * starting from 0 (left most).
 * \param[in] rdf the rdf to look in
 * \param[in] labelpos return the label with this number
 * \return a ldns_rdf* with the label as name or NULL on error
 */
ldns_rdf * ldns_dname_label(const ldns_rdf *rdf, uint8_t labelpos);

#endif	/* !_LDNS_DNAME_H */
