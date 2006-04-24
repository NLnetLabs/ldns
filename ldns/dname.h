/*
 * dname.h
 *
 * dname definitions
 *
 * a Net::DNS like library for C
 *
 * (c) NLnet Labs, 2004-2006
 *
 * See the file LICENSE for the license
 */

#ifndef LDNS_DNAME_H
#define LDNS_DNAME_H

#include <ldns/common.h>
#include <ldns/rdata.h>

#define LDNS_DNAME_NORMALIZE        tolower

/**
 * concatenate two dnames together
 * \param[in] rd1 the leftside
 * \param[in] rd2 the rightside
 * \return a new rdf with leftside/rightside
 */
ldns_rdf *ldns_dname_cat_clone(const ldns_rdf *rd1, const ldns_rdf *rd2);

/**
 * concatenates rd2 after rd1 (rd2 is copied, rd1 is modified)
 * \param[in] rd1 the leftside
 * \param[in] rd2 the rightside
 * \return LDNS_STATUS_OK on success
 */
ldns_status 	ldns_dname_cat(ldns_rdf *rd1, ldns_rdf *rd2);

/**
 * Returns a clone of the given dname with the labels
 * reversed
 * \param[in] d the dname to reverse
 * \return clone of the dname with the labels reversed.
 */
ldns_rdf *ldns_dname_reverse(const ldns_rdf *d);

/**
 * chop one label off the left side of a dname. so 
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
 * creates a new dname rdf from a string.
 * \param[in] str string to use
 * \return ldns_rdf* or NULL in case of an error
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
 * Compares the two dname rdf's according to the algorithm for ordering
 * in RFC4034 Section 6.
 * \param[in] dname1 First dname rdf to compare
 * \param[in] dname2 Second dname rdf to compare
 * \return -1 if dname1 comes before dname2, 1 if dname1 comes after dname2, and 0 if they are equal.
 */
int ldns_dname_compare(const ldns_rdf *dname1, const ldns_rdf *dname2);

/**
 * check if middle lays in the interval defined by prev and next
 * prev <= middle < next. This is usefull for nsec checking
 * \param[in] prev the previous dname
 * \param[in] middle the dname to check
 * \param[in] next the next dname
 * return 0 on error or unknown, -1 when middle is in the interval, +1 when not
 */
int ldns_dname_interval(const ldns_rdf *prev, const ldns_rdf *middle, const ldns_rdf *next);

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

#endif	/* LDNS_DNAME_H */
