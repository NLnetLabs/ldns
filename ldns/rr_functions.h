/*
 * rr_functions.h
 *
 * the .h file with defs for the per rr
 * functions
 *
 * a Net::DNS like library for C
 * 
 * (c) NLnet Labs, 2004
 * 
 * See the file LICENSE for the license
 */
#ifndef _RR_FUNCTIONS_H
#define _RR_FUNCTIONS_H

ldns_rdf * ldns_rr_address(ldns_rr *r);
bool ldns_rr_set_address(ldns_rr *r, ldns_rdf *f);

ldns_rdf * ldns_rr_nsdname(ldns_rr *r);

ldns_rdf * ldns_rr_preference(ldns_rr *r);
ldns_rdf * ldns_rr_exchange(ldns_rr *r);

ldns_rdf * ldns_rr_typecovered(ldns_rr *r);
bool ldns_rr_set_typecovered(ldns_rr *r, ldns_rdf *f);
ldns_rdf * ldns_rr_algorithm(ldns_rr *r);
bool ldns_rr_set_algorithm(ldns_rr *r, ldns_rdf *f);
ldns_rdf * ldns_rr_labels(ldns_rr *r);
bool ldns_rr_set_labels(ldns_rr *r, ldns_rdf *f);
ldns_rdf * ldns_rr_origttl(ldns_rr *r);
bool ldns_rr_set_origttl(ldns_rr *r, ldns_rdf *f);
ldns_rdf * ldns_rr_expiration(ldns_rr *r);
bool ldns_rr_set_expiration(ldns_rr *r, ldns_rdf *f);
ldns_rdf * ldns_rr_inception(ldns_rr *r);
bool ldns_rr_set_inception(ldns_rr *r, ldns_rdf *f);
ldns_rdf * ldns_rr_keytag(ldns_rr *r);
bool ldns_rr_set_keytag(ldns_rr *r, ldns_rdf *f);
ldns_rdf * ldns_rr_signame(ldns_rr *r);
bool ldns_rr_set_signame(ldns_rr *r, ldns_rdf *f);
ldns_rdf * ldns_rr_sig(ldns_rr *r);
bool ldns_rr_set_sig(ldns_rr *r, ldns_rdf *f);


#endif /* _RR_FUNCTIONS_H */
