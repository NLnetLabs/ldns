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


/* set rdf's at a specific offset
 * The RR need to be created with ldns_rr_new_frm_type which
 * allocated enough space for all rdf's and sets them to NULL
 */

/* A/AAAA */
ldns_rdf * ldns_rr_address(ldns_rr *r);
bool ldns_rr_set_address(ldns_rr *r, ldns_rdf *f);

/* NS */
ldns_rdf * ldns_rr_ns_nsdname(ldns_rr *r);

/* MX */
ldns_rdf * ldns_rr_mx_preference(ldns_rr *r);
ldns_rdf * ldns_rr_mx_exchange(ldns_rr *r);

/* RRSIG */
ldns_rdf * ldns_rr_rrsig_typecovered(ldns_rr *r);
bool ldns_rr_rrsig_set_typecovered(ldns_rr *r, ldns_rdf *f);
ldns_rdf * ldns_rr_rrsig_algorithm(ldns_rr *r);
bool ldns_rr_rrsig_set_algorithm(ldns_rr *r, ldns_rdf *f);
ldns_rdf * ldns_rr_rrsig_labels(ldns_rr *r);
bool ldns_rr_rrsig_set_labels(ldns_rr *r, ldns_rdf *f);
ldns_rdf * ldns_rr_rrsig_origttl(ldns_rr *r);
bool ldns_rr_rrsig_set_origttl(ldns_rr *r, ldns_rdf *f);
ldns_rdf * ldns_rr_rrsig_expiration(ldns_rr *r);
bool ldns_rr_rrsig_set_expiration(ldns_rr *r, ldns_rdf *f);
ldns_rdf * ldns_rr_rrsig_inception(ldns_rr *r);
bool ldns_rr_rrsig_set_inception(ldns_rr *r, ldns_rdf *f);
ldns_rdf * ldns_rr_rrsig_keytag(ldns_rr *r);
bool ldns_rr_rrsig_set_keytag(ldns_rr *r, ldns_rdf *f);
ldns_rdf * ldns_rr_rrsig_signame(ldns_rr *r);
bool ldns_rr_rrsig_set_signame(ldns_rr *r, ldns_rdf *f);
ldns_rdf * ldns_rr_rrsig_sig(ldns_rr *r);
bool ldns_rr_rrsig_set_sig(ldns_rr *r, ldns_rdf *f);

/* DNSKEY */
ldns_rdf * ldns_rr_dnskey_flags(ldns_rr *r);
bool ldns_rr_dnskey_set_flags(ldns_rr *r, ldns_rdf *f);
ldns_rdf * ldns_rr_dnskey_protocol(ldns_rr *r);
bool ldns_rr_dnskey_set_protocol(ldns_rr *r, ldns_rdf *f);
ldns_rdf * ldns_rr_dnskey_algorithm(ldns_rr *r);
bool ldns_rr_dnskey_set_algorithm(ldns_rr *r, ldns_rdf *f);
ldns_rdf * ldns_rr_dnskey_key(ldns_rr *r);
bool ldns_rr_dnskey_set_key(ldns_rr *r, ldns_rdf *f);


#endif /* _RR_FUNCTIONS_H */
