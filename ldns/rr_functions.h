/*
 * rr_functions.h
 *
 * the .h file with defs for the per rr
 * functions
 *
 * a Net::DNS like library for C
 * 
 * (c) NLnet Labs, 2005-2006
 * 
 * See the file LICENSE for the license
 */
#ifndef LDNS_RR_FUNCTIONS_H
#define LDNS_RR_FUNCTIONS_H


/* set rdf's at a specific offset
 * The RR need to be created with ldns_rr_new_frm_type which
 * allocated enough space for all rdf's and sets them to NULL
 */

/* A/AAAA */

/**
 * returns the address of a LDNS_RR_TYPE_A rr
 * \param[in] r the resource record
 * \return a ldns_rdf* with the address or NULL on failure
 */
ldns_rdf* ldns_rr_a_address(ldns_rr *r);

/**
 * sets the address of a LDNS_RR_TYPE_A rr
 * \param[in] r the rr to use
 * \param[in] f the address to set
 * \return true on success, false otherwise
 */
bool ldns_rr_a_set_address(ldns_rr *r, ldns_rdf *f);

/* NS */
/**
 * returns the name of a LDNS_RR_TYPE_NS rr
 * \param[in] r the resource record
 * \return a ldns_rdf* with the name or NULL on failure
 */
ldns_rdf* ldns_rr_ns_nsdname(ldns_rr *r);

/* MX */
/**
 * returns the mx pref. of a LDNS_RR_TYPE_MX rr
 * \param[in] r the resource record
 * \return a ldns_rdf* with the preference or NULL on failure
 */
ldns_rdf* ldns_rr_mx_preference(ldns_rr *r);
/**
 * returns the mx host of a LDNS_RR_TYPE_MX rr
 * \param[in] r the resource record
 * \return a ldns_rdf* with the name of the MX host or NULL on failure
 */
ldns_rdf* ldns_rr_mx_exchange(ldns_rr *r);

/* RRSIG */
/**
 * returns the type covered of a LDNS_RR_TYPE_RRSIG rr
 * \param[in] r the resource record
 * \return a ldns_rdf* with the type covered or NULL on failure
 */
ldns_rdf* ldns_rr_rrsig_typecovered(ldns_rr *r);
/**
 * sets the typecovered of a LDNS_RR_TYPE_RRSIG rr
 * \param[in] r the rr to use
 * \param[in] f the typecovered to set
 * \return true on success, false otherwise
 */
bool ldns_rr_rrsig_set_typecovered(ldns_rr *r, ldns_rdf *f);
/**
 * returns the algorithm of a LDNS_RR_TYPE_RRSIG RR
 * \param[in] r the resource record
 * \return a ldns_rdf* with the algorithm or NULL on failure
 */
ldns_rdf* ldns_rr_rrsig_algorithm(ldns_rr *r);
/**
 * sets the algorithm of a LDNS_RR_TYPE_RRSIG rr
 * \param[in] r the rr to use
 * \param[in] f the algorithm to set
 * \return true on success, false otherwise
 */
bool ldns_rr_rrsig_set_algorithm(ldns_rr *r, ldns_rdf *f);
/**
 * returns the number of labels of a LDNS_RR_TYPE_RRSIG RR
 * \param[in] r the resource record
 * \return a ldns_rdf* with the number of labels or NULL on failure
 */
ldns_rdf* ldns_rr_rrsig_labels(ldns_rr *r);
/**
 * sets the number of labels of a LDNS_RR_TYPE_RRSIG rr
 * \param[in] r the rr to use
 * \param[in] f the number of labels to set
 * \return true on success, false otherwise
 */
bool ldns_rr_rrsig_set_labels(ldns_rr *r, ldns_rdf *f);
/**
 * returns the original TTL of a LDNS_RR_TYPE_RRSIG RR
 * \param[in] r the resource record
 * \return a ldns_rdf* with the original TTL or NULL on failure
 */
ldns_rdf* ldns_rr_rrsig_origttl(ldns_rr *r);
/**
 * sets the original TTL of a LDNS_RR_TYPE_RRSIG rr
 * \param[in] r the rr to use
 * \param[in] f the original TTL to set
 * \return true on success, false otherwise
 */
bool ldns_rr_rrsig_set_origttl(ldns_rr *r, ldns_rdf *f);
/**
 * returns the expiration time of a LDNS_RR_TYPE_RRSIG RR
 * \param[in] r the resource record
 * \return a ldns_rdf* with the expiration time or NULL on failure
 */
ldns_rdf* ldns_rr_rrsig_expiration(ldns_rr *r);
/**
 * sets the expireation date of a LDNS_RR_TYPE_RRSIG rr
 * \param[in] r the rr to use
 * \param[in] f the expireation date to set
 * \return true on success, false otherwise
 */
bool ldns_rr_rrsig_set_expiration(ldns_rr *r, ldns_rdf *f);
/**
 * returns the inception time of a LDNS_RR_TYPE_RRSIG RR
 * \param[in] r the resource record
 * \return a ldns_rdf* with the inception time or NULL on failure
 */
ldns_rdf* ldns_rr_rrsig_inception(ldns_rr *r);
/**
 * sets the inception date of a LDNS_RR_TYPE_RRSIG rr
 * \param[in] r the rr to use
 * \param[in] f the inception date to set
 * \return true on success, false otherwise
 */
bool ldns_rr_rrsig_set_inception(ldns_rr *r, ldns_rdf *f);
/**
 * returns the keytag of a LDNS_RR_TYPE_RRSIG RR
 * \param[in] r the resource record
 * \return a ldns_rdf* with the keytag or NULL on failure
 */
ldns_rdf* ldns_rr_rrsig_keytag(ldns_rr *r);
/**
 * sets the keytag of a LDNS_RR_TYPE_RRSIG rr
 * \param[in] r the rr to use
 * \param[in] f the keytag to set
 * \return true on success, false otherwise
 */
bool ldns_rr_rrsig_set_keytag(ldns_rr *r, ldns_rdf *f);
/**
 * returns the signers name of a LDNS_RR_TYPE_RRSIG RR
 * \param[in] r the resource record
 * \return a ldns_rdf* with the signers name or NULL on failure
 */
ldns_rdf* ldns_rr_rrsig_signame(ldns_rr *r);
/**
 * sets the signers name of a LDNS_RR_TYPE_RRSIG rr
 * \param[in] r the rr to use
 * \param[in] f the signers name to set
 * \return true on success, false otherwise
 */
bool ldns_rr_rrsig_set_signame(ldns_rr *r, ldns_rdf *f);
/**
 * returns the signature data of a LDNS_RR_TYPE_RRSIG RR
 * \param[in] r the resource record
 * \return a ldns_rdf* with the signature data or NULL on failure
 */
ldns_rdf* ldns_rr_rrsig_sig(ldns_rr *r);
/**
 * sets the signature data of a LDNS_RR_TYPE_RRSIG rr
 * \param[in] r the rr to use
 * \param[in] f the signature data to set
 * \return true on success, false otherwise
 */
bool ldns_rr_rrsig_set_sig(ldns_rr *r, ldns_rdf *f);

/* DNSKEY */
/**
 * returns the flags of a LDNS_RR_TYPE_DNSKEY rr
 * \param[in] r the resource record
 * \return a ldns_rdf* with the flags or NULL on failure
 */
ldns_rdf* ldns_rr_dnskey_flags(ldns_rr *r);
/**
 * sets the flags of a LDNS_RR_TYPE_DNSKEY rr
 * \param[in] r the rr to use
 * \param[in] f the flags to set
 * \return true on success, false otherwise
 */
bool ldns_rr_dnskey_set_flags(ldns_rr *r, ldns_rdf *f);
/**
 * returns the protocol of a LDNS_RR_TYPE_DNSKEY rr
 * \param[in] r the resource record
 * \return a ldns_rdf* with the protocol or NULL on failure
 */
ldns_rdf* ldns_rr_dnskey_protocol(ldns_rr *r);
/**
 * sets the protocol of a LDNS_RR_TYPE_DNSKEY rr
 * \param[in] r the rr to use
 * \param[in] f the protocol to set
 * \return true on success, false otherwise
 */
bool ldns_rr_dnskey_set_protocol(ldns_rr *r, ldns_rdf *f);
/**
 * returns the algorithm of a LDNS_RR_TYPE_DNSKEY rr
 * \param[in] r the resource record
 * \return a ldns_rdf* with the algorithm or NULL on failure
 */
ldns_rdf* ldns_rr_dnskey_algorithm(ldns_rr *r);
/**
 * sets the algorithm of a LDNS_RR_TYPE_DNSKEY rr
 * \param[in] r the rr to use
 * \param[in] f the algorithm to set
 * \return true on success, false otherwise
 */
bool ldns_rr_dnskey_set_algorithm(ldns_rr *r, ldns_rdf *f);
/**
 * returns the key data of a LDNS_RR_TYPE_DNSKEY rr
 * \param[in] r the resource record
 * \return a ldns_rdf* with the key data or NULL on failure
 */
ldns_rdf* ldns_rr_dnskey_key(ldns_rr *r);
/**
 * sets the key data of a LDNS_RR_TYPE_DNSKEY rr
 * \param[in] r the rr to use
 * \param[in] f the key data to set
 * \return true on success, false otherwise
 */
bool ldns_rr_dnskey_set_key(ldns_rr *r, ldns_rdf *f);

/**
 * get the length of the keydata in bits
 * \param[in] key the key rr to use
 * \return the keysize in bits
 */
uint16_t ldns_rr_dnskey_key_size(ldns_rr *key);

#endif /* LDNS_RR_FUNCTIONS_H */
