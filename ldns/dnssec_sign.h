/** dnssec_verify */

#ifndef LDNS_DNSSEC_SIGN_H
#define LDNS_DNSSEC_SIGN_H

#include <ldns/dnssec.h>

/* sign functions */

/**
 * Sign an rrset
 * \param[in] rrset the rrset
 * \param[in] keys the keys to use
 * \return a rr_list with the signatures
 */
ldns_rr_list *ldns_sign_public(ldns_rr_list *rrset, ldns_key_list *keys);

#ifdef HAVE_SSL
/**
 * Sign a buffer with the DSA key (hash with SHA1)
 * \param[in] to_sign buffer with the data
 * \param[in] key the key to use
 * \return a ldns_rdf with the signed data
 */
ldns_rdf *ldns_sign_public_dsa(ldns_buffer *to_sign, DSA *key);

/**
 * Sign buffer with EVP envelope
 */
ldns_rdf *ldns_sign_public_evp(ldns_buffer *to_sign,
						 EVP_PKEY *key,
						 const EVP_MD *digest_type);

/**
 * Sign a buffer with the RSA key (hash with SHA1)
 * \param[in] to_sign buffer with the data
 * \param[in] key the key to use
 * \return a ldns_rdf with the signed data
 */
ldns_rdf *ldns_sign_public_rsasha1(ldns_buffer *to_sign, RSA *key);

/**
 * Sign a buffer with the RSA key (hash with MD5)
 * \param[in] to_sign buffer with the data
 * \param[in] key the key to use
 * \return a ldns_rdf with the signed data
 */
ldns_rdf *ldns_sign_public_rsamd5(ldns_buffer *to_sign, RSA *key);
#endif /* HAVE_SSL */

/**
 * Adds NSEC RRs to the zone
 */
ldns_status
ldns_dnssec_zone_create_nsecs(ldns_dnssec_zone *zone,
						ldns_rr_list *new_rrs,
						ldns_rr_type nsec_type);

/**
 * remove signatures if callback function tells to
 */
ldns_dnssec_rrs *
ldns_dnssec_remove_signatures(ldns_dnssec_rrs *signatures,
						ldns_key_list *key_list,
						int (*func)(ldns_rr *, void *),
						void *arg);

/**
 * Adds signatures to the zone
 */
ldns_status
ldns_dnssec_zone_create_rrsigs(ldns_dnssec_zone *zone,
						 ldns_rr_list *new_rrs,
						 ldns_key_list *key_list,
						 int (*func)(ldns_rr *, void*),
						 void *arg);

/**
 * signs the given zone with the given new zone
 * 
 * \param[in] zone the zone to sign
 * \param[in] key_list the list of keys to sign the zone with
 * \param[in] new_rrs newly created resource records are added to this list, to free them later
 * \param[in] func callback function that decides what to do with old signatures
 * \param[in] arg optional argument for the callback function
 * \return LDNS_STATUS_OK on success, an error code otherwise
 */
ldns_status ldns_dnssec_zone_sign(ldns_dnssec_zone *zone,
						    ldns_rr_list *new_rrs,
						    ldns_key_list *key_list,
						    int (*func)(ldns_rr *, void *),
						    void *arg);

/**
 * signs the given zone with the given new zone, with NSEC3
 *
 * \param[in] zone the zone to sign
 * \param[in] key_list the list of keys to sign the zone with
 * \param[in] new_rrs newly created resource records are added to this list, to free them later
 * \param[in] func callback function that decides what to do with old signatures
 * \param[in] arg optional argument for the callback function
 * \param[in] algorithm the NSEC3 hashing algorithm to use
 * \param[in] flags NSEC3 flags
 * \param[in] iterations the number of NSEC3 hash iterations to use
 * \param[in] salt_length the length (in octets) of the NSEC3 salt
 * \param[in] salt the NSEC3 salt data
 * \return LDNS_STATUS_OK on success, an error code otherwise
 */
ldns_status ldns_dnssec_zone_sign_nsec3(ldns_dnssec_zone *zone,
								ldns_rr_list *new_rrs,
								ldns_key_list *key_list,
								int (*func)(ldns_rr *, void *),
								void *arg,
								uint8_t algorithm,
								uint8_t flags,
								uint16_t iterations,
								uint8_t salt_length,
								uint8_t *salt);

/**
 * Signs the zone, and returns a newly allocated signed zone
 * \param[in] zone the zone to sign
 * \param[in] key_list list of keys to sign with
 * \return signed zone
 */
ldns_zone *ldns_zone_sign(const ldns_zone *zone, ldns_key_list *key_list);

/**
 * Signs the zone with NSEC3, and returns a newly allocated signed zone
 * \param[in] zone the zone to sign
 * \param[in] key_list list of keys to sign with
 * \param[in] algorithm the NSEC3 hashing algorithm to use
 * \param[in] flags NSEC3 flags
 * \param[in] iterations the number of NSEC3 hash iterations to use
 * \param[in] salt_length the length (in octets) of the NSEC3 salt
 * \param[in] salt the NSEC3 salt data
 * \return signed zone
 */
ldns_zone *ldns_zone_sign_nsec3(ldns_zone *zone, ldns_key_list *key_list, uint8_t algorithm, uint8_t flags, uint16_t iterations, uint8_t salt_length, uint8_t *salt);
 


#endif
