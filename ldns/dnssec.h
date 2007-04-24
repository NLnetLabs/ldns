/*
 * dnssec.h -- defines for the Domain Name System (SEC) (DNSSEC)
 *
 * Copyright (c) 2005-2006, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 * A bunch of defines that are used in the DNS
 */

/**
 * \file dnssec.h
 *
 * This module contains functions for DNSSEC operations (RFC4033 t/m RFC4035).
 * 
 * Since those functions heavily rely op cryptographic operations, this module is
 * dependent on openssl.
 * 
 */
 

#ifndef LDNS_DNSSEC_H
#define LDNS_DNSSEC_H

#ifdef HAVE_SSL
#include <openssl/ssl.h>
#include <openssl/evp.h>
#endif /* HAVE_SSL */
#include <ldns/common.h>
#include <ldns/packet.h>
#include <ldns/keys.h>
#include <ldns/zone.h>

#define LDNS_MAX_KEYLEN		2048
#define LDNS_DNSSEC_KEYPROTO	3
/* default time before sigs expire */
#define LDNS_DEFAULT_EXP_TIME	2419200 /* 4 weeks */

/** 
 * calculates a keytag of a key for use in DNSSEC.
 *
 * \param[in] key the key as an RR to use for the calc.
 * \return the keytag
 */
uint16_t ldns_calc_keytag(const ldns_rr *key);

/**
 * Verifies a list of signatures for one rrset.
 *
 * \param[in] rrset the rrset to verify
 * \param[in] rrsig a list of signatures to check
 * \param[in] keys a list of keys to check with
 * \param[out] good_keys  if this is a (initialized) list, the keys from keys that validate one of the signatures are added to it
 * \return status LDNS_STATUS_OK if there is at least one correct key
 */
ldns_status ldns_verify(ldns_rr_list *rrset, ldns_rr_list *rrsig, ldns_rr_list *keys, ldns_rr_list *good_keys);	

/**
 * Verifies the already processed data in the buffers
 * This function should probably not be used directly.
 *
 * \param[in] rawsig_buf Buffer containing signature data to use
 * \param[in] verify_buf Buffer containing data to verify
 * \param[in] key_buf Buffer containing key data to use
 * \param[in] algo Signing algorithm
 * \return status LDNS_STATUS_OK if the data verifies. Error if not.
 */
ldns_status ldns_verify_rrsig_buffers(ldns_buffer *rawsig_buf, ldns_buffer *verify_buf, ldns_buffer *key_buf, uint8_t algo);

/**
 * Verifies an rrsig. All keys in the keyset are tried.
 * \param[in] rrset the rrset to check
 * \param[in] rrsig the signature of the rrset
 * \param[in] keys the keys to try
 * \param[out] good_keys  if this is a (initialized) list, the keys from keys that validate one of the signatures are added to it
 * \return a list of keys which validate the rrsig + rrset. Return NULL when none of the keys validate.
 */
ldns_status ldns_verify_rrsig_keylist(ldns_rr_list *rrset, ldns_rr *rrsig, ldns_rr_list *keys, ldns_rr_list *good_keys);

/**
 * verify an rrsig with 1 key
 * \param[in] rrset the rrset
 * \param[in] rrsig the rrsig to verify
 * \param[in] key the key to use
 * \return status message wether verification succeeded.
 */
ldns_status ldns_verify_rrsig(ldns_rr_list *rrset, ldns_rr *rrsig, ldns_rr *key);

/**
 * verifies a buffer with signature data for a buffer with rrset data 
 * with an EVP_PKEY
 *
 * \param[in] sig the signature data
 * \param[in] rrset the rrset data, sorted and processed for verification
 * \param[in] key the EVP key structure
 * \param[in] digest_type The digest type of the signature
 */
#ifdef HAVE_SSL
ldns_status ldns_verify_rrsig_evp(ldns_buffer *sig, ldns_buffer *rrset, EVP_PKEY *key, const EVP_MD *digest_type);
#endif

/**
 * verifies a buffer with signature data (DSA) for a buffer with rrset data 
 * with a buffer with key data.
 *
 * \param[in] sig the signature data
 * \param[in] rrset the rrset data, sorted and processed for verification
 * \param[in] key the key data
 */
ldns_status ldns_verify_rrsig_dsa(ldns_buffer *sig, ldns_buffer *rrset, ldns_buffer *key);
/**
 * verifies a buffer with signature data (RSASHA1) for a buffer with rrset data 
 * with a buffer with key data.
 *
 * \param[in] sig the signature data
 * \param[in] rrset the rrset data, sorted and processed for verification
 * \param[in] key the key data
 */
ldns_status ldns_verify_rrsig_rsasha1(ldns_buffer *sig, ldns_buffer *rrset, ldns_buffer *key);
/**
 * verifies a buffer with signature data (RSAMD5) for a buffer with rrset data 
 * with a buffer with key data.
 *
 * \param[in] sig the signature data
 * \param[in] rrset the rrset data, sorted and processed for verification
 * \param[in] key the key data
 */
ldns_status ldns_verify_rrsig_rsamd5(ldns_buffer *sig, ldns_buffer *rrset, ldns_buffer *key);

#ifdef HAVE_SSL
/**
 * converts a buffer holding key material to a DSA key in openssl.
 *
 * \param[in] key the key to convert
 * \return a DSA * structure with the key material
 */
DSA *ldns_key_buf2dsa(ldns_buffer *key);
#endif /* HAVE_SSL */

#ifdef HAVE_SSL
/**
 * converts a buffer holding key material to a RSA key in openssl.
 *
 * \param[in] key the key to convert
 * \return a RSA * structure with the key material
 */
RSA *ldns_key_buf2rsa(ldns_buffer *key);
#endif /* HAVE_SSL */

/** 
 * returns a new DS rr that represents the given key rr.
 *
 * \param[in] *key the key to convert
 * \param[in] h the hash to use LDNS_SHA1/LDNS_SHA256
 * \return ldns_rr* a new rr pointer to a DS
 */
ldns_rr *ldns_key_rr2ds(const ldns_rr *key, ldns_hash h);

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
ldns_rdf *ldns_sign_public_evp(ldns_buffer *to_sign, EVP_PKEY *key, const EVP_MD *digest_type);
/**
 * Sign a buffer with the RSA key (hash with MD5)
 * \param[in] to_sign buffer with the data
 * \param[in] key the key to use
 * \return a ldns_rdf with the signed data
 */
ldns_rdf *ldns_sign_public_rsamd5(ldns_buffer *to_sign, RSA *key);
/**
 * Sign a buffer with the RSA key (hash with SHA1)
 * \param[in] to_sign buffer with the data
 * \param[in] key the key to use
 * \return a ldns_rdf with the signed data
 */
ldns_rdf *ldns_sign_public_rsasha1(ldns_buffer *to_sign, RSA *key);
#endif /* HAVE_SSL */

/**
 * Create a NSEC record
 * \param[in] cur_owner the current owner which should be taken as the starting point
 * \param[in] next_owner the rrlist which the nsec rr should point to 
 * \param[in] rrs all rrs from the zone, to find all RR types of cur_owner in
 * \return a ldns_rr with the nsec record in it
 */
ldns_rr * ldns_create_nsec(ldns_rdf *cur_owner, ldns_rdf *next_owner, ldns_rr_list *rrs);

/**
 * Checks coverage of NSEC RR type bitmap
 * \param[in] nsec_bitmap The NSEC bitmap rdata field to check
 * \param[in] type The type to check
 * \return true if the NSEC RR covers the type
 */
bool ldns_nsec_bitmap_covers_type(const ldns_rdf *nsec_bitmap, ldns_rr_type type);

/**
 * Checks coverage of NSEC RR name span
 * Remember that nsec and name must both be in canonical form (ie use
 * \ref ldns_rr2canonical and \ref ldns_dname2canonical prior to calling this
 * function)
 *
 * \param[in] nsec The NSEC RR to check
 * \param[in] name The owner dname to check
 * \return true if the NSEC RR covers the owner name
 */
bool ldns_nsec_covers_name(const ldns_rr *nsec, const ldns_rdf *name);

/**
 * verify a packet 
 * \param[in] p the packet
 * \param[in] t the rr set type to check
 * \param[in] o the rr set name to ckeck
 * \param[in] k list of keys
 * \param[in] s list of sigs (may be null)
 * \param[out] good_keys keys which validated the packet
 * \return status 
 * 
 */
ldns_status ldns_pkt_verify(ldns_pkt *p, ldns_rr_type t, ldns_rdf *o, ldns_rr_list *k, ldns_rr_list *s, ldns_rr_list *good_keys);

/**
 * signs the given zone with the given new zone
 * returns a newly allocated signed zone
 * extra arguments will come later (expiration etc.)
 *
 * \param[in] zone the zone to sign
 * \param[in] key_list the list of keys to sign the zone with
 * \return the signed zone
 */
ldns_zone *ldns_zone_sign(const ldns_zone *zone, ldns_key_list *key_list);
 
/**
 * Initialize the random function. This calls OpenSSL
 * \param[in] fd a file providing entropy data
 * \param[in] bytes number of bytes for the seed
 * \return LDNS_STATUS_OK if init succeeds
 */
ldns_status ldns_init_random(FILE *fd, uint16_t bytes);

#endif /* LDNS_DNSSEC_H */
