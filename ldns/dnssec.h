/*
 * dnssec.h -- defines for the Domain Name System (SEC) (DNSSEC)
 *
 * Copyright (c) 2001-2005, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 * A bunch of defines that are used in the DNS
 */

#ifndef _LDNS_DNSSEC_H_
#define _LDNS_DNSSEC_H_

#include <openssl/ssl.h>
#include <ldns/common.h>
#include <ldns/dns.h>
#include <ldns/buffer.h>
#include <ldns/packet.h>
#include <ldns/zone.h>
#include <ldns/keys.h>

#define LDNS_MAX_KEYLEN		2048
#define LDNS_DNSSEC_KEYPROTO	3
/* default time before sigs expire */
#define LDNS_DEFAULT_EXP_TIME	1209600

#if 0
/**
 * algorigthms used in dns
 */
enum ldns_enum_algorithm
{
	LDNS_RSAMD5		= 1,
	LDNS_DH			= 2,
	LDNS_DSA		= 3,
	LDNS_ECC		= 4,
	LDNS_RSASHA1		= 5,
	LDNS_INDIRECT		= 252,
	LDNS_PRIVATEDNS		= 253,
	LDNS_PRIVATEOID		= 254
};
typedef enum ldns_enum_algorithm ldns_algorithm;
#endif

/** 
 * calculates a keytag of a key for use in DNSSEC.
 *
 * \param[in] key the key to use for the calc.
 * \return the keytag
 */
uint16_t ldns_calc_keytag(ldns_rr *key);

/**
 * verifies an rrsig rrset.
 *
 * \param[in] rrset the rrset to verify
 * \param[in] rrsig a list of signatures to check
 * \param[in] keys a list of keys to check with
 * \param[out] good_keys, if this is a (initialized) list, the keys from keys that validate one of the signatures are added to it
 * \return status LDNS_STATUS_OK if there is at least one correct key
 */
ldns_status ldns_verify(ldns_rr_list *rrset, ldns_rr_list *rrsig, ldns_rr_list *keys, ldns_rr_list *good_keys);	

/**
 * Verifies an rrsig. All keys in the keyset are tried.
 *
 * \param[in] rrset the rrset to check
 * \param[in] rrsig the signature of the rrset
 * \param[in] keys the keys to try
 * \return a list of keys which validate the rrsig + rrset. Return NULL
 * when none of the keys validate.
 */
ldns_status ldns_verify_rrsig_keylist(ldns_rr_list *rrset, ldns_rr *rrsig, ldns_rr_list *keys, ldns_rr_list *good_keys);
ldns_status ldns_verify_rrsig(ldns_rr_list *rrset, ldns_rr *rrsig, ldns_rr *key);

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

/**
 * converts a buffer holding key material to a DSA key in openssl.
 *
 * \param[in] key the key to convert
 * \return a DSA * structure with the key material
 */
DSA *ldns_key_buf2dsa(ldns_buffer *key);

/**
 * converts a buffer holding key material to a RSA key in openssl.
 *
 * \param[in] key the key to convert
 * \return a RSA * structure with the key material
 */
RSA *ldns_key_buf2rsa(ldns_buffer *key);

/* TODO
 * Packet is still given (and used, but could be constructed from wire)
 * remove that?
 */
/**
 * verifies the tsig rr for the given packet and key (string?).
 * The wire must be given too because tsig does not sign normalized packets.
 *
 * \return true if tsig is correct, false if not, or if tsig is not set
 */
bool ldns_pkt_tsig_verify(ldns_pkt *pkt, uint8_t *wire, size_t wire_size, const char *key_name, const char *key_data, ldns_rdf *mac);

/**
 * creates a tsig rr for the given packet and key (string?).
 * \param[in] pkt the packet to sign
 * \param[in] key_name the name of the shared key
 * \param[in] key_data the key in base 64 format
 * \param[in] fudge seconds of error permitted in time signed
 * \param[in] algorithm_name the name of the algorithm used (TODO more than only hmac-md5.sig-alg.reg.int.?)
 * \param[in] query_mac is added to the digest if not NULL (so NULL is for signing queries, not NULL is for signing answers)
 * \return status (OK if success)
 */
ldns_status ldns_pkt_tsig_sign(ldns_pkt *pkt, const char *key_name, const char *key_data, uint16_t fudge, const char *algorithm_name, ldns_rdf *query_mac);

/** 
 * returns a new DS rr that represents the given key rr.
 *
 * \param[in] *key the key to convert
 * \return ldns_rr* a new rr pointer to a DS
 */
ldns_rr *ldns_key_rr2ds(const ldns_rr *key);

/* sign functions - these are very much a work in progress */
ldns_rr_list *ldns_sign_public(ldns_rr_list *rrset, ldns_key_list *keys);
ldns_rdf *ldns_sign_public_dsa(ldns_buffer *to_sign, DSA *key);
ldns_rdf *ldns_sign_public_rsamd5(ldns_buffer *to_sign, RSA *key);
ldns_rdf *ldns_sign_public_rsasha1(ldns_buffer *to_sign, RSA *key);
ldns_rdf *ldns_sign_public_dsa(ldns_buffer *to_sign, DSA *key);

/**
 * Create a NSEC record
 * \param[in] cur_owner the current owner which should be taken as the starting point
 * \param[in] next_owner the rrlist which the nsec rr should point to 
 * \param[in] rrs all rrs from the zone, to find all RR types of cur_owner in
 * \return a ldns_rr with the nsec record in it
 */
ldns_rr * ldns_create_nsec(ldns_rdf *cur_owner, ldns_rdf *next_owner, ldns_rr_list *rrs);

/**
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
ldns_zone *ldns_zone_sign(ldns_zone *zone, ldns_key_list *key_list, ldns_key_list *key_signing_key_list);
 

#endif /* _LDNS_DNSSEC_H_ */
