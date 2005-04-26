/*
 * dnssec.h -- defines for the Domain Name System (SEC) (DNSSEC)
 *
 * Copyright (c) 2001-2005, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 * A bunch of defines that are used in the DNS
 */

#ifndef _DNSSEC_H_
#define _DNSSEC_H_

#include <openssl/ssl.h>
#include <ldns/common.h>
#include <ldns/dns.h>
#include <ldns/buffer.h>
#include <ldns/packet.h>
#include <ldns/keys.h>

#define MAX_KEYLEN	2048
#define DNSSEC_KEYPROTO	3

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
 * Calculates a keytag of a key for use in DNSSEC
 * \param[in] key the key to use for the calc.
 * \return the keytag
 */
uint16_t ldns_calc_keytag(ldns_rr *key);

/**
 * verify an rrsig rrset
 */
bool ldns_verify(ldns_rr_list *, ldns_rr_list *, ldns_rr_list *);	

/**
 * Verifies an rrsig 
 * \param[in] rrset the rrset to check
 * \param[in] rrsig the signature of the rrset
 * \param[in] keys the keys to try
 */
bool ldns_verify_rrsig(ldns_rr_list *rrset, ldns_rr *rrsig, ldns_rr_list *keys);

bool ldns_verify_rrsig_dsa(ldns_buffer *, ldns_buffer *, ldns_buffer *);
bool ldns_verify_rrsig_rsasha1(ldns_buffer *, ldns_buffer *, ldns_buffer *);
bool ldns_verify_rrsig_rsamd5(ldns_buffer *, ldns_buffer *, ldns_buffer *);

/**
 * convert a buffer holding key material to a DSA key in openssl 
 * \param[in] key the key to convert
 * \return a DSA * structure with the key material
 */
DSA *ldns_key_buf2dsa(ldns_buffer *key);

/**
 * convert a buffer holding key material to a RSA key in openssl 
 * \param[in] key the key to convert
 * \return a RSA * structure with the key material
 */
RSA *ldns_key_buf2rsa(ldns_buffer *key);

/**
 * Verifies the tsig rr for the given packet and key (string?)
 * wire must be given too because tsig does not sign normalized packet
 * packet is still given (and used, but could be constructed from wire)
   remove that?
 * @return true if tsig is correct, false if not, or if tsig is not set
 */
bool ldns_pkt_tsig_verify(ldns_pkt *pkt, uint8_t *wire, size_t wire_size, const char *key_name, const char *key_data, ldns_rdf *mac);

/**
 * Creates a tsig rr for the given packet and key (string?)
 *
 * @param pkt the packet to sign
 * @param key_name the name of the shared key
 * @param key_data the key in base 64 format
 * @param fudge seconds of error permitted in time signed
 * @param algorithm_name the name of the algorithm used (TODO more than only hmac-md5.sig-alg.reg.int.?)
 * @param query_mac is added to the digest if not NULL (so NULL is for signing queries, not NULL is for signing answers)
 * @return status (OK if success)
 */
ldns_status ldns_pkt_tsig_sign(ldns_pkt *pkt, const char *key_name, const char *key_data, uint16_t fudge, const char *algorithm_name, ldns_rdf *query_mac);

/** 
 * Returns a new DS rr that represents the given key rr
 * \param[in] *key the key to convert
 * \return ldns_rr* a new rr pointer to a DS
 */
ldns_rr *ldns_key_rr2ds(const ldns_rr *key);

/* sign functions - these are very much a work in progress */
ldns_rr_list * ldns_sign_public(ldns_rr_list *rrset, ldns_key_list *keys);
ldns_rdf *ldns_sign_public_dsa(ldns_buffer *to_sign, DSA *key);
ldns_rdf *ldns_sign_public_rsamd5(ldns_buffer *to_sign, RSA *key);
ldns_rdf *ldns_sign_public_rsasha1(ldns_buffer *to_sign, RSA *key);
ldns_rdf *ldns_sign_public_dsa(ldns_buffer *to_sign, DSA *key);

#endif /* _DNSSEC_H_ */
