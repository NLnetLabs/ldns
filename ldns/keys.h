/*
 * 
 * keys.h
 *
 * priv key definitions
 *
 * a Net::DNS like library for C
 *
 * (c) NLnet Labs, 2004
 *
 * See the file LICENSE for the license
 */

#ifndef _LDNS_KEYS_H
#define _LDNS_KEYS_H

#include <openssl/ssl.h>

#include <util.h>

extern ldns_lookup_table ldns_signing_algorithms[];

enum ldns_enum_signing_algorithm
{
	LDNS_SIGN_ALG_RSAMD5	 = 1,
	LDNS_SIGN_ALG_RSASHA1	 = 2,
	LDNS_SIGN_ALG_DSAMD5	 = 3,
	LDNS_SIGN_ALG_DSASHA1	 = 4,
	LDNS_SIGN_ALG_HMACMD5	 = 5
};
typedef enum ldns_enum_signing_algorithm ldns_signing_algorithm;


struct ldns_struct_key {
	ldns_signing_algorithm alg;
	/* types of keys supported */
	union {
		RSA	*rsa;
		DSA	*dsa;
		unsigned char *hmac;
	} key;
	/* depending on the key we can have 
	 * extra data
	 */
	union {
		struct {
			uint32_t ttl;
			uint32_t inception;
			uint32_t expiration;
		}  dnssec;
		struct {
			uint16_t fudge;
			char *   name; /* needed? */
		} tsig;
	} extra;
	ldns_rdf *pubkey_owner;
};
typedef struct ldns_struct_key ldns_key;

/**
 * same as rr_list, but now for keys 
 */
struct ldns_struct_key_list
{
	size_t _key_count;
	ldns_key **_keys;
};
typedef struct ldns_struct_key_list ldns_key_list;

#endif /* _LDNS_KEYS_H */
