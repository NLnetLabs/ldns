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
#include <ldns/dnssec.h>
#include <util.h>

extern ldns_lookup_table ldns_signing_algorithms[];

enum ldns_enum_signing_algorithm
{
	LDNS_SIGN_RSAMD5	 = LDNS_RSAMD5,
	LDNS_SIGN_RSASHA1	 = LDNS_RSASHA1,
	LDNS_SIGN_DSA		 = LDNS_DSA,
	LDNS_SIGN_HMACMD5	 = 150	/* not official! */
};
typedef enum ldns_enum_signing_algorithm ldns_signing_algorithm;


struct ldns_struct_key {
	ldns_signing_algorithm _alg;
	/* types of keys supported */
	union {
		RSA	*rsa;
		DSA	*dsa;
		unsigned char *hmac;
	} _key;
	/* depending on the key we can have 
	 * extra data
	 */
	union {
		struct {
			uint32_t orig_ttl;
			uint32_t inception;
			uint32_t expiration;
			uint16_t keytag;
			uint16_t flags;
		}  dnssec;
		struct {
			uint16_t fudge;
			char *   name; /* needed? */
		} tsig;
	} _extra;
	ldns_rdf *_pubkey_owner;
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

ldns_key_list * ldns_key_list_new();
ldns_key *ldns_key_new();
void ldns_key_set_algorithm(ldns_key *k, ldns_signing_algorithm l);
void ldns_key_set_rsa_key(ldns_key *k, RSA *r);
void ldns_key_set_dsa_key(ldns_key *k, DSA *d);
void ldns_key_set_hmac_key(ldns_key *k, unsigned char *hmac);
void ldns_key_set_ttl(ldns_key *k, uint32_t t);
void ldns_key_set_inception(ldns_key *k, uint32_t i);
void ldns_key_set_expiration(ldns_key *k, uint32_t e);
void ldns_key_set_pubkey_owner(ldns_key *k, ldns_rdf *r);
void ldns_key_set_keytag(ldns_key *k, uint16_t tag);
void ldns_key_set_flags(ldns_key *k, uint16_t flags);
size_t ldns_key_list_key_count(ldns_key_list *key_list);
ldns_key * ldns_key_list_key(ldns_key_list *key, size_t nr);

ldns_signing_algorithm ldns_key_algorithm(ldns_key *k);
RSA * ldns_key_rsa_key(ldns_key *k);
DSA * ldns_key_dsa_key(ldns_key *k);
unsigned char * ldns_key_hmac_key(ldns_key *k);
uint32_t ldns_key_ttl(ldns_key *k);
uint32_t ldns_key_inception(ldns_key *k);
uint32_t ldns_key_expiration(ldns_key *k);
uint16_t ldns_key_keytag(ldns_key *k);
void ldns_key_list_set_key_count(ldns_key_list *key, size_t count);
ldns_rdf * ldns_key_pubkey_owner(ldns_key *k);
bool ldns_key_list_push_key(ldns_key_list *key_list, ldns_key *key);
ldns_key * ldns_key_list_pop_key(ldns_key_list *key_list);

ldns_key * ldns_key_new_frm_algorithm(ldns_signing_algorithm a, uint16_t size);

ldns_rr * ldns_key2rr(ldns_key *k);
uint16_t ldns_key_flags(ldns_key *k);

#endif /* _LDNS_KEYS_H */
