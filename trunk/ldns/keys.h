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

#include <openssl/ssl.h>
#include <util.h>

enum ldns_enum_signing_algorithm
{
	LDNS_SIGN_ALG_RSAMD5	= 1,
	LDNS_SIGN_ALG_RSASHA1	= 2,
	LDNS_SIGN_ALG_DSAMD5	= 3, 
	LDNS_SIGN_ALG_DSASHA1	= 4,
	LDNS_SIGN_ALG_HMACMD5	= 5
};
typedef enum ldns_enum_signing_algorithm ldns_signing_algorithm;

ldns_lookup_table ldns_signing_algorithms[] = {
	{ LDNS_SIGN_ALG_RSAMD5, "RSAMD5" },
	{ LDNS_SIGN_ALG_RSASHA1, "RSASHA1" },
	{ LDNS_SIGN_ALG_DSAMD5, "DSAMD5" },
	{ LDNS_SIGN_ALG_DSASHA1, "DSASHA1" },
	{ LDNS_SIGN_ALG_HMACMD5, "hmac-md5.sig-alg.reg.int" },
	{ 0, NULL }
};


struct ldns_struct_key {
	ldns_signing_algorithm algorithm;
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
};
typedef struct ldns_struct_key ldns_key;

