/*
 * 
 * keys.h
 *
 * priv key definitions
 *
 * a Net::DNS like library for C
 *
 * (c) NLnet Labs, 2004, 2005
 *
 * See the file LICENSE for the license
 */

#ifndef _LDNS_KEYS_H
#define _LDNS_KEYS_H

#include <openssl/ssl.h>
#include <ldns/dnssec.h>
#include <ldns/util.h>

extern ldns_lookup_table ldns_signing_algorithms[];

#define LDNS_KEY_ZONE_KEY 0x0100
#define LDNS_KEY_SEP_KEY 0x0001

/**
 * algorithms used in dns
 */
enum ldns_enum_algorithm
{
        LDNS_RSAMD5             = 1,
        LDNS_DH                 = 2,
        LDNS_DSA                = 3,
        LDNS_ECC                = 4,
        LDNS_RSASHA1            = 5,
        LDNS_INDIRECT           = 252,
        LDNS_PRIVATEDNS         = 253,
        LDNS_PRIVATEOID         = 254
};
typedef enum ldns_enum_algorithm ldns_algorithm;

/**
 * algorithms used in dns for signing
 */
enum ldns_enum_signing_algorithm
{
	LDNS_SIGN_RSAMD5	 = LDNS_RSAMD5,
	LDNS_SIGN_RSASHA1	 = LDNS_RSASHA1,
	LDNS_SIGN_DSA		 = LDNS_DSA,
	LDNS_SIGN_HMACMD5	 = 150	/* not official! */
};
typedef enum ldns_enum_signing_algorithm ldns_signing_algorithm;

/**
 * general key structure, can contain all types of keys
 */
struct ldns_struct_key {
	ldns_signing_algorithm _alg;
	/** types of keys supported */
	union {
		RSA	*rsa;
		DSA	*dsa;
		unsigned char *hmac;
	} _key;
	/** depending on the key we can have extra data */
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


/**
 * creates a new empty key list
 */
ldns_key_list *ldns_key_list_new();

/** 
 * creates a new empty key structure
 */
ldns_key *ldns_key_new();

/**
 * creates a new key based on the algorithm
 *
 * \param[in] a The algorithm to use
 * \param[in] size the number of bytes for the keysize
 * \return a new ldns_key structure with the key
 */
ldns_key *ldns_key_new_frm_algorithm(ldns_signing_algorithm a, uint16_t size);

/**
 * creates a new priv key based on the 
 * contents of the file pointed by fp
 *
 * \param[in] fp the file pointer to use
 * \return a new ldns_key structure with the key
 */
ldns_key *ldns_key_new_frm_fp(FILE *fp);

/**
 * creates a new priv key based on the 
 * contents of the file pointed by fp
 *
 * \param[in] fp the file pointer to use
 * \param[in] line_nr pointer to an integer containing the current line number (for debugging purposes)
 * \return a new ldns_key structure with the key
 */
ldns_key *ldns_key_new_frm_fp_l(FILE *fp, int *line_nr);

/**
 * frm_fp helper function. This function parsed the
 * remainder of the (RSA) priv. key file generated from bind9
 * \param[in] fp the file to parse
 * \return NULL on failure otherwise a RSA structure
 */
RSA *ldns_key_new_frm_fp_rsa(FILE *fp);

/**
 * frm_fp helper function. This function parsed the
 * remainder of the (RSA) priv. key file generated from bind9
 * \param[in] fp the file to parse
 * \param[in] line_nr pointer to an integer containing the current line number (for debugging purposes)
 * \return NULL on failure otherwise a RSA structure
 */
RSA *ldns_key_new_frm_fp_rsa_l(FILE *fp, int *line_nr);

/**
 * frm_fp helper function. This function parsed the
 * remainder of the (DSA) priv. key file generated from bind9
 * \param[in] fp the file to parse
 * \return NULL on failure otherwise a RSA structure
 */
DSA *ldns_key_new_frm_fp_dsa(FILE *fp);

/**
 * frm_fp helper function. This function parsed the
 * remainder of the (DSA) priv. key file generated from bind9
 * \param[in] fp the file to parse
 * \param[in] line_nr pointer to an integer containing the current line number (for debugging purposes)
 * \return NULL on failure otherwise a RSA structure
 */
DSA *ldns_key_new_frm_fp_dsa_l(FILE *fp, int *line_nr);

/* acces write functions */
void ldns_key_set_algorithm(ldns_key *k, ldns_signing_algorithm l);
void ldns_key_set_rsa_key(ldns_key *k, RSA *r);
void ldns_key_set_dsa_key(ldns_key *k, DSA *d);
void ldns_key_set_hmac_key(ldns_key *k, unsigned char *hmac);
void ldns_key_set_origttl(ldns_key *k, uint32_t t);
void ldns_key_set_inception(ldns_key *k, uint32_t i);
void ldns_key_set_expiration(ldns_key *k, uint32_t e);
void ldns_key_set_pubkey_owner(ldns_key *k, ldns_rdf *r);
void ldns_key_set_keytag(ldns_key *k, uint16_t tag);
void ldns_key_set_flags(ldns_key *k, uint16_t flags);
void ldns_key_list_set_key_count(ldns_key_list *key, size_t count);

/**     
 * pushes a key to a keylist
 * \param[in] key_list the key_list to push to 
 * \param[in] key the key to push 
 * \return false on error, otherwise true
 */      
bool ldns_key_list_push_key(ldns_key_list *key_list, ldns_key *key);

/**
 * returns the number of keys in the key list
 */
size_t ldns_key_list_key_count(ldns_key_list *key_list);

/**
 * returns a pointer to the key in the list at the given position
 */
ldns_key *ldns_key_list_key(ldns_key_list *key, size_t nr);

/**
 * returns the (openssl) RSA struct contained in the key
 */
RSA *ldns_key_rsa_key(ldns_key *k);

/**
 * returns the (openssl) DSA struct contained in the key
 */
DSA *ldns_key_dsa_key(ldns_key *k);

ldns_signing_algorithm ldns_key_algorithm(ldns_key *k);
unsigned char *ldns_key_hmac_key(ldns_key *k);
uint32_t ldns_key_origttl(ldns_key *k);
uint32_t ldns_key_inception(ldns_key *k);
uint32_t ldns_key_expiration(ldns_key *k);
uint16_t ldns_key_keytag(ldns_key *k);
ldns_rdf *ldns_key_pubkey_owner(ldns_key *k);
uint16_t ldns_key_flags(ldns_key *k);

/**     
 * pops the last rr from a keylist
 * \param[in] key_list the rr_list to pop from
 * \return NULL if nothing to pop. Otherwise the popped RR
 */
ldns_key *ldns_key_list_pop_key(ldns_key_list *key_list);

/** 
 * converts a ldns_key to a public key rr
 *
 * \param[in] k the ldns_key to convert
 * \return ldns_rr representation of the key
 */
ldns_rr *ldns_key2rr(ldns_key *k);

/**
 * print a private key to the file ouput
 * 
 * \param[in] output the FILE descriptor where to print to
 * \param[in] k the ldns_key to print
 */
void ldns_key_print(FILE *output, ldns_key *k);

/**
 * frees a key structure
 *
 * \param[in] key the key object to free
 */
void ldns_key_free(ldns_key *key);

/**
 * frees a key structure and all it's internal data
 *
 * \param[in] key the key object to free
 */
void ldns_key_deep_free(ldns_key *key);

/**
 * Frees a key list structure
 * \param[in] key_list the key list object to free
 */
void ldns_key_list_free(ldns_key_list *key_list);

#endif /* _LDNS_KEYS_H */
