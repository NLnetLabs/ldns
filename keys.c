/*
 * keys.c handle private keys for use in DNSSEC
 *
 * This module should hide some of the openSSL complexities
 * and give a general interface for private keys and hmac
 * handling
 */

#include <config.h>
#include <openssl/ssl.h>

#include <util.h>
#include <ldns/keys.h>



ldns_lookup_table ldns_signing_algorithms[] = {
        { LDNS_SIGN_ALG_RSAMD5, "RSAMD5" },
        { LDNS_SIGN_ALG_RSASHA1, "RSASHA1" },
        { LDNS_SIGN_ALG_DSAMD5, "DSAMD5" },
        { LDNS_SIGN_ALG_DSASHA1, "DSASHA1" },
        { LDNS_SIGN_ALG_HMACMD5, "hmac-md5.sig-alg.reg.int" },
        { 0, NULL }
};

ldns_key_list *
ldns_key_list_new()
{
	ldns_key_list *key_list = MALLOC(ldns_key_list);
	key_list->_key_count = 0;
	key_list->_keys = NULL;
	return key_list;
}

void
ldns_key_set_algorithm(ldns_key *k, ldns_signing_algorithm l) 
{
	k->_alg = l;
}

void
ldns_key_set_rsa_key(ldns_key *k, RSA *r)
{
	k->_key.rsa = r;
}

void
ldns_key_set_dsa_key(ldns_key *k, DSA *d)
{
	k->_key.dsa  = d;
}

void
ldns_key_set_hmac_key(ldns_key *k, unsigned char *hmac)
{
	k->_key.hmac = hmac;
}

void
ldns_key_set_ttl(ldns_key *k, uint32_t t)
{
	k->_extra.dnssec.orig_ttl = t;
}

void
ldns_key_set_inception(ldns_key *k, uint32_t i)
{
	k->_extra.dnssec.inception = i;
}

void
ldns_key_set_expiration(ldns_key *k, uint32_t e)
{
	k->_extra.dnssec.expiration = e;
}

/* todo also for tsig */

void
ldns_key_set_pubkey_owner(ldns_key *k, ldns_rdf *r)
{
	k->_pubkey_owner = r;
}


/* read */
size_t
ldns_key_list_key_count(ldns_key_list *key_list)
{
	        return key_list->_key_count;
}       

ldns_key *
ldns_key_list_key(ldns_key_list *key, size_t nr)
{       
	if (nr < ldns_key_list_key_count(key)) {
		return key->_keys[nr];
	} else {
		return NULL;
	}
}

ldns_signing_algorithm
ldns_key_algorithm(ldns_key *k) 
{
	return k->_alg;
}

RSA *
ldns_key_rsa_key(ldns_key *k)
{
	return k->_key.rsa;
}

DSA *
ldns_key_dsa_key(ldns_key *k)
{
	return k->_key.dsa;
}

unsigned char *
ldns_key_hmac_key(ldns_key *k)
{
	return k->_key.hmac;
}

uint32_t
ldns_key_ttl(ldns_key *k)
{
	return k->_extra.dnssec.orig_ttl;
}

uint32_t
ldns_key_inception(ldns_key *k)
{
	return k->_extra.dnssec.inception;
}

uint32_t
ldns_key_expiration(ldns_key *k)
{
	return k->_extra.dnssec.expiration;
}

/* todo also for tsig */

ldns_rdf *
ldns_key_pubkey_owner(ldns_key *k)
{
	return k->_pubkey_owner;
}

/* write */
void            
ldns_key_list_set_key_count(ldns_key_list *key, size_t count)
{
	        key->_key_count = count;
}       

/**     
 * push an key to a keylist
 * \param[in] key_list the key_list to push to 
 * \param[in] key the key to push 
 * \return false on error, otherwise true
 */             
bool             
ldns_key_list_push_key(ldns_key_list *key_list, ldns_key *key)
{       
        size_t key_count;
        ldns_key **keys;

        key_count = ldns_key_list_key_count(key_list);
        
        /* grow the array */
        keys = XREALLOC(
                key_list->_keys, ldns_key *, key_count + 1);
        if (!keys) {
                return false;
        }

        /* add the new member */
        key_list->_keys = keys;
        key_list->_keys[key_count] = key;

        ldns_key_list_set_key_count(key_list, key_count + 1);
        return true;
}

/**     
 * pop the last rr from a rrlist
 * \param[in] rr_list the rr_list to pop from
 * \return NULL if nothing to pop. Otherwise the popped RR
 */     
ldns_key *
ldns_key_list_pop_key(ldns_key_list *key_list)
{                               
        size_t key_count;
        ldns_key *pop;
        
        key_count = ldns_key_list_key_count(key_list);
                                
        if (key_count == 0) {
                return NULL;
        }       
        
        pop = ldns_key_list_key(key_list, key_count);
        
        /* shrink the array */
        key_list->_keys = XREALLOC(
                key_list->_keys, ldns_key *, key_count - 1);

        ldns_key_list_set_key_count(key_list, key_count - 1);

        return pop;
}       

