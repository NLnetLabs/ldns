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
        { LDNS_SIGN_RSAMD5, "RSAMD5" },
        { LDNS_SIGN_RSASHA1, "RSASHA1" },
        { LDNS_SIGN_DSA, "DSAMD5" },
        { LDNS_SIGN_HMACMD5, "hmac-md5.sig-alg.reg.int" },
        { 0, NULL }
};

ldns_key_list *
ldns_key_list_new()
{
	ldns_key_list *key_list = MALLOC(ldns_key_list);
	if (!key_list) {
		return NULL;
	} else {
		key_list->_key_count = 0;
		key_list->_keys = NULL;
		return key_list;
	}
}

ldns_key *
ldns_key_new()
{
	ldns_key *newkey;

	newkey = MALLOC(ldns_key);
	if (!newkey) {
		return NULL;
	} else {
		ldns_key_set_flags(newkey, 256);
		ldns_key_set_inception(newkey, 0);
		ldns_key_set_expiration(newkey, 0);
		ldns_key_set_pubkey_owner(newkey, NULL);
		return newkey;
	}
}

/**
 * generate a new key based on the algorithm
 */
ldns_key *
ldns_key_new_frm_algorithm(ldns_signing_algorithm alg, uint16_t size)
{
	ldns_key *k;
	DSA *d;
	RSA *r;

	k = ldns_key_new();
	if (!k) {
		return NULL;
	}
	switch(alg) {
		case LDNS_SIGN_RSAMD5:
		case LDNS_SIGN_RSASHA1:
			r = RSA_generate_key((int)size, RSA_F4, NULL, NULL);
			if (RSA_check_key(r) != 1) {
				printf("keygen failed\n");
				return NULL;
			}
			ldns_key_set_rsa_key(k, r);
			break;
		case LDNS_SIGN_DSA:
			d = DSA_generate_parameters((int)size, NULL, 0, NULL, NULL, NULL, NULL);
			DSA_generate_key(d);
			ldns_key_set_dsa_key(k, d);
			break;
		case LDNS_SIGN_HMACMD5:
			/* do your hmac thing here */
			break;
	}
	ldns_key_set_algorithm(k, alg);
	/* some defaults - not sure wether to this there or not */
	ldns_key_set_flags(k, 256);
	ldns_key_set_inception(k, 0);
	ldns_key_set_expiration(k, 0);
	ldns_key_set_keytag(k,
			ldns_key_calc_keytag(k));
	printf("keytag %d\n", ldns_key_calc_keytag(k));
	return k;
}

void
ldns_key_set_algorithm(ldns_key *k, ldns_signing_algorithm l) 
{
	k->_alg = l;
}

void
ldns_key_set_flags(ldns_key *k, uint16_t f)
{
	k->_extra.dnssec.flags = f;
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

void
ldns_key_set_keytag(ldns_key *k, uint16_t tag)
{
	k->_extra.dnssec.keytag = tag;
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

uint16_t
ldns_key_flags(ldns_key *k)
{
	return k->_extra.dnssec.flags;
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

uint16_t
ldns_key_keytag(ldns_key *k)
{
	return k->_extra.dnssec.keytag;
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
 * Pushes a key to a keylist
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
 * Pops the last rr from a keylist
 * \param[in] key_list the rr_list to pop from
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

static bool
ldns_key_rsa2bin(unsigned char *data, RSA *k, uint16_t *size)
{
	 if (BN_num_bytes(k->e) < 256) {
                data[0] = (unsigned char) BN_num_bytes(k->e);

                BN_bn2bin(k->e, data + 1);  
                BN_bn2bin(k->n, data + *(data + 1) + 2);
        } else if (BN_num_bytes(k->e) < 65536) {
                data[0] = 0;
		/* this writing is not endian save or is it? */
		write_uint16(data + 1, (uint16_t) BN_num_bytes(k->e));

                BN_bn2bin(k->e, data + 3);
                BN_bn2bin(k->n, data + 4 + BN_num_bytes(k->e));
	} else {
		return false;
	}
	*size = (uint16_t) BN_num_bytes(k->n) + 4;
	return true;
}

static bool
ldns_key_dsa2bin(unsigned char *data, DSA *k, uint16_t *size)
{
	uint8_t T;

	/* See RFC2536 */
	T = (uint8_t) ((DSA_size(k) - 512) / 64);
	memcpy(data, &T, 1);

	*size = 64 + (T * 8); 

	BN_bn2bin(k->q, data + 1 ); 		/* 20 octects */
	BN_bn2bin(k->p, data + 22 ); 		/* offset octects */
	BN_bn2bin(k->g, data + 23 + *size ); 	/* offset octets */
	BN_bn2bin(k->pub_key, data + 24 + *size + *size); /* offset octets */
	*size = 24 + (*size * 3);
	return true;
}

/** 
 * convert a ldns_key to a public key rr
 */
ldns_rr *
ldns_key2rr(ldns_key *k)
{
	/* this function will convert a the keydata contained in
	 * rsa/dsa pointers to a DNSKEY rr. It will fill in as
	 * much as it can, but it does not know about key-flags
	 * for instance
	 */

	ldns_rr *pubkey;
	ldns_rdf *keybin;
	unsigned char *bin;
	uint16_t size;
	pubkey = ldns_rr_new();

	if (!k) {
		return NULL;
	}

	bin = XMALLOC(unsigned char, MAX_KEYLEN);
	if (!bin) {
		return NULL;
	}

	ldns_rr_set_type(pubkey, LDNS_RR_TYPE_DNSKEY);
	/* zero-th rdf - flags */
	ldns_rr_push_rdf(pubkey,
			ldns_native2rdf_int16(LDNS_RDF_TYPE_INT16, 
				ldns_key_flags(k)));
	/* first - proto */
	ldns_rr_push_rdf(pubkey, 
			ldns_native2rdf_int8(LDNS_RDF_TYPE_INT8, DNSSEC_KEYPROTO));
	
	ldns_rr_set_owner(pubkey, ldns_key_pubkey_owner(k));

	/* third - da algorithm */
	switch(ldns_key_algorithm(k)) {
		case LDNS_SIGN_RSAMD5:
			ldns_rr_push_rdf(pubkey,
					ldns_native2rdf_int8(LDNS_RDF_TYPE_ALG, LDNS_RSAMD5));
			if (!ldns_key_rsa2bin(bin, ldns_key_rsa_key(k), &size)) {
				return NULL;
			}
			break;
		case LDNS_SIGN_RSASHA1:
			ldns_rr_push_rdf(pubkey,
					ldns_native2rdf_int8(LDNS_RDF_TYPE_ALG, LDNS_RSASHA1));
			if (!ldns_key_rsa2bin(bin, ldns_key_rsa_key(k), &size)) {
				return NULL;
			}
			break;
		case LDNS_SIGN_DSA:
			ldns_rr_push_rdf(pubkey,
					ldns_native2rdf_int8(LDNS_RDF_TYPE_ALG, LDNS_DSA));
			if (!ldns_key_dsa2bin(bin, ldns_key_dsa_key(k), &size)) {
				return NULL;
			}
			break;
		case LDNS_SIGN_HMACMD5:
			/* tja */
			break;
	}
	/* fourth the key bin material */
	keybin = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_B64, size, bin);
	FREE(bin);
	ldns_rr_push_rdf(pubkey, keybin);
	return pubkey;
}

uint16_t
ldns_key_calc_keytag(ldns_key *k)
{
	ldns_rr *keyrr;
	uint16_t tag;

	keyrr = ldns_key2rr(k);

	tag = ldns_calc_keytag(keyrr);
	ldns_rr_free(keyrr);
	return tag;
}
