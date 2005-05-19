/*
 * keys.c handle private keys for use in DNSSEC
 *
 * This module should hide some of the openSSL complexities
 * and give a general interface for private keys and hmac
 * handling
 */

#include <ldns/config.h>

#include <ldns/dns.h>

#include <openssl/ssl.h>

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
	ldns_key_list *key_list = LDNS_MALLOC(ldns_key_list);
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

	newkey = LDNS_MALLOC(ldns_key);
	if (!newkey) {
		return NULL;
	} else {
		/* some defaults - not sure wether to do this */
		ldns_key_set_flags(newkey, 256);
		ldns_key_set_origttl(newkey, 0);
		ldns_key_set_keytag(newkey, 0);
		ldns_key_set_inception(newkey, 0);
		ldns_key_set_expiration(newkey, 0);
		ldns_key_set_pubkey_owner(newkey, NULL);
		return newkey;
	}
}

ldns_key *
ldns_key_new_frm_fp(FILE *fp)
{
	ldns_key *k;
	char *d;
	ldns_signing_algorithm alg;

	k = ldns_key_new();
	d = LDNS_XMALLOC(char, LDNS_MAX_LINELEN);
	if (!k || !d) {
		return NULL;
	}
	
	alg = 0;
	
	/* the file is highly structured. Do this in sequence */
	/* RSA:
	 * Private-key-format: v1.2
 	 * Algorithm: 1 (RSA)

	 */
	/* get the key format version number */
	if (ldns_fget_keyword_data(fp, "Private-key-format", ": ", d, "\n",
				LDNS_MAX_LINELEN) == -1) {
		/* no version information */
		return NULL;
	}
	if (strncmp(d, "v1.2", strlen(d)) != 0) {
		printf("Wrong version\n");
		return NULL;
	}

	/* get the algorithm type, our file function strip ( ) so there are
	 * not in the return string! */
	if (ldns_fget_keyword_data(fp, "Algorithm", ": ", d, "\n", 
				LDNS_MAX_LINELEN) == -1) {
		/* no version information */
		return NULL;
	}
	if (strncmp(d, "1 RSA", strlen(d)) == 0) {
		alg = LDNS_SIGN_RSAMD5; /* md5, really?? */
	}
	if (strncmp(d, "3 DSA", strlen(d)) == 0) {
		alg = LDNS_SIGN_DSA; 
	}

	LDNS_FREE(d);

	switch(alg) {
		case 0:
		default:
			printf("No algorithm seen, bailing out\n");
			return NULL;
		case LDNS_SIGN_RSAMD5:
		case LDNS_SIGN_RSASHA1:
			printf("RSA seen\n");

			ldns_key_set_algorithm(k, alg);
			ldns_key_set_rsa_key(k, ldns_key_new_frm_fp_rsa(fp));

			break;
		case LDNS_SIGN_DSA:
			printf("DSA seen\n");
			ldns_key_set_algorithm(k, alg);
			ldns_key_set_dsa_key(k, ldns_key_new_frm_fp_dsa(fp));
			break;
	}

	printf("So far so good\n");

	return k;
}

RSA *
ldns_key_new_frm_fp_rsa(FILE *f)
{
	/* we parse
 	 * Modulus: 
 	 * PublicExponent: 
 	 * PrivateExponent: 
 	 * Prime1: 
 	 * Prime2: 
 	 * Exponent1: 
 	 * Exponent2: 
 	 * Coefficient: 
	 *
	 * man 3 RSA:
	 *
	 * struct
         *     {
         *     BIGNUM *n;              // public modulus
         *     BIGNUM *e;              // public exponent
         *     BIGNUM *d;              // private exponent
         *     BIGNUM *p;              // secret prime factor
         *     BIGNUM *q;              // secret prime factor
         *     BIGNUM *dmp1;           // d mod (p-1)
         *     BIGNUM *dmq1;           // d mod (q-1)
         *     BIGNUM *iqmp;           // q^-1 mod p
         *     // ...
	 *
	 */
	char *d;
	RSA *rsa;
	uint8_t *buf;
	int i;

	d = LDNS_XMALLOC(char, LDNS_MAX_LINELEN);
	buf = LDNS_XMALLOC(uint8_t, LDNS_MAX_LINELEN);
	rsa = RSA_new();
	if (!d || !rsa || !buf) {
		return NULL;
	}

	/* I could use functions again, but that seems an overkill,
	 * allthough this also looks tedious 
	 */

	/* Modules, rsa->n */
	if (ldns_fget_keyword_data(f, "Modulus", ": ", d, "\n", LDNS_MAX_LINELEN) == -1) {
		goto error;
	}
	i = b64_pton((const char*)d, buf, b64_ntop_calculate_size(strlen(d)));
	rsa->n = BN_bin2bn((const char unsigned*)buf, i, NULL);
	if (!rsa->n) {
		goto error;
	}

	/* PublicExponent, rsa->e */
	if (ldns_fget_keyword_data(f, "PublicExponent", ": ", d, "\n", LDNS_MAX_LINELEN) == -1) {
		goto error;
	}
	i = b64_pton((const char*)d, buf, b64_ntop_calculate_size(strlen(d)));
	rsa->e = BN_bin2bn((const char unsigned*)buf, i, NULL);
	if (!rsa->e) {
		goto error;
	}

	/* PrivateExponent, rsa->d */
	if (ldns_fget_keyword_data(f, "PrivateExponent", ": ", d, "\n", LDNS_MAX_LINELEN) == -1) {
		goto error;
	}
	i = b64_pton((const char*)d, buf, b64_ntop_calculate_size(strlen(d)));
	rsa->d = BN_bin2bn((const char unsigned*)buf, i, NULL);
	if (!rsa->d) {
		goto error;
	}

	/* Prime1, rsa->p */
	if (ldns_fget_keyword_data(f, "Prime1", ": ", d, "\n", LDNS_MAX_LINELEN) == -1) {
		goto error;
	}
	i = b64_pton((const char*)d, buf, b64_ntop_calculate_size(strlen(d)));
	rsa->p = BN_bin2bn((const char unsigned*)buf, i, NULL);
	if (!rsa->p) {
		goto error;
	}
	
	/* Prime2, rsa->q */
	if (ldns_fget_keyword_data(f, "Prime2", ": ", d, "\n", LDNS_MAX_LINELEN) == -1) {
		goto error;
	}
	i = b64_pton((const char*)d, buf, b64_ntop_calculate_size(strlen(d)));
	rsa->q = BN_bin2bn((const char unsigned*)buf, i, NULL);
	if (!rsa->q) {
		goto error;
	}

	/* Exponent1, rsa->dmp1 */
	if (ldns_fget_keyword_data(f, "Exponent1", ": ", d, "\n", LDNS_MAX_LINELEN) == -1) {
		goto error;
	}
	i = b64_pton((const char*)d, buf, b64_ntop_calculate_size(strlen(d)));
	rsa->dmp1 = BN_bin2bn((const char unsigned*)buf, i, NULL);
	if (!rsa->dmp1) {
		goto error;
	}
	
	/* Exponent2, rsa->dmq1 */
	if (ldns_fget_keyword_data(f, "Exponent2", ": ", d, "\n", LDNS_MAX_LINELEN) == -1) {
		goto error;
	}
	i = b64_pton((const char*)d, buf, b64_ntop_calculate_size(strlen(d)));
	rsa->dmq1 = BN_bin2bn((const char unsigned*)buf, i, NULL);
	if (!rsa->dmq1) {
		goto error;
	}

	/* Coefficient, rsa->iqmp */
	if (ldns_fget_keyword_data(f, "Coefficient", ": ", d, "\n", LDNS_MAX_LINELEN) == -1) {
		goto error;
	}
	i = b64_pton((const char*)d, buf, b64_ntop_calculate_size(strlen(d)));
	rsa->iqmp = BN_bin2bn((const char unsigned*)buf, i, NULL);
	if (!rsa->iqmp) {
		goto error;
	}
	return rsa;

error:
	LDNS_FREE(d);
	LDNS_FREE(buf);
	return NULL;
}

DSA *
ldns_key_new_frm_fp_dsa(FILE *f)
{
	char *d;
	DSA *dsa;

	d = LDNS_XMALLOC(char, LDNS_MAX_LABELLEN);
	dsa = DSA_new();
	if (!d || !dsa) {
		return NULL;
	}
	f = f;

#if 0
From the signer

	                        dsakey->p       = priv_fromfile_helper(f, "Prime(p)");
                        dsakey->q       = priv_fromfile_helper(f, "Subprime(q)");
                        dsakey->g       = priv_fromfile_helper(f, "Base(g)");
                        dsakey->priv_key        = priv_fromfile_helper(f, "Private_value(x)");
                        dsakey->pub_key         = priv_fromfile_helper(f, "Public_value(y)");
                        key->keydata.dsap       = dsakey;
                        key->size       = BN_num_bits(dsakey->pub_key)
#endif

	return NULL;
}

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
			r = RSA_generate_key((int)size, RSA_3, NULL, NULL);
			if (RSA_check_key(r) != 1) {
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
ldns_key_set_origttl(ldns_key *k, uint32_t t)
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
ldns_key_origttl(ldns_key *k)
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

bool             
ldns_key_list_push_key(ldns_key_list *key_list, ldns_key *key)
{       
        size_t key_count;
        ldns_key **keys;

        key_count = ldns_key_list_key_count(key_list);
        
        /* grow the array */
        keys = LDNS_XREALLOC(
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

ldns_key *
ldns_key_list_pop_key(ldns_key_list *key_list)
{                               
        size_t key_count;
        ldns_key *pop;

	if (!key_list) {
		return NULL;
	}
        
        key_count = ldns_key_list_key_count(key_list);
        if (key_count == 0) {
                return NULL;
        }       
        
        pop = ldns_key_list_key(key_list, key_count);
        
        /* shrink the array */
        key_list->_keys = LDNS_XREALLOC(
                key_list->_keys, ldns_key *, key_count - 1);

        ldns_key_list_set_key_count(key_list, key_count - 1);

        return pop;
}       

static bool
ldns_key_rsa2bin(unsigned char *data, RSA *k, uint16_t *size)
{
	if (!k) {
		return false;
	}
	
	 if (BN_num_bytes(k->e) <= 2) {
                data[0] = (unsigned char) BN_num_bytes(k->e);

                BN_bn2bin(k->e, data + 1);  
                BN_bn2bin(k->n, data + *(data + 1) + 2);
		*size = (uint16_t) BN_num_bytes(k->n) + 4;
        } else if (BN_num_bytes(k->e) <= 16) {
                data[0] = 0;
		/* this writing is not endian save or is it? */
		write_uint16(data + 1, (uint16_t) BN_num_bytes(k->e));

                BN_bn2bin(k->e, data + 3);
                BN_bn2bin(k->n, data + 4 + BN_num_bytes(k->e));
                *size = (uint16_t) BN_num_bytes(k->n) + 6;
	} else {
		return false;
	}
	return true;
}

static bool
ldns_key_dsa2bin(unsigned char *data, DSA *k, uint16_t *size)
{
	uint8_t T;

	if (!k) {
		return false;
	}
	
	/* See RFC2536 */
	*size = (uint16_t)BN_num_bytes(k->g);
	T = (*size - 64) / 8;
	memcpy(data, &T, 1);

	if (T > 8) {
		dprintf("DSA_size = %d, T > 8, not implemented\n", DSA_size(k));
		return false;
	}

	/* size = 64 + (T * 8); */
	data[0] = (unsigned char)T;
	BN_bn2bin(k->q, data + 1 ); 		/* 20 octects */
	BN_bn2bin(k->p, data + 21 ); 		/* offset octects */
	BN_bn2bin(k->g, data + 21 + *size); 	/* offset octets */
	BN_bn2bin(k->pub_key, data + 21 + *size + *size); /* offset octets */
	*size = 24 + (*size * 3);
	return true;
}

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

	bin = LDNS_XMALLOC(unsigned char, LDNS_MAX_KEYLEN);
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
			ldns_native2rdf_int8(LDNS_RDF_TYPE_INT8, LDNS_DNSSEC_KEYPROTO));
	
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
			printf("Entering here I\n");
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
	keybin = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_B64, size + 1, bin);
	LDNS_FREE(bin);
	ldns_rr_push_rdf(pubkey, keybin);
	return pubkey;
}
