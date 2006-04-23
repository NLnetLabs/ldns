/* 
 * dnssec.c
 *
 * contains the cryptographic function needed for DNSSEC
 * The crypto library used is openssl
 *
 * (c) NLnet Labs, 2004-2006
 * a Net::DNS like library for C
 *
 * See the file LICENSE for the license
 */

#include <ldns/config.h>

#include <ldns/dns.h>

#include <strings.h>
#include <time.h>

#ifdef HAVE_SSL
/* this entire file is rather useless when you don't have
 * crypto...
 */
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/md5.h>

/* used only on the public key RR */
uint16_t
ldns_calc_keytag(const ldns_rr *key)
{
	unsigned int i;
	uint32_t ac32;
	uint16_t ac16;
	
	ldns_buffer *keybuf;
	size_t keysize;

	if (!key) {
		return 0;
	}

	ac32 = 0;
	if (ldns_rr_get_type(key) != LDNS_RR_TYPE_DNSKEY) {
		return 0;
	}

	/* rdata to buf - only put the rdata in a buffer */
	keybuf = ldns_buffer_new(LDNS_MIN_BUFLEN); /* grows */
	if (!keybuf) {
		return 0;
	}
	(void)ldns_rr_rdata2buffer_wire(keybuf, key);
	/* the current pos in the buffer is the keysize */
	keysize= ldns_buffer_position(keybuf);

	/* look at the algorithm field, copied from 2535bis */
	if (ldns_rdf2native_int8(ldns_rr_rdf(key, 2)) == LDNS_RSAMD5) {
		if (keysize > 4) {
			ldns_buffer_read_at(keybuf, keysize - 3, &ac16, 2);
		}
		ldns_buffer_free(keybuf);
		ac16 = ntohs(ac16);
	        return (uint16_t) ac16;
	} else {
		for (i = 0; (size_t)i < keysize; ++i) {
			ac32 += (i & 1) ? *ldns_buffer_at(keybuf, i) : 
				*ldns_buffer_at(keybuf, i) << 8;
		}
		ldns_buffer_free(keybuf);
		ac32 += (ac32 >> 16) & 0xFFFF;
		return (uint16_t) (ac32 & 0xFFFF);
	}
}

ldns_status
ldns_verify(ldns_rr_list *rrset, ldns_rr_list *rrsig, ldns_rr_list *keys, 
		ldns_rr_list *good_keys)
{
	uint16_t i;
	bool valid;
	ldns_status verify_result = LDNS_STATUS_ERR;

	if (!rrset || !rrsig || !keys) {
		return LDNS_STATUS_ERR;
	}

	valid = false;

	if (ldns_rr_list_rr_count(rrset) < 1) {
		return LDNS_STATUS_ERR;
	}

	if (ldns_rr_list_rr_count(rrsig) < 1) {
		return LDNS_STATUS_CRYPTO_NO_RRSIG;
	}
	
	if (ldns_rr_list_rr_count(keys) < 1) {
		verify_result = LDNS_STATUS_CRYPTO_NO_TRUSTED_DNSKEY;
	} else {
		for (i = 0; i < ldns_rr_list_rr_count(rrsig); i++) {

			if (ldns_verify_rrsig_keylist(rrset,
					ldns_rr_list_rr(rrsig, i),
					keys, good_keys) == LDNS_STATUS_OK) {
				verify_result = LDNS_STATUS_OK;
			}
		}
	}
	return verify_result;
}

ldns_status
ldns_verify_rrsig_buffers(ldns_buffer *rawsig_buf, ldns_buffer *verify_buf, 
		ldns_buffer *key_buf, uint8_t algo)
{
		/* check for right key */
		switch(algo) {
			case LDNS_DSA:
				return ldns_verify_rrsig_dsa(rawsig_buf, verify_buf, key_buf);
				break;
			case LDNS_RSASHA1:
				return ldns_verify_rrsig_rsasha1(rawsig_buf, verify_buf, key_buf);
				break;
			case LDNS_RSAMD5:
				return ldns_verify_rrsig_rsamd5(rawsig_buf, verify_buf, key_buf);
				break;
			default:
				/* do you know this alg?! */
				return LDNS_STATUS_CRYPTO_UNKNOWN_ALGO;
		}
}

/* Post 1.0 TODO: next 2 functions contain a lot of similar code */
/* 
 * to verify:
 * - create the wire fmt of the b64 key rdata
 * - create the wire fmt of the sorted rrset
 * - create the wire fmt of the b64 sig rdata
 * - create the wire fmt of the sig without the b64 rdata
 * - cat the sig data (without b64 rdata) to the rrset
 * - verify the rrset+sig, with the b64 data and the b64 key data
 */
ldns_status
ldns_verify_rrsig_keylist(ldns_rr_list *rrset, ldns_rr *rrsig, ldns_rr_list *keys, 
		ldns_rr_list *good_keys)
{
	ldns_buffer *rawsig_buf;
	ldns_buffer *verify_buf;
	ldns_buffer *key_buf;
	uint32_t orig_ttl;
	uint16_t i;
	uint8_t sig_algo;
	ldns_status result;
	ldns_rr *current_key;
	ldns_rr_list *rrset_clone;
	ldns_rr_list *validkeys;
	time_t now, inception, expiration;
	uint8_t label_count;
	ldns_rdf *wildcard_name;

	if (!rrset) {
		return LDNS_STATUS_ERR;
	}

	validkeys = ldns_rr_list_new();
	if (!validkeys) {
		return LDNS_STATUS_MEM_ERR;
	}
	
	/* clone the rrset so that we can fiddle with it */
	rrset_clone = ldns_rr_list_clone(rrset);

	/* check if the typecovered is equal to the type checked */
	if (ldns_rdf2rr_type(ldns_rr_rrsig_typecovered(rrsig)) !=
			ldns_rr_get_type(ldns_rr_list_rr(rrset_clone, 0))) {
		return LDNS_STATUS_CRYPTO_TYPE_COVERED_ERR;
	}
	
	/* create the buffers which will certainly hold the raw data */
	rawsig_buf = ldns_buffer_new(LDNS_MAX_PACKETLEN);
	verify_buf  = ldns_buffer_new(LDNS_MAX_PACKETLEN);
	
	sig_algo = ldns_rdf2native_int8(ldns_rr_rdf(rrsig, 1));
	result = LDNS_STATUS_ERR;

	/* check the signature time stamps */
	inception = ldns_rdf2native_time_t(ldns_rr_rrsig_inception(rrsig));
	expiration = ldns_rdf2native_time_t(ldns_rr_rrsig_expiration(rrsig));
	now = time(NULL);

	if (expiration - inception < 0) {
                /* bad sig, expiration before inception?? Tsssg */
		return LDNS_STATUS_CRYPTO_EXPIRATION_BEFORE_INCEPTION;
        }
        if (now - inception < 0) {
                /* bad sig, inception date has passed */
		return LDNS_STATUS_CRYPTO_SIG_NOT_INCEPTED;
        }
        if (expiration - now < 0) {
                /* bad sig, expiration date has passed */
		return LDNS_STATUS_CRYPTO_SIG_EXPIRED;
        }
	
	/* create a buffer with b64 signature rdata */
	if (ldns_rdf2buffer_wire(rawsig_buf, ldns_rr_rdf(rrsig, 8)) != LDNS_STATUS_OK) {
		ldns_buffer_free(rawsig_buf);
		ldns_buffer_free(verify_buf);
		return LDNS_STATUS_MEM_ERR;
	}

	orig_ttl = ldns_rdf2native_int32( ldns_rr_rdf(rrsig, 3));

	label_count = ldns_rdf2native_int8(ldns_rr_rdf(rrsig, 2));

	/* reset the ttl in the rrset with the orig_ttl from the sig */
	/* and update owner name if it was wildcard */
	for(i = 0; i < ldns_rr_list_rr_count(rrset_clone); i++) {
		if (label_count < 
			ldns_dname_label_count(
		               	ldns_rr_owner(ldns_rr_list_rr(rrset_clone, i)))) {
			(void) ldns_str2rdf_dname(&wildcard_name, "*");
			(void) ldns_dname_cat(wildcard_name, 
					      ldns_dname_left_chop(ldns_rr_owner(ldns_rr_list_rr
							      (rrset_clone, i))));
			ldns_rr_set_owner(ldns_rr_list_rr(rrset_clone, i), 
					wildcard_name);
		                  	
		}
		ldns_rr_set_ttl(ldns_rr_list_rr(rrset_clone, i), orig_ttl);
		/* convert to lowercase */
		ldns_rr2canonical(ldns_rr_list_rr(rrset_clone, i));
	}

	/* sort the rrset in canonical order  */
	ldns_rr_list_sort(rrset_clone);

	/* put the signature rr (without the b64) to the verify_buf */
	if (ldns_rrsig2buffer_wire(verify_buf, rrsig) != LDNS_STATUS_OK) {
		ldns_buffer_free(rawsig_buf);
		ldns_buffer_free(verify_buf);
		return LDNS_STATUS_MEM_ERR;
	}

	/* add the rrset in verify_buf */
	if (ldns_rr_list2buffer_wire(verify_buf, rrset_clone) != LDNS_STATUS_OK) {
		ldns_buffer_free(rawsig_buf);
		ldns_buffer_free(verify_buf);
		return LDNS_STATUS_MEM_ERR;
	}

	for(i = 0; i < ldns_rr_list_rr_count(keys); i++) {
		current_key = ldns_rr_list_rr(keys, i);
		/* before anything, check if the keytags match */
		if (ldns_calc_keytag(current_key) ==
		    ldns_rdf2native_int16(ldns_rr_rrsig_keytag(rrsig))) {
			key_buf = ldns_buffer_new(LDNS_MAX_PACKETLEN);
			
			/* put the key-data in a buffer, that's the third rdf, with
			 * the base64 encoded key data */
			if (ldns_rdf2buffer_wire(key_buf,
					ldns_rr_rdf(current_key, 3)) != LDNS_STATUS_OK) {
				ldns_buffer_free(rawsig_buf);
				ldns_buffer_free(verify_buf);
				/* returning is bad might screw up good keys later in the list
				   what to do? */
				return LDNS_STATUS_MEM_ERR;
			}

			/* check for right key */
			if (sig_algo == ldns_rdf2native_int8(ldns_rr_rdf(current_key, 
							2))) {
				result = ldns_verify_rrsig_buffers(rawsig_buf, 
						verify_buf, key_buf, sig_algo);
			} else {
				/* There is no else here ???? */
			}
			ldns_buffer_free(key_buf); 
			if (result == LDNS_STATUS_OK) {
				/* one of the keys has matched, don't break
				 * here, instead put the 'winning' key in
				 * the validkey list and return the list 
				 * later */
				if (!ldns_rr_list_push_rr(validkeys, current_key)) {
					/* couldn't push the key?? */
					return LDNS_STATUS_MEM_ERR;
				}
			} 
		} else {
			result = LDNS_STATUS_CRYPTO_NO_MATCHING_KEYTAG_DNSKEY;
		}
	}

	/* no longer needed */
	ldns_rr_list_deep_free(rrset_clone);
	ldns_buffer_free(rawsig_buf);
	ldns_buffer_free(verify_buf);
	if (ldns_rr_list_rr_count(validkeys) == 0) {
		/* no keys were added, return last error */
		ldns_rr_list_free(validkeys);
		return result;
	} else {
		ldns_rr_list_cat(good_keys, validkeys);
		return LDNS_STATUS_OK;
	}
}

ldns_status
ldns_verify_rrsig(ldns_rr_list *rrset, ldns_rr *rrsig, ldns_rr *key)
{
	ldns_buffer *rawsig_buf;
	ldns_buffer *verify_buf;
	ldns_buffer *key_buf;
	uint32_t orig_ttl;
	uint16_t i;
	uint8_t sig_algo;
	uint16_t label_count;
	ldns_status result;
	ldns_rr_list *rrset_clone;
	time_t now, inception, expiration;
	ldns_rdf *wildcard_name;

	if (!rrset) {
		return LDNS_STATUS_NO_DATA;
	}

	/* check the signature time stamps */
	inception = ldns_rdf2native_time_t(ldns_rr_rrsig_inception(rrsig));
	expiration = ldns_rdf2native_time_t(ldns_rr_rrsig_expiration(rrsig));
	now = time(NULL);

	if (expiration - inception < 0) {
                /* bad sig, expiration before inception?? Tsssg */
		return LDNS_STATUS_CRYPTO_EXPIRATION_BEFORE_INCEPTION;
        }
        if (now - inception < 0) {
                /* bad sig, inception date has passed */
		return LDNS_STATUS_CRYPTO_SIG_NOT_INCEPTED;
        }

        if (expiration - now < 0) {
                /* bad sig, expiration date has passed */
		return LDNS_STATUS_CRYPTO_SIG_EXPIRED;
        }
	/* clone the rrset so that we can fiddle with it */
	rrset_clone = ldns_rr_list_clone(rrset);
	
	/* create the buffers which will certainly hold the raw data */
	rawsig_buf = ldns_buffer_new(LDNS_MAX_PACKETLEN);
	verify_buf  = ldns_buffer_new(LDNS_MAX_PACKETLEN);
	
	sig_algo = ldns_rdf2native_int8(ldns_rr_rdf(rrsig, 1));
	
	/* check for known and implemented algo's now (otherwise 
	 * the function could return a wrong error
	 */
	switch(sig_algo) {
		case LDNS_RSAMD5:
		case LDNS_RSASHA1:
		case LDNS_DSA:
			break;
		case LDNS_DH:
		case LDNS_ECC:
		case LDNS_INDIRECT:
			ldns_buffer_free(rawsig_buf);
			ldns_buffer_free(verify_buf);
			return LDNS_STATUS_CRYPTO_ALGO_NOT_IMPL;
		default:
			ldns_buffer_free(rawsig_buf);
			ldns_buffer_free(verify_buf);
			return LDNS_STATUS_CRYPTO_UNKNOWN_ALGO;
	}
	
	result = LDNS_STATUS_ERR;

	/* create a buffer with b64 signature rdata */
	if (ldns_rdf2buffer_wire(rawsig_buf,
				ldns_rr_rdf(rrsig, 8)) != LDNS_STATUS_OK) {
		ldns_buffer_free(rawsig_buf);
		ldns_buffer_free(verify_buf);
		return LDNS_STATUS_MEM_ERR;
	}

	/* remove labels if the label count is higher than the label count
	   from the rrsig */
	label_count = ldns_rdf2native_int8(ldns_rr_rdf(rrsig, 2));

	orig_ttl = ldns_rdf2native_int32(
			ldns_rr_rdf(rrsig, 3));

	/* reset the ttl in the rrset with the orig_ttl from the sig */
	for(i = 0; i < ldns_rr_list_rr_count(rrset_clone); i++) {
		if (label_count < ldns_dname_label_count(ldns_rr_owner(ldns_rr_list_rr(rrset_clone, i)))) {
			(void) ldns_str2rdf_dname(&wildcard_name, "*");
			(void) ldns_dname_cat(wildcard_name, ldns_dname_left_chop(ldns_rr_owner(ldns_rr_list_rr(rrset_clone, i))));
			ldns_rr_set_owner(ldns_rr_list_rr(rrset_clone, i), wildcard_name);
		}
		ldns_rr_set_ttl(
				ldns_rr_list_rr(rrset_clone, i),
				orig_ttl);
		/* convert to lowercase */
		ldns_rr2canonical(ldns_rr_list_rr(rrset_clone, i));
	}

	/* sort the rrset in canonical order  */
	ldns_rr_list_sort(rrset_clone);

	/* put the signature rr (without the b64) to the verify_buf */
	if (ldns_rrsig2buffer_wire(verify_buf, rrsig) != LDNS_STATUS_OK) {
		ldns_rr_list_deep_free(rrset_clone);
		ldns_buffer_free(rawsig_buf);
		ldns_buffer_free(verify_buf);
		return LDNS_STATUS_ERR;
	}

	/* add the rrset in verify_buf */
	if (ldns_rr_list2buffer_wire(verify_buf, rrset_clone) != LDNS_STATUS_OK) {
		ldns_rr_list_deep_free(rrset_clone);
		ldns_buffer_free(rawsig_buf);
		ldns_buffer_free(verify_buf);
		return LDNS_STATUS_ERR;
	}

	if (ldns_calc_keytag(key)
	    ==
	    ldns_rdf2native_int16(ldns_rr_rrsig_keytag(rrsig))
	   ) {
		key_buf = ldns_buffer_new(LDNS_MAX_PACKETLEN);
		
		/* before anything, check if the keytags match */

		/* put the key-data in a buffer, that's the third rdf, with
		 * the base64 encoded key data */
		if (ldns_rdf2buffer_wire(key_buf,
				ldns_rr_rdf(key, 3)) != LDNS_STATUS_OK) {
			ldns_rr_list_deep_free(rrset_clone);
			ldns_buffer_free(rawsig_buf);
			ldns_buffer_free(verify_buf);
			/* returning is bad might screw up
			   good keys later in the list
			   what to do? */
			return LDNS_STATUS_ERR;
		}
		
		if (sig_algo == ldns_rdf2native_int8(ldns_rr_rdf(key, 2))) {
			result = ldns_verify_rrsig_buffers(rawsig_buf, verify_buf, key_buf, sig_algo);
		}
		
		ldns_buffer_free(key_buf); 
	}
	 else {
		/* No keys with the corresponding keytag are found */
		result = LDNS_STATUS_CRYPTO_NO_MATCHING_KEYTAG_DNSKEY;
	}
	/* no longer needed */
	ldns_rr_list_deep_free(rrset_clone);
	ldns_buffer_free(rawsig_buf);
	ldns_buffer_free(verify_buf);
	return result;
}

ldns_status
ldns_verify_rrsig_dsa(ldns_buffer *sig, ldns_buffer *rrset, ldns_buffer *key)
{
	DSA *dsakey;
	DSA_SIG *dsasig;
	BIGNUM *R;
	BIGNUM *S;
	uint8_t t;
	int result;

	unsigned char *sha1_hash;

	dsakey = ldns_key_buf2dsa(key);
	if (!dsakey) {
		return LDNS_STATUS_ERR;
	}

	/* extract the R and S field from the sig buffer */
	t = *(ldns_buffer_at(sig, 0));
	R = BN_new();
	(void) BN_bin2bn((unsigned char*)ldns_buffer_at(sig, 1), SHA_DIGEST_LENGTH, R);
	S = BN_new();
	(void) BN_bin2bn((unsigned char*)ldns_buffer_at(sig, 21), SHA_DIGEST_LENGTH, S);

	dsasig = DSA_SIG_new();
	if (!dsasig) {
		return LDNS_STATUS_MEM_ERR;
	}

	dsasig->r = R;
	dsasig->s = S;
	sha1_hash = SHA1((unsigned char*)ldns_buffer_begin(rrset), ldns_buffer_position(rrset), NULL);
	if (!sha1_hash) {
		return LDNS_STATUS_ERR;
	}

	result = DSA_do_verify(sha1_hash, SHA_DIGEST_LENGTH, dsasig, dsakey);

	if (result == 1) {
		return LDNS_STATUS_OK;
	} else {
		dprintf("error in verify: %d\n", result);
		return LDNS_STATUS_CRYPTO_BOGUS;
	}
}

ldns_status
ldns_verify_rrsig_rsasha1(ldns_buffer *sig, ldns_buffer *rrset, ldns_buffer *key)
{
	RSA *rsakey;
	unsigned char *sha1_hash;

	rsakey = ldns_key_buf2rsa(key);
	if (!rsakey) {
		return LDNS_STATUS_ERR;
	}

	sha1_hash = SHA1((unsigned char*)ldns_buffer_begin(rrset), ldns_buffer_position(rrset), NULL);
	if (!sha1_hash) {
		return LDNS_STATUS_ERR;
	}
	
	if (RSA_verify(NID_sha1, sha1_hash, SHA_DIGEST_LENGTH, 
				(unsigned char*)ldns_buffer_begin(sig),
			(unsigned int)ldns_buffer_position(sig), rsakey) == 1) {
		return LDNS_STATUS_OK;
	} else {
		  ERR_load_crypto_strings();
		  ERR_print_errors_fp(stdout);

		return LDNS_STATUS_CRYPTO_BOGUS;
	}
}


ldns_status
ldns_verify_rrsig_rsamd5(ldns_buffer *sig, ldns_buffer *rrset, ldns_buffer *key)
{
	RSA *rsakey;
	unsigned char *md5_hash;

	rsakey = ldns_key_buf2rsa(key);
	if (!rsakey) {
		return LDNS_STATUS_ERR;
	}
	md5_hash = MD5((unsigned char*)ldns_buffer_begin(rrset), 
			(unsigned int)ldns_buffer_position(rrset), NULL);
	if (!md5_hash) {
		return LDNS_STATUS_ERR;
	}
	if (RSA_verify(NID_md5, md5_hash, MD5_DIGEST_LENGTH, 
				(unsigned char*)ldns_buffer_begin(sig),
			(unsigned int)ldns_buffer_position(sig), rsakey) == 1) {
		return LDNS_STATUS_OK;
	} else {
		return LDNS_STATUS_CRYPTO_BOGUS;
	}
	return true;
}

/* some helper functions */
DSA *
ldns_key_buf2dsa(ldns_buffer *key)
{
	uint8_t T;
	uint16_t length;
	uint16_t offset;
	DSA *dsa;
	BIGNUM *Q; BIGNUM *P;
	BIGNUM *G; BIGNUM *Y;

	T = *ldns_buffer_at(key, 0);
	length = (64 + T * 8);
	offset = 1;
	
	if (T > 8) {
		dprintf("%s\n", "DSA type > 8 not implemented, unable to verify signature");
		return NULL;
	}
	
	Q = BN_bin2bn((unsigned char*)ldns_buffer_at(key, offset), SHA_DIGEST_LENGTH, NULL);
	offset += SHA_DIGEST_LENGTH;
	
	P = BN_bin2bn((unsigned char*)ldns_buffer_at(key, offset), (int)length, NULL);
	offset += length;
	
	G = BN_bin2bn((unsigned char*)ldns_buffer_at(key, offset), (int)length, NULL);
	offset += length;
	
	Y = BN_bin2bn((unsigned char*)ldns_buffer_at(key, offset), (int)length, NULL);
	offset += length;
	
	/* create the key and set its properties */
	dsa = DSA_new();
	dsa->p = P;
	dsa->q = Q;
	dsa->g = G;
	dsa->pub_key = Y;

	return dsa;
}

RSA *
ldns_key_buf2rsa(ldns_buffer *key)
{
	uint16_t offset;
	uint16_t exp;
	uint16_t int16;
	RSA *rsa;
	BIGNUM *modulus;
	BIGNUM *exponent;

	if ((*ldns_buffer_at(key, 0)) == 0) {
		/* need some smart comment here XXX*/
		/* the exponent is too large so it's places
		 * futher...???? */
		memcpy(&int16, ldns_buffer_at(key, 1), 2);
		exp = ntohs(int16);
		offset = 3;
	} else {
		exp = *ldns_buffer_at(key, 0);
		offset = 1;
	}
	
	/* Exponent */
	exponent = BN_new();
	(void) BN_bin2bn(
			 (unsigned char*)ldns_buffer_at(key, offset), (int)exp, exponent);
	offset += exp;

	/* Modulus */
	modulus = BN_new();
	/* capicity of the buffer must match the key length! */
	(void) BN_bin2bn((unsigned char*)ldns_buffer_at(key, offset), 
			 (int)(ldns_buffer_position(key) - offset), modulus);

	rsa = RSA_new();
	rsa->n = modulus;
	rsa->e = exponent;

	return rsa;
}

ldns_rr *
ldns_key_rr2ds(const ldns_rr *key, ldns_hash h)
{
        ldns_rdf *tmp;
        ldns_rr *ds;
        uint16_t keytag;
        uint8_t  sha1hash;
        uint8_t *digest;
        ldns_buffer *data_buf;

        if (ldns_rr_get_type(key) != LDNS_RR_TYPE_DNSKEY) {
                return NULL;
        }

        ds = ldns_rr_new();
        if (!ds) {
                return NULL;
        }
	ldns_rr_set_type(ds, LDNS_RR_TYPE_DS);
	ldns_rr_set_owner(ds, ldns_rdf_clone(
				ldns_rr_owner(key)));
	ldns_rr_set_ttl(ds, ldns_rr_ttl(key));
	ldns_rr_set_class(ds, ldns_rr_get_class(key));

	switch(h) {
		default:
		case LDNS_SHA1:
			digest = LDNS_XMALLOC(uint8_t, SHA_DIGEST_LENGTH);
			if (!digest) {
				return NULL;
			}
		break;
		case LDNS_SHA256:
			return NULL; /* not implemented */
		break;
	}

        data_buf = ldns_buffer_new(LDNS_MAX_PACKETLEN);
        if (!data_buf) {
                return NULL;
        }

        /* keytag */
        keytag = htons(ldns_calc_keytag((ldns_rr*)key));
        tmp = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_INT16, sizeof(uint16_t), &keytag);
        ldns_rr_push_rdf(ds, tmp);

        /* copy the algorithm field */
        ldns_rr_push_rdf(ds, ldns_rdf_clone( ldns_rr_rdf(key, 2))); /* second rfd */

        /* digest hash type */
        sha1hash = (uint8_t)h;
        tmp = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_INT8, sizeof(uint8_t), &sha1hash);
        ldns_rr_push_rdf(ds, tmp);

        /* digest */
        /* owner name */
	if (ldns_rdf2buffer_wire(data_buf, ldns_rr_owner(key)) != LDNS_STATUS_OK) {
		return NULL;
	}

        /* all the rdata's */
	if (ldns_rr_rdata2buffer_wire(data_buf, (ldns_rr*)key) != LDNS_STATUS_OK) { 
		return NULL;
	}
	switch(h) {
		case LDNS_SHA1:
		(void) SHA1((unsigned char *) ldns_buffer_begin(data_buf),
			    ldns_buffer_position(data_buf),
			    (unsigned char*) digest);

		tmp = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_HEX, SHA_DIGEST_LENGTH,
				digest);
		ldns_rr_push_rdf(ds, tmp);

		break;
		case LDNS_SHA256:
		break;
	}

        return ds;
}

/*
 * use this function to sign with a public/private key alg
 * return the created signatures
 */
ldns_rr_list *
ldns_sign_public(ldns_rr_list *rrset, ldns_key_list *keys)
{
	ldns_rr_list *signatures;
	ldns_rr_list *rrset_clone;
	ldns_rr *current_sig;
	ldns_rdf *b64rdf;
	ldns_key *current_key;
	size_t key_count;
	uint16_t i;
	ldns_buffer *sign_buf;
	uint32_t orig_ttl;
	time_t now;
	uint8_t label_count;
	ldns_rdf *first_label;
	ldns_rdf *wildcard_label;
	ldns_rdf *new_owner;

	if (!rrset || ldns_rr_list_rr_count(rrset) < 1 || !keys) {
		return NULL;
	}

	key_count = 0;
	signatures = ldns_rr_list_new();

	/* prepare a signature and add all the know data
	 * prepare the rrset. Sign this together.  */
	rrset_clone = ldns_rr_list_clone(rrset);
	if (!rrset_clone) {
		return NULL;
	}

	/* check for label count and wildcard */
	label_count = ldns_dname_label_count(ldns_rr_owner(ldns_rr_list_rr(rrset, 0)));
	(void) ldns_str2rdf_dname(&wildcard_label, "*");
	first_label = ldns_dname_label(ldns_rr_owner(ldns_rr_list_rr(rrset, 0)), 0);
	if (ldns_rdf_compare(first_label, wildcard_label) == 0) {
		label_count--;
		for (i = 0; i < ldns_rr_list_rr_count(rrset_clone); i++) {
			new_owner = ldns_dname_cat_clone(wildcard_label, 
					ldns_dname_left_chop(ldns_rr_owner(ldns_rr_list_rr(rrset_clone, i))));
			ldns_rr_set_owner(ldns_rr_list_rr(rrset_clone, i), new_owner);
		}
	}

	/* make it canonical */
	for(i = 0; i < ldns_rr_list_rr_count(rrset_clone); i++) {
		ldns_rr2canonical(ldns_rr_list_rr(rrset_clone, i));
	}
	/* sort */
	ldns_rr_list_sort(rrset_clone);
	
	for (key_count = 0; key_count < ldns_key_list_key_count(keys); key_count++) {

		sign_buf = ldns_buffer_new(LDNS_MAX_PACKETLEN);
		b64rdf = NULL;

		current_key = ldns_key_list_key(keys, key_count);
		if (
			ldns_key_flags(current_key) & LDNS_KEY_ZONE_KEY &&
			(!(ldns_key_flags(current_key) & LDNS_KEY_SEP_KEY) ||
			ldns_rr_get_type(ldns_rr_list_rr(rrset, 0)) == LDNS_RR_TYPE_DNSKEY)
		   ) {
			current_sig = ldns_rr_new_frm_type(LDNS_RR_TYPE_RRSIG);
			
			/* set the type on the new signature */
			orig_ttl = ldns_rr_ttl(ldns_rr_list_rr(rrset, 0));

			ldns_rr_set_ttl(current_sig, orig_ttl);
			ldns_rr_set_owner(current_sig, 
					ldns_rdf_clone(ldns_rr_owner(ldns_rr_list_rr(rrset_clone, 0))));

			/* fill in what we know of the signature */

			/* set the orig_ttl */
			(void)ldns_rr_rrsig_set_origttl(current_sig, 
					ldns_native2rdf_int32(LDNS_RDF_TYPE_INT32, orig_ttl));
			/* the signers name */

			(void)ldns_rr_rrsig_set_signame(current_sig, 
					ldns_rdf_clone(ldns_key_pubkey_owner(current_key)));
			/* label count - get it from the first rr in the rr_list */
			(void)ldns_rr_rrsig_set_labels(current_sig, 
					ldns_native2rdf_int8(LDNS_RDF_TYPE_INT8, label_count));
			/* inception, expiration */
			now = time(NULL);
			if (ldns_key_inception(current_key) != 0) {
				(void)ldns_rr_rrsig_set_inception(current_sig,
						ldns_native2rdf_int32(LDNS_RDF_TYPE_TIME, 
							ldns_key_inception(current_key)));
			} else {
				(void)ldns_rr_rrsig_set_inception(current_sig,
						ldns_native2rdf_int32(LDNS_RDF_TYPE_TIME, now));
			}
			if (ldns_key_expiration(current_key) != 0) {
				(void)ldns_rr_rrsig_set_expiration(current_sig,
						ldns_native2rdf_int32(LDNS_RDF_TYPE_TIME, 
							ldns_key_expiration(current_key)));
			} else {
				(void)ldns_rr_rrsig_set_expiration(current_sig,
						ldns_native2rdf_int32(LDNS_RDF_TYPE_TIME, 
							now + LDNS_DEFAULT_EXP_TIME));
			}

			/* key-tag */
			(void)ldns_rr_rrsig_set_keytag(current_sig,
					ldns_native2rdf_int16(LDNS_RDF_TYPE_INT16, 
						ldns_key_keytag(current_key)));

			/* algorithm - check the key and substitute that */
			(void)ldns_rr_rrsig_set_algorithm(current_sig,
					ldns_native2rdf_int8(LDNS_RDF_TYPE_ALG, 
						ldns_key_algorithm(current_key)));
			/* type-covered */
			(void)ldns_rr_rrsig_set_typecovered(current_sig,
					ldns_native2rdf_int16(LDNS_RDF_TYPE_TYPE,
						ldns_rr_get_type(ldns_rr_list_rr(rrset_clone, 0))));
			/* right now, we have: a key, a semi-sig and an rrset. For
			 * which we can create the sig and base64 encode that and
			 * add that to the signature */
			
			if (ldns_rrsig2buffer_wire(sign_buf, current_sig) != LDNS_STATUS_OK) {
				ldns_buffer_free(sign_buf);
				dprintf("%s\n", "couldn't convert to buffer 1");
				/* ERROR */
				return NULL;
			}
			/* add the rrset in sign_buf */

			if (ldns_rr_list2buffer_wire(sign_buf, rrset_clone) != LDNS_STATUS_OK) {
				dprintf("%s\n", "couldn't convert to buffer 2");
				ldns_buffer_free(sign_buf);
				return NULL;
			}
			
			switch(ldns_key_algorithm(current_key)) {
				case LDNS_SIGN_DSA:
					b64rdf = ldns_sign_public_dsa(sign_buf, ldns_key_dsa_key(current_key));
					break;
				case LDNS_SIGN_RSASHA1:
					b64rdf = ldns_sign_public_rsasha1(sign_buf, ldns_key_rsa_key(current_key));
					break;
				case LDNS_SIGN_RSAMD5:
					b64rdf = ldns_sign_public_rsamd5(sign_buf, ldns_key_rsa_key(current_key));
					break;
				default:
					/* do _you_ know this alg? */
					break;
			}
			if (!b64rdf) {
				/* signing went wrong */
				dprintf("%s", "couldn't sign!\n");
				return NULL;
			}
			ldns_rr_rrsig_set_sig(current_sig, b64rdf);

			/* push the signature to the signatures list */
			ldns_rr_list_push_rr(signatures, current_sig);
		}
		ldns_buffer_free(sign_buf); /* restart for the next key */
        }
        ldns_rr_list_deep_free(rrset_clone);

	return signatures;
}

ldns_rdf *
ldns_sign_public_dsa(ldns_buffer *to_sign, DSA *key)
{
	unsigned char *sha1_hash;
	ldns_rdf *sigdata_rdf;
	ldns_buffer *b64sig;

	DSA_SIG *sig;
	uint8_t *data;
	size_t pad;

	b64sig = ldns_buffer_new(LDNS_MAX_PACKETLEN);
	if (!b64sig) {
		return NULL;
	}
	
	sha1_hash = SHA1((unsigned char*)ldns_buffer_begin(to_sign),
			ldns_buffer_position(to_sign), NULL);
	if (!sha1_hash) {
		ldns_buffer_free(b64sig);
		return NULL;
	}


	sig = DSA_do_sign(sha1_hash, SHA_DIGEST_LENGTH, key);

	data = LDNS_XMALLOC(uint8_t, 1 + 2 * SHA_DIGEST_LENGTH);

	data[0] = 1;
	pad = 20 - (size_t) BN_num_bytes(sig->r);
	if (pad > 0) {
		memset(data + 1, 0, pad);
	}
	BN_bn2bin(sig->r, (unsigned char *) (data + 1) + pad);

	pad = 20 - (size_t) BN_num_bytes(sig->s);
	if (pad > 0) {
		memset(data + 1 + SHA_DIGEST_LENGTH, 0, pad);
	}
	BN_bn2bin(sig->s, (unsigned char *) (data + 1 + SHA_DIGEST_LENGTH + pad));

	sigdata_rdf = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_B64,  1 + 2 * SHA_DIGEST_LENGTH, data);

	ldns_buffer_free(b64sig);
	LDNS_FREE(data);

	return sigdata_rdf;
}

ldns_rdf *
ldns_sign_public_rsasha1(ldns_buffer *to_sign, RSA *key)
{
	unsigned char *sha1_hash;
	unsigned int siglen;
	ldns_rdf *sigdata_rdf;
	ldns_buffer *b64sig;

	siglen = 0;
	b64sig = ldns_buffer_new(LDNS_MAX_PACKETLEN);
	if (!b64sig) {
		return NULL;
	}

	sha1_hash = SHA1((unsigned char*)ldns_buffer_begin(to_sign),
			ldns_buffer_position(to_sign), NULL);
	if (!sha1_hash) {
		ldns_buffer_free(b64sig);
		return NULL;
	}

	RSA_sign(NID_sha1, sha1_hash, SHA_DIGEST_LENGTH,
			(unsigned char*)ldns_buffer_begin(b64sig),
			&siglen, key);
	sigdata_rdf = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_B64, siglen, 
			ldns_buffer_begin(b64sig));
	ldns_buffer_free(b64sig); /* can't free this buffer ?? */
	return sigdata_rdf;
}

ldns_rdf *
ldns_sign_public_rsamd5(ldns_buffer *to_sign, RSA *key)
{
	unsigned char *md5_hash;
	unsigned int siglen;
	ldns_rdf *sigdata_rdf;
	ldns_buffer *b64sig;

	b64sig = ldns_buffer_new(LDNS_MAX_PACKETLEN);
	if (!b64sig) {
		return NULL;
	}
	
	md5_hash = MD5((unsigned char*)ldns_buffer_begin(to_sign),
			ldns_buffer_position(to_sign), NULL);
	if (!md5_hash) {
		ldns_buffer_free(b64sig);
		return NULL;
	}

	RSA_sign(NID_md5, md5_hash, MD5_DIGEST_LENGTH,
			(unsigned char*)ldns_buffer_begin(b64sig),
			&siglen, key);

	sigdata_rdf = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_B64, siglen, 
			ldns_buffer_begin(b64sig));
	ldns_buffer_free(b64sig);
	return sigdata_rdf;
}

ldns_rr *
ldns_create_nsec(ldns_rdf *cur_owner, ldns_rdf *next_owner, ldns_rr_list *rrs)
{
	/* we do not do any check here - garbage in, garbage out */
	
	/* the the start and end names - get the type from the
	 * before rrlist */

	/* we don't have an nsec encoder... :( */

	/* inefficient, just give it a name, a next name, and a list of rrs */
	/* we make 1 big uberbitmap first, then windows */
	/* todo: make something more efficient :) */
	uint16_t i;
	ldns_rr *i_rr;

	uint8_t *bitmap = LDNS_XMALLOC(uint8_t, 1);
	uint16_t bm_len = 0;
	uint16_t i_type;

	ldns_rr *nsec = NULL;

	uint8_t *data = NULL;
	uint8_t cur_data[32];
	uint8_t cur_window = 0;
	uint8_t cur_window_max = 0;
	uint16_t cur_data_size = 0;

	nsec = ldns_rr_new();
	ldns_rr_set_type(nsec, LDNS_RR_TYPE_NSEC);
	ldns_rr_set_owner(nsec, ldns_rdf_clone(cur_owner));
	/* TODO: TTL jelte? */
	ldns_rr_push_rdf(nsec, ldns_rdf_clone(next_owner));

	bitmap[0] = 0;
	for (i = 0; i < ldns_rr_list_rr_count(rrs); i++) {
		i_rr = ldns_rr_list_rr(rrs, i);

		if (ldns_rdf_compare(cur_owner,
		                     ldns_rr_owner(i_rr)) == 0) {
			/* add type to bitmap */
			i_type = ldns_rr_get_type(i_rr);
			if ((i_type / 8) + 1 > bm_len) {
				bitmap = LDNS_XREALLOC(bitmap, uint8_t, (i_type / 8) + 1);
				/* set to 0 */
				for (; bm_len <= i_type / 8; bm_len++) {
					bitmap[bm_len] = 0;
				}
			}
			ldns_set_bit(bitmap + (int) i_type / 8, (int) (7 - (i_type % 8)), true);
		}
	}
	/* add NSEC and RRSIG anyway */
	i_type = LDNS_RR_TYPE_RRSIG;
	if (i_type / 8 > bm_len) {
		bitmap = LDNS_XREALLOC(bitmap, uint8_t, (i_type / 8) + 1);
		/* set to 0 */
		for (; bm_len <= i_type / 8; bm_len++) {
			bitmap[bm_len] = 0;
		}
	}
	ldns_set_bit(bitmap + (int) i_type / 8, (int) (7 - (i_type % 8)), true);
	i_type = LDNS_RR_TYPE_NSEC;

	if (i_type / 8 > bm_len) {
		bitmap = LDNS_XREALLOC(bitmap, uint8_t, (i_type / 8) + 1);
		/* set to 0 */
		for (; bm_len <= i_type / 8; bm_len++) {
			bitmap[bm_len] = 0;
		}
	}
	ldns_set_bit(bitmap + (int) i_type / 8, (int) (7 - (i_type % 8)), true);

	memset(cur_data, 0, 32);
	for (i = 0; i < bm_len; i++) {
		if (i / 32 > cur_window) {
			/* check, copy, new */
			if (cur_window_max > 0) {
				/* this window has stuff, add it */
				data = LDNS_XREALLOC(data, uint8_t, cur_data_size + cur_window_max + 3);
				data[cur_data_size] = cur_window;
				data[cur_data_size + 1] = cur_window_max + 1;
				memcpy(data + cur_data_size + 2, cur_data, cur_window_max+1);
				cur_data_size += cur_window_max + 3;
			}
			cur_window++;
			cur_window_max = 0;
			memset(cur_data, 0, 32);
		} else {
			cur_data[i%32] = bitmap[i];
			if (bitmap[i] > 0) {
				cur_window_max = i%32;
			}
		}
	}
	if (cur_window_max > 0) {
		/* this window has stuff, add it */
		data = LDNS_XREALLOC(data, uint8_t, cur_data_size + cur_window_max + 3);
		data[cur_data_size] = cur_window;
		data[cur_data_size + 1] = cur_window_max + 1;
		memcpy(data + cur_data_size + 2, cur_data, cur_window_max+1);
		cur_data_size += cur_window_max + 3;
	}

	ldns_rr_push_rdf(nsec, ldns_rdf_new_frm_data(LDNS_RDF_TYPE_NSEC, cur_data_size, data));

	LDNS_FREE(bitmap);
	LDNS_FREE(data);
	return nsec;
}

ldns_rdf *
ldns_nsec3_hash_name(ldns_rdf *name, uint8_t algorithm, uint32_t iterations, uint8_t salt_length, uint8_t *salt)
{
	char *orig_owner_str;
	size_t hashed_owner_str_len;
	ldns_rdf *hashed_owner;
	char *hashed_owner_str;
	char *hashed_owner_b32;
	uint32_t cur_it;
	char *hash = NULL;
	size_t i;
	ldns_status status;
	
	/* prepare the owner name according to the draft section bla */
	orig_owner_str = ldns_rdf2str(name);
	
	/* TODO: mnemonic list for hash algs SHA-1, default to 1 now (sha1) */
	if (iterations > 16777216 || iterations < 1) {
		perror("Bad number for NSEC3 hash iterations");
		return NULL;
	}
	
	hashed_owner_str_len = salt_length + ldns_rdf_size(name);
	hashed_owner_str = LDNS_XMALLOC(char, hashed_owner_str_len);
        memcpy(hashed_owner_str, ldns_rdf_data(name), ldns_rdf_size(name));
	memcpy(hashed_owner_str + ldns_rdf_size(name), salt, salt_length);

	for (cur_it = iterations + 1; cur_it > 0; cur_it--) {
		/*xprintf_hex(hashed_owner_str, hashed_owner_str_len);*/
		hash = (char *) SHA1((unsigned char *) hashed_owner_str, hashed_owner_str_len, NULL);

		LDNS_FREE(hashed_owner_str);
		hashed_owner_str_len = salt_length + SHA_DIGEST_LENGTH;
		hashed_owner_str = LDNS_XMALLOC(char, hashed_owner_str_len);
		if (!hashed_owner_str) {
			fprintf(stderr, "Memory error\n");
			abort();
		}
		memcpy(hashed_owner_str, hash, SHA_DIGEST_LENGTH);
		memcpy(hashed_owner_str + SHA_DIGEST_LENGTH, salt, salt_length);
		hashed_owner_str_len = SHA_DIGEST_LENGTH + salt_length;
	}

	hashed_owner_str = hash;
	hashed_owner_str_len = SHA_DIGEST_LENGTH;

/*
printf("Created hash from: ");
ldns_rdf_print(stdout, name);
printf(":\n");
xprintf_hex(hashed_owner_str, hashed_owner_str_len);
printf("\n\n");
exit(0);
*/
	hashed_owner_b32 = LDNS_XMALLOC(char, b32_ntop_calculate_size(hashed_owner_str_len));
	i = (size_t) b32_ntop_extended_hex((uint8_t *) hashed_owner_str, hashed_owner_str_len, hashed_owner_b32, b32_ntop_calculate_size(hashed_owner_str_len));
	if (i < 1) {
		fprintf(stderr, "Error in base32 extended hex encoding of hashed owner name (name: ");
		ldns_rdf_print(stderr, name);
		fprintf(stderr, ", return code: %u)\n", (unsigned int) i);
		exit(4);
	}
	hashed_owner_str_len = i;
        hashed_owner_b32[hashed_owner_str_len] = '\0';
	status = ldns_str2rdf_dname(&hashed_owner, hashed_owner_b32);
	if (status != LDNS_STATUS_OK) {
		fprintf(stderr, "Error creating rdf from %s\n", hashed_owner_b32);
		exit(1);
	}

printf("RETURNING TYPE: %d\n", ldns_rdf_get_type(hashed_owner));
	return hashed_owner;
}

/* this will NOT return the NSEC3  completed, you will have to run the
   finalize function on the rrlist later! */
ldns_rr *
ldns_create_nsec3(ldns_rdf *cur_owner,
                  ldns_rdf *cur_zone,
                  ldns_rr_list *rrs,
                  uint8_t algorithm,
                  bool opt_in,
                  uint32_t iterations,
                  uint8_t salt_length,
                  uint8_t *salt)
{
	size_t i;
	ldns_rr *i_rr;

	uint8_t *bitmap = LDNS_XMALLOC(uint8_t, 1);
	uint16_t bm_len = 0;
	uint16_t i_type;

	ldns_rr *nsec = NULL;
	ldns_rdf *hashed_owner = NULL;

	uint8_t iterations_data[4];
	
	uint8_t *data = NULL;
	uint8_t cur_data[32];
	uint8_t cur_window = 0;
	uint8_t cur_window_max = 0;
	uint16_t cur_data_size = 0;

	uint8_t *nsec3_vars_data;
	ldns_rdf *nsec3_vars_rdf;
	
	ldns_status status;
	
        /*
        printf("HASH FOR: ");
        ldns_rdf_print(stdout, cur_owner);
        */
	
	/*
	printf("\n");
	for (i=0; i<hashed_owner_str_len; i++) {
		printf("%02x ", (uint8_t) hashed_owner_str[i]);
	}
	printf("\n");
	*/
	nsec3_vars_data = LDNS_XMALLOC(uint8_t, 5 + salt_length);
	nsec3_vars_data[0] = algorithm;
	if (opt_in) {
		nsec3_vars_data[0] &= 0xff;
	} else {
		nsec3_vars_data[0] &= 0x7f;
	}
	
	ldns_write_uint32(&iterations_data, iterations);
	memcpy(&nsec3_vars_data[1], &iterations_data[1], 3);
	nsec3_vars_data[4] = salt_length;
	if (salt_length > 0) {
		memcpy(&nsec3_vars_data[5], salt, salt_length);
	}
	nsec3_vars_rdf = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_NSEC3_VARS, 5 + salt_length, nsec3_vars_data);
	
	hashed_owner = ldns_nsec3_hash_name(cur_owner, algorithm, iterations, salt_length, salt);
	status = ldns_dname_cat(hashed_owner, cur_zone);

	nsec = ldns_rr_new();
	ldns_rr_set_type(nsec, LDNS_RR_TYPE_NSEC3);
	ldns_rr_set_owner(nsec, hashed_owner);
	/* TODO: TTL? */
	ldns_rr_push_rdf(nsec, nsec3_vars_rdf);
	ldns_rr_push_rdf(nsec, NULL);

	bitmap[0] = 0;
	for (i = 0; i < ldns_rr_list_rr_count(rrs); i++) {
		i_rr = ldns_rr_list_rr(rrs, i);

		if (ldns_rdf_compare(cur_owner,
		                     ldns_rr_owner(i_rr)) == 0) {
			/* add type to bitmap */
			i_type = ldns_rr_get_type(i_rr);
			if ((i_type / 8) + 1 > bm_len) {
				bitmap = LDNS_XREALLOC(bitmap, uint8_t, (i_type / 8) + 1);
				/* set to 0 */
				for (; bm_len <= i_type / 8; bm_len++) {
					bitmap[bm_len] = 0;
				}
			}
			ldns_set_bit(bitmap + (int) i_type / 8, (int) (7 - (i_type % 8)), true);
		}
	}
	/* add NSEC and RRSIG anyway */
	i_type = LDNS_RR_TYPE_RRSIG;
	if (i_type / 8 > bm_len) {
		bitmap = LDNS_XREALLOC(bitmap, uint8_t, (i_type / 8) + 1);
		/* set to 0 */
		for (; bm_len <= i_type / 8; bm_len++) {
			bitmap[bm_len] = 0;
		}
	}
	ldns_set_bit(bitmap + (int) i_type / 8, (int) (7 - (i_type % 8)), true);
	i_type = LDNS_RR_TYPE_NSEC3;

	if (i_type / 8 > bm_len) {
		bitmap = LDNS_XREALLOC(bitmap, uint8_t, (i_type / 8) + 1);
		/* set to 0 */
		for (; bm_len <= i_type / 8; bm_len++) {
			bitmap[bm_len] = 0;
		}
	}
	ldns_set_bit(bitmap + (int) i_type / 8, (int) (7 - (i_type % 8)), true);

	memset(cur_data, 0, 32);
	for (i = 0; i < bm_len; i++) {
		if (i / 32 > cur_window) {
			/* check, copy, new */
			if (cur_window_max > 0) {
				/* this window has stuff, add it */
				data = LDNS_XREALLOC(data, uint8_t, cur_data_size + cur_window_max + 3);
				data[cur_data_size] = cur_window;
				data[cur_data_size + 1] = cur_window_max + 1;
				memcpy(data + cur_data_size + 2, cur_data, cur_window_max+1);
				cur_data_size += cur_window_max + 3;
			}
			cur_window++;
			cur_window_max = 0;
			memset(cur_data, 0, 32);
		} else {
			cur_data[i%32] = bitmap[i];
			if (bitmap[i] > 0) {
				cur_window_max = i%32;
			}
		}
	}
	if (cur_window_max > 0) {
		/* this window has stuff, add it */
		data = LDNS_XREALLOC(data, uint8_t, cur_data_size + cur_window_max + 3);
		data[cur_data_size] = cur_window;
		data[cur_data_size + 1] = cur_window_max + 1;
		memcpy(data + cur_data_size + 2, cur_data, cur_window_max+1);
		cur_data_size += cur_window_max + 3;
	}

	ldns_rr_push_rdf(nsec, ldns_rdf_new_frm_data(LDNS_RDF_TYPE_NSEC, cur_data_size, data));

	LDNS_FREE(bitmap);
	LDNS_FREE(data);
	return nsec;
}

bool
ldns_nsec3_covers_name(const ldns_rr *nsec, ldns_rdf *name)
{
	uint8_t algorithm;
	uint32_t iterations;
	uint8_t iterations_wire[4];
	
	uint8_t *data;

	uint8_t salt_length;
	uint8_t *salt;
	
	ldns_status status;
	
	bool result;
	
	ldns_rdf *hashed_owner;
	ldns_rdf *nsec_owner = ldns_rr_owner(nsec);
	ldns_rdf *nsec_next = ldns_rr_rdf(nsec, 1);
	ldns_rdf *zone_name = ldns_dname_left_chop(nsec_owner);
	
	status = ldns_dname_cat(nsec_next, zone_name);
	if (status != LDNS_STATUS_OK) {
		return false;
	}
	
	data = ldns_rdf_data(ldns_rr_rdf(nsec, 0));
	algorithm = data[0];
	iterations_wire[0] = 0;
	iterations_wire[1] = data[2];
	iterations_wire[2] = data[3];
	iterations_wire[3] = data[4];
	
	iterations = ldns_read_uint32(iterations_wire);
	
	salt_length = data[5];
	salt = LDNS_XMALLOC(uint8_t, salt_length);
	memcpy(salt, &data[6], salt_length);
	
	hashed_owner = ldns_nsec3_hash_name(name, algorithm, iterations, salt_length, salt);
	

	result = (ldns_dname_compare(nsec_owner, name) <= 0 &&
	    ldns_dname_compare(name, nsec_next) > 0);
	
	LDNS_FREE(salt);
	return result;
}

ldns_rdf *
ldns_nsec3_hash_name_frm_nsec3(const ldns_rr *nsec, ldns_rdf *name)
{
	uint8_t algorithm;
	uint32_t iterations;
	uint8_t iterations_wire[4];
	
	uint8_t *data;

	uint8_t salt_length;
	uint8_t *salt;
	
	ldns_rdf *hashed_owner;
	ldns_rdf *nsec_owner = ldns_rr_owner(nsec);
	
	data = ldns_rdf_data(ldns_rr_rdf(nsec, 0));
	algorithm = data[0];
	iterations_wire[0] = 0;
	iterations_wire[1] = data[2];
	iterations_wire[2] = data[3];
	iterations_wire[3] = data[4];
	
	iterations = ldns_read_uint32(iterations_wire);
	
	salt_length = data[5];
	salt = LDNS_XMALLOC(uint8_t, salt_length);
	memcpy(salt, &data[6], salt_length);
	
	hashed_owner = ldns_nsec3_hash_name(name, algorithm, iterations, salt_length, salt);
	
	LDNS_FREE(salt);
	return hashed_owner;
}

bool
ldns_nsec_bitmap_covers_type(const ldns_rdf *nsec_bitmap, ldns_rr_type type)
{
	uint8_t *bitmap;
	uint16_t i;
	uint8_t window_block_nr;
	
	/* Check the bitmap if our type is there */
	bitmap = ldns_rdf_data(nsec_bitmap);
	window_block_nr = (uint8_t) (type / 256);
	i = 0;
	while (i < ldns_rdf_size(nsec_bitmap)) {
		if (bitmap[i] == window_block_nr) {
			/* this is the right window, check the bit */
			if ((uint8_t) (type / 8) < bitmap[i + 1] &&
			    ldns_get_bit(&bitmap[i + 1 + (type / 8)], (size_t) (7 - (type % 8)))) {
				return true;
			} else {
				return false;
			}
		} else {
			/* this is the wrong window, go to the next */
			i++;
			i += bitmap[i];
		}
	}

	return false;
}

bool
ldns_nsec_covers_name(const ldns_rr *nsec, ldns_rdf *name)
{
	ldns_rdf *nsec_owner = ldns_rr_owner(nsec);
	ldns_rdf *hash_next;
	char *yo;
	ldns_rdf *nsec_next;
	ldns_status status;

	if (ldns_rr_get_type(nsec) == LDNS_RR_TYPE_NSEC) {
		nsec_next = ldns_rr_rdf(nsec, 0);
	} else if (ldns_rr_get_type(nsec) == LDNS_RR_TYPE_NSEC3) {
		hash_next = ldns_rr_rdf(nsec, 1);
		yo = ldns_rdf2str(hash_next);
		nsec_next = ldns_dname_new_frm_str(yo);
		status = ldns_dname_cat(nsec_next, ldns_dname_left_chop(nsec_owner));
		if (status != LDNS_STATUS_OK) {
			printf("error catting: %s\n", ldns_get_errorstr_by_id(status));
		}
	} else {
		return false;
	}
	
/*
printf("nsec coverage:\n");
ldns_rdf_print(stdout, nsec_owner);
printf(" <= \n");
ldns_rdf_print(stdout, name);
printf(" <  \n");
ldns_rdf_print(stdout, nsec_next);
printf("\n\n");
*/
	return (ldns_dname_compare(nsec_owner, name) <= 0 &&
	    ldns_dname_compare(name, nsec_next) > 0);
}

/* sig may be null - if so look in the packet */
ldns_status
ldns_pkt_verify(ldns_pkt *p, ldns_rr_type t, ldns_rdf *o, 
		ldns_rr_list *k, ldns_rr_list *s, ldns_rr_list *good_keys)
{
	ldns_rr_list *rrset;
	ldns_rr_list *sigs;
	ldns_rr_list *sigs_covered;
	ldns_rdf *rdf_t;
	ldns_rr_type t_netorder;

	if (!k) {
		return LDNS_STATUS_ERR;
		/* return LDNS_STATUS_CRYPTO_NO_DNSKEY; */
	}

	if (t == LDNS_RR_TYPE_RRSIG) {
		/* we don't have RRSIG(RRSIG) (yet? ;-) ) */
		/* return LDNS_STATUS_ERR; */
		return LDNS_STATUS_ERR;
	}
	
	if (s) {
		/* if s is not NULL, the sigs are given to use */
		sigs = s;
	} else {
		/* otherwise get them from the packet */
		sigs = ldns_pkt_rr_list_by_name_and_type(p, o, LDNS_RR_TYPE_RRSIG, 
				LDNS_SECTION_ANY_NOQUESTION);
		if (!sigs) {
			/* no sigs */
			return LDNS_STATUS_ERR;
			/* return LDNS_STATUS_CRYPTO_NO_RRSIG; */
		}
	}

	/* *sigh* rrsig are subtyped, so now we need to find the correct
	 * sigs for the type t
	 */
	t_netorder = htons(t); /* rdf are in network order! */
	rdf_t = ldns_rdf_new(LDNS_RDF_TYPE_TYPE, sizeof(ldns_rr_type), &t_netorder);
	sigs_covered = ldns_rr_list_subtype_by_rdf(sigs, rdf_t, 0);
	
	rrset = ldns_pkt_rr_list_by_name_and_type(p, o, t, LDNS_SECTION_ANY_NOQUESTION);

	if (!rrset) {
		return LDNS_STATUS_ERR;
	}

	if (!sigs_covered) {
		return LDNS_STATUS_ERR;
	}

	return ldns_verify(rrset, sigs, k, good_keys);
}

ldns_zone *
ldns_zone_sign(ldns_zone *zone, ldns_key_list *key_list)
{
	/*
	 * Algorithm to be created:
	 * - sort the rrs (name/class/type?)
	 * - if sorted, every next rr is belongs either to the rrset
	 * you are working on, or the rrset is complete
	 * for each rrset, calculate rrsig and nsec
	 * put the rrset, rrsig and nsec in the new zone
	 * done!
	 * ow and don't sign old rrsigs etc.
	 */
	
	ldns_zone *signed_zone;
	ldns_rr_list *cur_rrset;
	ldns_rr_list *soa_rrset;
	ldns_rr_list *cur_rrsigs;
	ldns_rr_list *orig_zone_rrs;
	ldns_rr_list *signed_zone_rrs;
	ldns_rr_list *pubkeys;
	ldns_rr_list *glue_rrs;
	
	ldns_rdf *start_dname = NULL;
	ldns_rdf *cur_dname = NULL;
	ldns_rr *next_rr = NULL;
	ldns_rdf *next_dname = NULL;
	ldns_rr *nsec;
	ldns_rr *ckey;
	uint16_t i;
	ldns_rr_type cur_rrset_type;
	
	signed_zone = ldns_zone_new();
	
	/* there should only be 1 SOA, so the soa record is 1 rrset */
	soa_rrset = ldns_rr_list_new();
	ldns_rr_list_push_rr(soa_rrset, ldns_zone_soa(zone));
	cur_rrsigs = ldns_sign_public(soa_rrset, key_list);
	cur_dname = ldns_rr_owner(ldns_rr_list_rr(soa_rrset, 0));
	ldns_rr_list_free(soa_rrset);

	ldns_zone_set_soa(signed_zone, ldns_rr_clone(ldns_zone_soa(zone)));
	ldns_zone_push_rr_list(signed_zone, cur_rrsigs);
	ldns_rr_list_free(cur_rrsigs);
	
	orig_zone_rrs = ldns_rr_list_clone(ldns_zone_rrs(zone));

	glue_rrs = ldns_zone_glue_rr_list(zone);

	/* add the key (TODO: check if it's there already? */
	pubkeys = ldns_rr_list_new();
	for (i = 0; i < ldns_key_list_key_count(key_list); i++) {
		ckey = ldns_key2rr(ldns_key_list_key(key_list, i));
		ldns_rr_list_push_rr(pubkeys, ckey);
	}
	signed_zone_rrs = ldns_rr_list_new();

	ldns_rr_list_sort(orig_zone_rrs);
	
	/* add nsecs */
	for (i = 0; i < ldns_rr_list_rr_count(orig_zone_rrs); i++) {
		if (!start_dname) {
			/*start_dname = ldns_rr_owner(ldns_zone_soa(zone));*/
			start_dname = ldns_rr_owner(ldns_rr_list_rr(orig_zone_rrs, i));
			cur_dname = start_dname;
		} else {
			next_rr = ldns_rr_list_rr(orig_zone_rrs, i);
			next_dname = ldns_rr_owner(next_rr);
			if (ldns_rdf_compare(cur_dname, next_dname) != 0) {
				/* skip glue */
				if (ldns_rr_list_contains_rr(glue_rrs, next_rr)) {
					cur_dname = next_dname;
				} else {
					nsec = ldns_create_nsec(cur_dname, 
								next_dname,
								orig_zone_rrs);
					ldns_rr_set_ttl(nsec, ldns_rdf2native_int32(ldns_rr_rdf(ldns_zone_soa(zone), 6)));
					ldns_rr_list_push_rr(signed_zone_rrs, nsec);
					/*start_dname = next_dname;*/
					cur_dname = next_dname;
				}
			}
		}
		ldns_rr_list_push_rr(signed_zone_rrs, ldns_rr_list_rr(orig_zone_rrs, i));
	}
	nsec = ldns_create_nsec(cur_dname, 
				start_dname,
				orig_zone_rrs);
	ldns_rr_list_push_rr(signed_zone_rrs, nsec);
	ldns_rr_list_free(orig_zone_rrs);
	ldns_rr_set_ttl(nsec, ldns_rdf2native_int32(ldns_rr_rdf(ldns_zone_soa(zone), 6)));

	/* Sign all rrsets in the zone */
	cur_rrset = ldns_rr_list_pop_rrset(signed_zone_rrs);
	while (cur_rrset) {
		/* don't sign certain types */
		cur_rrset_type = ldns_rr_get_type(ldns_rr_list_rr(cur_rrset, 0));
		cur_dname = ldns_rr_owner(ldns_rr_list_rr(cur_rrset, 0));

		/* if we have KSKs, use them for DNSKEYS, otherwise
		   make them selfsigned (?) */
                /* don't sign sigs, delegations, and glue */
		if (cur_rrset_type != LDNS_RR_TYPE_RRSIG &&
		    ((ldns_dname_is_subdomain(cur_dname, ldns_rr_owner(ldns_zone_soa(zone)))
                      && cur_rrset_type != LDNS_RR_TYPE_NS
                     ) ||
		     ldns_rdf_compare(cur_dname, ldns_rr_owner(ldns_zone_soa(zone))) == 0
		    ) &&
		    !(ldns_rr_list_contains_rr(glue_rrs, ldns_rr_list_rr(cur_rrset, 0)))
		   ) {
			cur_rrsigs = ldns_sign_public(cur_rrset, key_list);

			/* TODO: make optional, replace exit call */
			/* if not optional it should be left out completely
			   (for it is possible to generate bad signarures, by
			   specifying a future inception date */
			
			ldns_zone_push_rr_list(signed_zone, cur_rrset);
			ldns_zone_push_rr_list(signed_zone, cur_rrsigs);
			ldns_rr_list_free(cur_rrsigs);
		} else {
			/* push it unsigned (glue, sigs, delegations) */
			ldns_zone_push_rr_list(signed_zone, cur_rrset);
		}
		ldns_rr_list_free(cur_rrset);
		cur_rrset = ldns_rr_list_pop_rrset(signed_zone_rrs);
	}
	ldns_rr_list_free(signed_zone_rrs);
	ldns_rr_list_free(pubkeys);
	return signed_zone;
	
}

static int
qsort_rr_compare_nsec3(const void *a, const void *b)
{
	const ldns_rr *rr1 = * (const ldns_rr **) a;
	const ldns_rr *rr2 = * (const ldns_rr **) b;
	if (rr1 == NULL && rr2 == NULL) {
		return 0;
	}
	if (rr1 == NULL) {
		return -1;
	} 
	if (rr2 == NULL) {
		return 1;
	}
	return ldns_rdf_compare(ldns_rr_owner(rr1), ldns_rr_owner(rr2));
}

void ldns_rr_list_sort_nsec3(ldns_rr_list *unsorted) {
	qsort(unsorted->_rrs,
	      ldns_rr_list_rr_count(unsorted),
	      sizeof(ldns_rr *),
	      qsort_rr_compare_nsec3);
}

ldns_zone *
ldns_zone_sign_nsec3(ldns_zone *zone, ldns_key_list *key_list, uint8_t algorithm, uint32_t iterations, uint8_t salt_length, uint8_t *salt)
{
	/*
	 * Algorithm to be created:
	 * - sort the rrs (name/class/type?)
	 * - if sorted, every next rr is belongs either to the rrset
	 * you are working on, or the rrset is complete
	 * for each rrset, calculate rrsig and nsec
	 * put the rrset, rrsig and nsec in the new zone
	 * done!
	 * ow and don't sign old rrsigs etc.
	 */
	
	ldns_zone *signed_zone;
	ldns_rr_list *cur_rrset;
	ldns_rr_list *soa_rrset;
	ldns_rr_list *cur_rrsigs;
	ldns_rr_list *orig_zone_rrs;
	ldns_rr_list *signed_zone_rrs;
	ldns_rr_list *pubkeys;
	ldns_rr_list *glue_rrs;
	ldns_rr_list *nsec3_rrs;
	
	ldns_status status;
	
	ldns_rdf *start_dname = NULL;
	ldns_rdf *cur_dname = NULL;
	ldns_rr *next_rr = NULL;
	ldns_rdf *next_dname = NULL;
	char *next_nsec_owner_str = NULL;
	ldns_rdf *next_nsec_rdf = NULL;
	ldns_rr *nsec;
	ldns_rr *ckey;
	uint16_t i;
	ldns_rr_type cur_rrset_type;
	
	signed_zone = ldns_zone_new();
	
	/* there should only be 1 SOA, so the soa record is 1 rrset */
	soa_rrset = ldns_rr_list_new();
	ldns_rr_list_push_rr(soa_rrset, ldns_zone_soa(zone));
	cur_rrsigs = ldns_sign_public(soa_rrset, key_list);
	cur_dname = ldns_rr_owner(ldns_rr_list_rr(soa_rrset, 0));
	ldns_rr_list_free(soa_rrset);

	ldns_zone_set_soa(signed_zone, ldns_rr_clone(ldns_zone_soa(zone)));
	ldns_zone_push_rr_list(signed_zone, cur_rrsigs);
	ldns_rr_list_free(cur_rrsigs);
	
	orig_zone_rrs = ldns_rr_list_clone(ldns_zone_rrs(zone));

	glue_rrs = ldns_zone_glue_rr_list(zone);

	/* add the key (TODO: check if it's there already? */
	pubkeys = ldns_rr_list_new();
	for (i = 0; i < ldns_key_list_key_count(key_list); i++) {
		ckey = ldns_key2rr(ldns_key_list_key(key_list, i));
		ldns_rr_list_push_rr(pubkeys, ckey);
	}
	signed_zone_rrs = ldns_rr_list_new();

	ldns_rr_list_sort(orig_zone_rrs);
	
	nsec3_rrs = ldns_rr_list_new();
	
	/* add nsecs */
	for (i = 0; i < ldns_rr_list_rr_count(orig_zone_rrs); i++) {
		if (!start_dname) {
			/*start_dname = ldns_rr_owner(ldns_zone_soa(zone));*/
			start_dname = ldns_rr_owner(ldns_rr_list_rr(orig_zone_rrs, i));
			cur_dname = start_dname;
		} else {
			next_rr = ldns_rr_list_rr(orig_zone_rrs, i);
			next_dname = ldns_rr_owner(next_rr);
			if (ldns_rdf_compare(cur_dname, next_dname) != 0) {
				/* skip glue */
				if (ldns_rr_list_contains_rr(glue_rrs, next_rr)) {
					cur_dname = next_dname;
				} else {
					nsec = ldns_create_nsec3(cur_dname, 
								ldns_rr_owner(ldns_zone_soa(zone)),
								orig_zone_rrs,
								algorithm,
								false,
								iterations,
								salt_length,
								salt);
					/*
					printf("Created NSEC3 for: ");
					ldns_rdf_print(stdout, cur_dname);
					printf(":\n");
					ldns_rr_print(stdout, nsec);
					*/
					ldns_rr_set_ttl(nsec, ldns_rdf2native_int32(ldns_rr_rdf(ldns_zone_soa(zone), 6)));
					ldns_rr_list_push_rr(nsec3_rrs, nsec);
					/*start_dname = next_dname;*/
					cur_dname = next_dname;
				}
			}
		}
		ldns_rr_list_push_rr(signed_zone_rrs, ldns_rr_list_rr(orig_zone_rrs, i));
	}
	nsec = ldns_create_nsec3(cur_dname, 
				ldns_rr_owner(ldns_zone_soa(zone)),
				orig_zone_rrs,
				algorithm,
				false,
				iterations,
				salt_length,
				salt);
	ldns_rr_list_push_rr(nsec3_rrs, nsec);
	ldns_rr_list_free(orig_zone_rrs);
	ldns_rr_set_ttl(nsec, ldns_rdf2native_int32(ldns_rr_rdf(ldns_zone_soa(zone), 6)));

	/*
	printf("Created NSEC3 for: ");
	ldns_rdf_print(stdout, cur_dname);
	printf(":\n");
	ldns_rr_print(stdout, nsec);
	*/
	/* sort nsec3s separately, set nexts and append to signed zone */
	ldns_rr_list_sort_nsec3(nsec3_rrs);
	for (i = 0; i < ldns_rr_list_rr_count(nsec3_rrs); i++) {
		if (i == ldns_rr_list_rr_count(nsec3_rrs) - 1) {
			next_nsec_owner_str = ldns_rdf2str(ldns_dname_label(ldns_rr_owner(ldns_rr_list_rr(nsec3_rrs, 0)), 0));
			if (next_nsec_owner_str[strlen(next_nsec_owner_str) - 1] == '.') {
				next_nsec_owner_str[strlen(next_nsec_owner_str) - 1] = '\0';
			}
			status = ldns_str2rdf_b32_ext(&next_nsec_rdf, next_nsec_owner_str);
			if (!ldns_rr_set_rdf(ldns_rr_list_rr(nsec3_rrs, i), next_nsec_rdf, 1)) {
				/* todo: error */
			}
		} else {
			next_nsec_owner_str = ldns_rdf2str(ldns_dname_label(ldns_rr_owner(ldns_rr_list_rr(nsec3_rrs, i + 1)), 0));
			if (next_nsec_owner_str[strlen(next_nsec_owner_str) - 1] == '.') {
				next_nsec_owner_str[strlen(next_nsec_owner_str) - 1] = '\0';
			}
			status = ldns_str2rdf_b32_ext(&next_nsec_rdf, next_nsec_owner_str);
			if (!ldns_rr_set_rdf(ldns_rr_list_rr(nsec3_rrs, i), next_nsec_rdf, 1)) {
				/* todo: error */
			}
		}
	}
	
	ldns_rr_list_cat(signed_zone_rrs, nsec3_rrs);
	ldns_rr_list_sort(signed_zone_rrs);
	
	/* Sign all rrsets in the zone */
	cur_rrset = ldns_rr_list_pop_rrset(signed_zone_rrs);
	while (cur_rrset) {
		/* don't sign certain types */
		cur_rrset_type = ldns_rr_get_type(ldns_rr_list_rr(cur_rrset, 0));
		cur_dname = ldns_rr_owner(ldns_rr_list_rr(cur_rrset, 0));

		/* if we have KSKs, use them for DNSKEYS, otherwise
		   make them selfsigned (?) */
                /* don't sign sigs, delegations, and glue */
		if (cur_rrset_type != LDNS_RR_TYPE_RRSIG &&
		    ((ldns_dname_is_subdomain(cur_dname, ldns_rr_owner(ldns_zone_soa(zone)))
                      && cur_rrset_type != LDNS_RR_TYPE_NS
                     ) ||
		     ldns_rdf_compare(cur_dname, ldns_rr_owner(ldns_zone_soa(zone))) == 0
		    ) &&
		    !(ldns_rr_list_contains_rr(glue_rrs, ldns_rr_list_rr(cur_rrset, 0)))
		   ) {
		   	/*
		   	printf("About to sign RRSET:\n");
		   	ldns_rr_list_print(stdout, cur_rrset);
			*/
			cur_rrsigs = ldns_sign_public(cur_rrset, key_list);

			/* TODO: make optional, replace exit call */
			/* if not optional it should be left out completely
			   (for it is possible to generate bad signarures, by
			   specifying a future inception date */
			/*
			result = ldns_verify(cur_rrset, cur_rrsigs, pubkeys, NULL);
			if (result != LDNS_STATUS_OK) {
				dprintf("%s", "Cannot verify own sig:\n");
				dprintf("%s\n", ldns_get_errorstr_by_id(result));
				ERR_load_crypto_strings();
				ERR_print_errors_fp(stdout);
				exit(result);
			}
			*/
			
			ldns_zone_push_rr_list(signed_zone, cur_rrset);
			ldns_zone_push_rr_list(signed_zone, cur_rrsigs);
			ldns_rr_list_free(cur_rrsigs);
		} else {
			/* push it unsigned (glue, sigs, delegations) */
			ldns_zone_push_rr_list(signed_zone, cur_rrset);
		}
		ldns_rr_list_free(cur_rrset);
		cur_rrset = ldns_rr_list_pop_rrset(signed_zone_rrs);
	}
	ldns_rr_list_free(signed_zone_rrs);
	ldns_rr_list_free(pubkeys);
	return signed_zone;
	
}

/* Init the random source
 * apps must call this 
 */
ldns_status 
ldns_init_random(FILE *fd, uint16_t bytes) 
{
	FILE *rand;
	uint8_t *buf;

	buf = LDNS_XMALLOC(uint8_t, bytes);
	if (!buf) {
		return LDNS_STATUS_ERR;;
	}
	if (!fd) {
		if ((rand = fopen("/dev/urandom", "r")) == NULL) {
			LDNS_FREE(buf);
			return LDNS_STATUS_ERR;
		}
	} else {
		rand = fd;
	}

	if ((fread(buf, sizeof(uint8_t), (size_t)bytes, rand) != bytes)) {
		LDNS_FREE(buf);
		if (!fd) {
			fclose(rand);
		}
		return LDNS_STATUS_ERR;
	}
	if (!fd) {
		fclose(rand);
	}
 	RAND_seed((const void *)buf, (int)bytes);
	LDNS_FREE(buf);
	return LDNS_STATUS_OK;
}
#endif /* HAVE_SSL */
