/* 
 * dnssec.c
 *
 * contains the cryptographic function needed for DNSSEC
 * The crypto library used is openssl
 *
 * (c) NLnet Labs, 2004
 * a Net::DNS like library for C
 *
 * See the file LICENSE for the license
 */

#include <config.h>
#include <ldns/ldns.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

/** 
 * calcalutes a keytag of a key for use in DNSSEC
 * \param[in] key the key to use for the calc.
 * \return the keytag
 */
uint16_t
ldns_keytag(ldns_rr *key)
{
	unsigned int i;
	uint32_t ac;
	ldns_buffer *keybuf;
	size_t keysize;
	
	ac = 0;

	if (ldns_rr_get_type(key) != LDNS_RR_TYPE_DNSKEY) {
		return 0;
	}

	/* rdata to buf - only put the rdata in a buffer */
	/* XXX waaayyy too much */
	keybuf = ldns_buffer_new(MAX_PACKETLEN);
	(void)ldns_rr_rdata2buffer_wire(keybuf, key);
	keysize= ldns_buffer_capacity(keybuf);

	/* look at the algorithm field */
	if (ldns_rdf2native_int8(ldns_rr_rdf(key, 2)) == LDNS_RSAMD5) {
		/* rsamd5 must be handled seperately */
		/* weird stuff copied from drill0.x XXX */
		if (keysize > 4) {
			memcpy(&ac, &key[keysize-3], 2);
		}
		ac = ntohs(ac);
	        return (uint16_t) ac;
	} else {
		/* copied from 2535bis */
		/* look at this again */
		for (i = 0; (size_t)i < keysize; ++i) {
			ac += (i & 1) ? *ldns_buffer_at(keybuf, i) : 
				*ldns_buffer_at(keybuf, i) << 8;
		}
		ac += (ac >> 16) & 0xFFFF;
		return (uint16_t) (ac & 0xFFFF);
	}
}

/**
 * verify an rrsig 
 * \param[in] rrset the rrset to check
 * \param[in] rrsig the signature of the rrset
 * \param[in] keys the keys to try
 */
bool
ldns_verify_rrsig(ldns_rr_list *rrset, ldns_rr *rrsig, ldns_rr_list *keys)
{
	ldns_buffer *rawsig_buf;
	ldns_buffer *rrset_buf;
	ldns_buffer *key_buf;
	uint32_t orig_ttl;
	uint16_t i;
	uint8_t sig_algo;
	bool result;
	ldns_rr *current_key;

	/* TODO remove */
	key_buf = NULL;
	rrset_buf = NULL;

	/* create a buffer which will certainly hold the
	 * raw data */
	rawsig_buf = ldns_buffer_new(MAX_PACKETLEN);
	sig_algo = ldns_rdf2native_int8(ldns_rr_rdf(rrsig, 1));
	result = false;
	
	(void)ldns_rrsig2buffer_wire(rawsig_buf, rrsig);

	orig_ttl = ldns_rdf2native_int32(
			ldns_rr_rdf(rrsig, 3));

	/* reset the ttl in the rrset with the orig_ttl
	 * from the sig */
	
	for(i = 0; i < ldns_rr_list_rr_count(rrset); i++) {
		ldns_rr_set_ttl(
				ldns_rr_list_rr(rrset, i),
				orig_ttl);
	}

	/* sort the rrset in canonical order - must this happen
	 * after setting the orig TTL? or before?? */
	ldns_rr_list_sort(rrset);

	/* put the rrset in a wirefmt buf */

	for(i = 0; i < ldns_rr_list_rr_count(keys); i++) {
		current_key = ldns_rr_list_rr(keys, i);

		/* put the key in a buffer */

		switch(sig_algo) {
			case LDNS_DSA:
				result = ldns_verify_rrsig_dsa(
						rawsig_buf, rrset_buf, key_buf);
				break;
			case LDNS_RSASHA1:
				result = ldns_verify_rrsig_rsasha1(
						rawsig_buf, rrset_buf, key_buf);
				break;
			case LDNS_RSAMD5:
				result = ldns_verify_rrsig_rsamd5(
						rawsig_buf, rrset_buf, key_buf);
				break;
			default:
				/* no fucking way man! */
				break;
		}

		/* ldns_buffer_free(key_buf); TODO */
		if (result) {
			/* one of the keys has matched */
			break;
		}
	}

	ldns_buffer_free(rawsig_buf);
	ldns_buffer_free(rrset_buf);

	return result;
}

bool
ldns_verify_rrsig_dsa(ldns_buffer *ATTR_UNUSED(sig), ldns_buffer *ATTR_UNUSED(rrset), ldns_buffer *ATTR_UNUSED(key))
{
	return true;
}

bool
ldns_verify_rrsig_rsasha1(ldns_buffer *ATTR_UNUSED(sig), ldns_buffer *ATTR_UNUSED(rrset), ldns_buffer *ATTR_UNUSED(key))
{
	return true;
}


bool
ldns_verify_rrsig_rsamd5(ldns_buffer *ATTR_UNUSED(sig), ldns_buffer *ATTR_UNUSED(rrset), ldns_buffer *ATTR_UNUSED(key))
{
	return true;
}


/* some helper functions */
/**
 * convert a buffer holding key material to a DSA key in openssl 
 * \param[in] key the key to convert
 * \return a DSA * structure with the key material
 */
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
		printf("DSA type > 8 not implemented, unable to verify signature");
		return NULL;
	}
	
	Q = BN_bin2bn((unsigned char*)ldns_buffer_at(key, offset), 20, NULL);
	offset += 20;
	
	P = BN_bin2bn((unsigned char*)ldns_buffer_at(key, offset), (int)length, NULL);
	offset += length;
	
	G = BN_bin2bn((unsigned char*)ldns_buffer_at(key, offset), (int)length, NULL);
	offset += length;
	
	Y = BN_bin2bn((unsigned char*)ldns_buffer_at(key, offset), (int)length, NULL);
	offset += length;
	
	/* 
	   TODO uncomment and fix
	t_sig = (uint8_t) sigbuf[0];
	
	if (t_sig != T) {
		warning("Values for T are different in key and signature, verification of DSA sig failed");
		return RET_FAIL;
	}
	*/
	/* create the key and set its properties */
	dsa = DSA_new();
	dsa->p = P;
	dsa->q = Q;
	dsa->g = G;
	dsa->pub_key = Y;
	return dsa;
}

/**
 * convert a buffer holding key material to a RSA key in openssl 
 * \param[in] key the key to convert
 * \return a RSA * structure with the key material
 */
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
		memcpy(&int16,
				ldns_buffer_at(key, 1), 2);
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
			 (int)(ldns_buffer_capacity(key) - offset), modulus);

	rsa = RSA_new();
	rsa->n = modulus;
	rsa->e = exponent;

	return rsa;
}


#if 0

/**
 * Verify an rrsig with the DSA algorithm, see RFC 2536
 * \param[in]
 */
bool
ldns_verify_rrsig_dsa(uint8_t *verifybuf, unsigned long length, unsigned char *sigbuf, unsigned int siglen,
		unsigned char *key_bytes, unsigned int keylen)
{
	t_sig = (uint8_t) sigbuf[0];
	
	if (t_sig != T) {
		warning("Values for T are different in key and signature, verification of DSA sig failed");
		return RET_FAIL;
	}
	
	
	R = BN_bin2bn(&sigbuf[1], 20, NULL);
	
	S = BN_bin2bn(&sigbuf[21], 20, NULL);
	
	dsa = DSA_new();
	
	dsa->p = P;
	dsa->q = Q;
	dsa->g = G;
	dsa->pub_key = Y;
	
	//hash = xmalloc(20);
	
	hash = SHA1((unsigned char *) verifybuf, length, NULL);
	
	sig = DSA_SIG_new();
	sig->r = R;
	sig->s = S;
	
	dsa_res = DSA_do_verify((unsigned char *) hash, 20, sig, dsa);

	if (dsa_res == 1) {
		result = RET_SUC;
	} else if (dsa_res == 0) {
		result = RET_FAIL;
	} else {
		warning("internal error when verifying: %d", dsa_res);
		ERR_print_errors_fp(stdout);
		result = RET_FAIL;
	}

	return result;
}



/**
 * Verify an rrsig with the RSA algorithm and SHA1 hash, see RFC 3110
 */
int
verify_rrsig_rsasha1(uint8_t *verifybuf, unsigned long length, unsigned char *sigbuf, unsigned int siglen,
		unsigned char *key_bytes, unsigned int keylen)
{
	BIGNUM *modulus;
	BIGNUM *exponent;
	unsigned char *modulus_bytes;
	unsigned char *exponent_bytes;
	unsigned char *digest;
	int offset;
	int explength;
	uint16_t int16;
	RSA *rsa;
	int rsa_res;

	int result;
	
	digest = SHA1((unsigned char *) verifybuf, length, NULL);
	if (digest == NULL) {
		error("Error digesting");
		exit(EXIT_FAILURE);
	}
	
	rsa_res = RSA_verify(NID_sha1,  digest, 20,  sigbuf, siglen, rsa);
	if (rsa_res == 1) {
		result = RET_SUC;
	} else if (rsa_res == 0) {
		result = RET_FAIL;
	} else {
		warning("internal error when verifying: %d\n", rsa_res);
		ERR_print_errors_fp(stdout);
		result = RET_FAIL;
	}
	
	xfree(modulus_bytes);
	xfree(exponent_bytes);
	RSA_free(rsa);
	return result;
}

int
verify_rrsig_rsamd5(uint8_t *verifybuf, unsigned long length, unsigned char *sigbuf, unsigned int siglen,
		unsigned char *key_bytes, unsigned int keylen)
{
	BIGNUM *modulus;
	BIGNUM *exponent;
	unsigned char *modulus_bytes;
	unsigned char *exponent_bytes;
	int offset, explength;
	unsigned char *digest;
	uint16_t int16;
	RSA *rsa;
	int rsa_res;

	int result;
	
	rsa = RSA_new();
	rsa->n = modulus;
	rsa->e = exponent;

	digest = xmalloc(16);
	digest =  MD5((unsigned char *) verifybuf, length,  digest);
	if (digest == NULL) {
		error("Error digesting\n");
		exit(EXIT_FAILURE);
	}
	
	rsa_res = RSA_verify(NID_md5, digest, 16,  sigbuf, siglen, rsa);
	if (rsa_res == 1) {
		result = RET_SUC;
	} else if (rsa_res == 0) {
		result = RET_FAIL;
	} else {
		warning("internal error when verifying: %d\n", rsa_res);
		ERR_print_errors_fp(stdout);
		result = RET_FAIL;
	}
	
	xfree(digest);
	xfree(modulus_bytes);
	xfree(exponent_bytes);
	RSA_free(rsa);
	return result;
}

#endif
