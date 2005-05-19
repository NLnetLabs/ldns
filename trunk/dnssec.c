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

#include <ldns/config.h>

#include <ldns/dns.h>

#include <strings.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

uint16_t
ldns_calc_keytag(ldns_rr *key)
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
	keybuf = ldns_buffer_new(LDNS_MAX_PACKETLEN);
	if (!keybuf) {
		return 0;
	}
	(void)ldns_rr_rdata2buffer_wire(keybuf, key);
	/* the current pos in the buffer is the keysize */
	keysize= ldns_buffer_position(keybuf);

	/* look at the algorithm field */
	if (ldns_rdf2native_int8(ldns_rr_rdf(key, 2)) == LDNS_RSAMD5) {
		/* rsamd5 must be handled seperately */
		/* weird stuff copied from drill0.x XXX */
		if (keysize > 4) {
			ldns_buffer_read_at(keybuf, keysize - 3, &ac, 2);
		}
		ldns_buffer_free(keybuf);
		ac = ntohs(ac);
	        return (uint16_t) ac;
	} else {
		/* copied from 2535bis */
		/* look at this again XXX */
		for (i = 0; (size_t)i < keysize; ++i) {
			ac += (i & 1) ? *ldns_buffer_at(keybuf, i) : 
				*ldns_buffer_at(keybuf, i) << 8;
		}
		ldns_buffer_free(keybuf);
		ac += (ac >> 16) & 0xFFFF;
		return (uint16_t) (ac & 0xFFFF);
	}
}

ldns_rr_list *
ldns_verify(ldns_rr_list *rrset, ldns_rr_list *rrsig, ldns_rr_list *keys)
{
	uint16_t i;
	ldns_rr_list * result;

	if (!rrset || !rrsig || !keys) {
		return NULL;
	}
	
	result = NULL;
	for (i = 0; i < ldns_rr_list_rr_count(rrsig); i++) {
		if (i == 0) {
			result = ldns_rr_list_new();
		}
		result = ldns_rr_list_cat(result,
			                  ldns_verify_rrsig_keylist(rrset, 
					  	ldns_rr_list_rr(rrsig, i),
					  	keys)
					 );
	}
	return result;
}

INLINE bool
ldns_verify_rrsig_buffers(ldns_buffer *rawsig_buf,
                          ldns_buffer *verify_buf,
                          ldns_buffer *key_buf,
                          uint8_t algo
                         )
{
		/* check for right key */
		switch(algo) {
			case LDNS_DSA:
				return ldns_verify_rrsig_dsa(
						rawsig_buf, verify_buf, key_buf);
				break;
			case LDNS_RSASHA1:
				return ldns_verify_rrsig_rsasha1(
						rawsig_buf, verify_buf, key_buf);
				break;
			case LDNS_RSAMD5:
				return ldns_verify_rrsig_rsamd5(
						rawsig_buf, verify_buf, key_buf);
				break;
			default:
				/* do you know this alg?! */
				return false;
		}
}


/* 
 * to verify:
 * - create the wire fmt of the b64 key rdata
 * - create the wire fmt of the sorted rrset
 * - create the wire fmt of the b64 sig rdata
 * - create the wire fmt of the sig without the b64 rdata
 * - cat the sig data (without b64 rdata) to the rrset
 * - verify the rrset+sig, with the b64 data and the b64 key data
 */
ldns_rr_list *
ldns_verify_rrsig_keylist(ldns_rr_list *rrset, ldns_rr *rrsig, ldns_rr_list *keys)
{
	ldns_buffer *rawsig_buf;
	ldns_buffer *verify_buf;
	ldns_buffer *key_buf;
	uint32_t orig_ttl;
	uint16_t i;
	uint8_t sig_algo;
	bool result;
	ldns_rr *current_key;
	ldns_rr_list *rrset_clone;
	ldns_rr_list *validkeys;

	if (!rrset) {
		return NULL;
	}

	validkeys = ldns_rr_list_new();
	if (!validkeys) {
		return NULL;
	}
	
	/* clone the rrset so that we can fiddle with it */
	rrset_clone = ldns_rr_list_deep_clone(rrset);
	
	/* create the buffers which will certainly hold the raw data */
	rawsig_buf = ldns_buffer_new(LDNS_MAX_PACKETLEN);
	verify_buf  = ldns_buffer_new(LDNS_MAX_PACKETLEN);
	
	sig_algo = ldns_rdf2native_int8(ldns_rr_rdf(rrsig, 1));
	result = false;

	/* create a buffer with b64 signature rdata */
	if (ldns_rdf2buffer_wire(rawsig_buf,
				ldns_rr_rdf(rrsig, 8)) != LDNS_STATUS_OK) {
		ldns_buffer_free(rawsig_buf);
		ldns_buffer_free(verify_buf);
		return NULL;
	}

	orig_ttl = ldns_rdf2native_int32(
			ldns_rr_rdf(rrsig, 3));

	/* reset the ttl in the rrset with the orig_ttl from the sig */
	for(i = 0; i < ldns_rr_list_rr_count(rrset_clone); i++) {
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
		ldns_buffer_free(rawsig_buf);
		ldns_buffer_free(verify_buf);
		return NULL;
	}

	/* add the rrset in verify_buf */
	if (ldns_rr_list2buffer_wire(verify_buf, rrset_clone) != LDNS_STATUS_OK) {
		ldns_buffer_free(rawsig_buf);
		ldns_buffer_free(verify_buf);
		return NULL;
	}

	for(i = 0; i < ldns_rr_list_rr_count(keys); i++) {
		current_key = ldns_rr_list_rr(keys, i);
		if (ldns_calc_keytag(current_key)
		    ==
		    ldns_rdf2native_int16(ldns_rr_rrsig_keytag(rrsig))
		   ) {
			key_buf = ldns_buffer_new(LDNS_MAX_PACKETLEN);
			
			/* before anything, check if the keytags match */

			/* put the key-data in a buffer, that's the third rdf, with
			 * the base64 encoded key data */
			if (ldns_rdf2buffer_wire(key_buf,
					ldns_rr_rdf(current_key, 3)) != LDNS_STATUS_OK) {
				ldns_buffer_free(rawsig_buf);
				ldns_buffer_free(verify_buf);
				/* returning is bad might screw up
				   good keys later in the list
				   what to do? */
				return NULL;
			}

			/* check for right key */
			if (sig_algo == ldns_rdf2native_int8(ldns_rr_rdf(current_key, 2))) {
				result = ldns_verify_rrsig_buffers(rawsig_buf, verify_buf, key_buf, sig_algo);
			}

			ldns_buffer_free(key_buf); 
			if (result) {
				/* one of the keys has matched, don't break
				 * here, instead put the 'winning' key in
				 * the validkey list and return the list 
				 * later */
				if (!ldns_rr_list_push_rr(validkeys, current_key)) {
					/* couldn't push the key?? */
					return NULL;
				}
				/* break; */ 
			}
		}
	}

	/* no longer needed */
	ldns_rr_list_free(rrset_clone);
	ldns_buffer_free(rawsig_buf);
	ldns_buffer_free(verify_buf);
	if (ldns_rr_list_rr_count(validkeys) == 0) {
		/* no keys were added */
		return NULL;
	} else {
		return validkeys;
	}
}

bool
ldns_verify_rrsig(ldns_rr_list *rrset, ldns_rr *rrsig, ldns_rr *key)
{
	ldns_buffer *rawsig_buf;
	ldns_buffer *verify_buf;
	ldns_buffer *key_buf;
	uint32_t orig_ttl;
	uint16_t i;
	uint8_t sig_algo;
	bool result;
	ldns_rr_list *rrset_clone;

	if (!rrset) {
		return false;
	}

	/* clone the rrset so that we can fiddle with it */
	rrset_clone = ldns_rr_list_deep_clone(rrset);
	
	/* create the buffers which will certainly hold the raw data */
	rawsig_buf = ldns_buffer_new(LDNS_MAX_PACKETLEN);
	verify_buf  = ldns_buffer_new(LDNS_MAX_PACKETLEN);
	
	sig_algo = ldns_rdf2native_int8(ldns_rr_rdf(rrsig, 1));
	result = false;

	/* create a buffer with b64 signature rdata */
	if (ldns_rdf2buffer_wire(rawsig_buf,
				ldns_rr_rdf(rrsig, 8)) != LDNS_STATUS_OK) {
		ldns_buffer_free(rawsig_buf);
		ldns_buffer_free(verify_buf);
		return false;
	}

	orig_ttl = ldns_rdf2native_int32(
			ldns_rr_rdf(rrsig, 3));

	/* reset the ttl in the rrset with the orig_ttl from the sig */
	for(i = 0; i < ldns_rr_list_rr_count(rrset_clone); i++) {
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
		ldns_buffer_free(rawsig_buf);
		ldns_buffer_free(verify_buf);
		return false;
	}

	/* add the rrset in verify_buf */
	if (ldns_rr_list2buffer_wire(verify_buf, rrset_clone) != LDNS_STATUS_OK) {
		ldns_buffer_free(rawsig_buf);
		ldns_buffer_free(verify_buf);
		return false;
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
			ldns_buffer_free(rawsig_buf);
			ldns_buffer_free(verify_buf);
			/* returning is bad might screw up
			   good keys later in the list
			   what to do? */
			return false;
		}
		
		if (sig_algo == ldns_rdf2native_int8(ldns_rr_rdf(key, 2))) {
			result = ldns_verify_rrsig_buffers(rawsig_buf, verify_buf, key_buf, sig_algo);
		}
		
		ldns_buffer_free(key_buf); 
	}

	/* no longer needed */
	ldns_rr_list_free(rrset_clone);
	ldns_buffer_free(rawsig_buf);
	ldns_buffer_free(verify_buf);
	return result;
}

bool
ldns_verify_rrsig_dsa(ldns_buffer *sig, ldns_buffer *rrset, ldns_buffer *key)
{
	DSA *dsakey;
	DSA_SIG *dsasig;
	BIGNUM *R;
	BIGNUM *S;
	unsigned char *sha1_hash;

	dsakey = ldns_key_buf2dsa(key);
	if (!dsakey) {
		return false;
	}

	/* extract the R and S field from the sig buffer */
	R = BN_bin2bn((unsigned char*)ldns_buffer_at(sig, 1), SHA_DIGEST_LENGTH, NULL);
	S = BN_bin2bn((unsigned char*)ldns_buffer_at(sig, 21), SHA_DIGEST_LENGTH, NULL);
	
	dsasig = DSA_SIG_new();
	if (!dsasig) {
		return false;
	}
	/* 
	   TODO uncomment and fix
	t_sig = (uint8_t) sigbuf[0];
	
	if (t_sig != T) {
		warning("Values for T are different in key and signature, verification of DSA sig failed");
		return RET_FAIL;
	}
	*/
	dsasig->r = R;
	dsasig->s = S;
	sha1_hash = SHA1((unsigned char*)ldns_buffer_begin(rrset), ldns_buffer_position(rrset), NULL);
	if (!sha1_hash) {
		return false;
	}
	
	if (DSA_do_verify(sha1_hash, SHA_DIGEST_LENGTH, dsasig, dsakey) == 1) {
		return true;
	} else {
		return false;
	}
}

bool
ldns_verify_rrsig_rsasha1(ldns_buffer *sig, ldns_buffer *rrset, ldns_buffer *key)
{
	RSA *rsakey;
	unsigned char *sha1_hash;

	rsakey = ldns_key_buf2rsa(key);
	if (!rsakey) {
		return false;
	}

	sha1_hash = SHA1((unsigned char*)ldns_buffer_begin(rrset), ldns_buffer_position(rrset), NULL);
	if (!sha1_hash) {
		return false;
	}
	
	if (RSA_verify(NID_sha1, sha1_hash, SHA_DIGEST_LENGTH, 
				(unsigned char*)ldns_buffer_begin(sig),
			(unsigned int)ldns_buffer_position(sig), rsakey) == 1) {
		return true;
	} else {
		  ERR_load_crypto_strings();
		  ERR_print_errors_fp(stdout);

		return false;
	}
}


bool
ldns_verify_rrsig_rsamd5(ldns_buffer *sig, ldns_buffer *rrset, ldns_buffer *key)
{
	RSA *rsakey;
	unsigned char *md5_hash;

	rsakey = ldns_key_buf2rsa(key);
	if (!rsakey) {
		return false;
	}
	md5_hash = MD5((unsigned char*)ldns_buffer_begin(rrset), 
			(unsigned int)ldns_buffer_position(rrset), NULL);
	if (!md5_hash) {
		return false;
	}
	if (RSA_verify(NID_md5, md5_hash, MD5_DIGEST_LENGTH, 
				(unsigned char*)ldns_buffer_begin(sig),
			(unsigned int)ldns_buffer_position(sig), rsakey) == 1) {
		return true;
	} else {
		return false;
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
			 (int)(ldns_buffer_position(key) - offset), modulus);

	rsa = RSA_new();
	rsa->n = modulus;
	rsa->e = exponent;

	return rsa;
}

/*
 *  Makes an exact copy of the wire, but with the tsig rr removed
 */
uint8_t *
ldns_tsig_prepare_pkt_wire(uint8_t *wire, size_t wire_len, size_t *result_len)
{
	uint8_t *wire2 = NULL;
	uint16_t qd_count;
	uint16_t an_count;
	uint16_t ns_count;
	uint16_t ar_count;
	ldns_rr *rr;
	
	size_t pos;
	uint16_t i;
	
	ldns_status status;

	/* fake parse the wire */
	qd_count = LDNS_QDCOUNT(wire);
	an_count = LDNS_ANCOUNT(wire);
	ns_count = LDNS_NSCOUNT(wire);
	ar_count = LDNS_ARCOUNT(wire);
	
	if (ar_count > 0) {
		ar_count--;
	} else {
		return NULL;
	}

	pos = LDNS_HEADER_SIZE;
	
	for (i = 0; i < qd_count; i++) {
		status = ldns_wire2rr(&rr, wire, wire_len, &pos,
		                      LDNS_SECTION_QUESTION);
		if (status != LDNS_STATUS_OK) {
			return NULL;
		}
		ldns_rr_free(rr);
	}
	
	for (i = 0; i < an_count; i++) {
		status = ldns_wire2rr(&rr, wire, wire_len, &pos,
		                      LDNS_SECTION_ANSWER);
		if (status != LDNS_STATUS_OK) {
			return NULL;
		}
		ldns_rr_free(rr);
	}
	
	for (i = 0; i < ns_count; i++) {
		status = ldns_wire2rr(&rr, wire, wire_len, &pos,
		                      LDNS_SECTION_AUTHORITY);
		if (status != LDNS_STATUS_OK) {
			return NULL;
		}
		ldns_rr_free(rr);
	}
	
	for (i = 0; i < ar_count; i++) {
		status = ldns_wire2rr(&rr, wire, wire_len, &pos,
		                      LDNS_SECTION_ADDITIONAL);
		if (status != LDNS_STATUS_OK) {
			return NULL;
		}
		ldns_rr_free(rr);
	}
	
	*result_len = pos;
	wire2 = LDNS_XMALLOC(uint8_t, *result_len);
	memcpy(wire2, wire, *result_len);
	
	write_uint16(wire2 + LDNS_ARCOUNT_OFF, ar_count);
	
	return wire2;
}

const EVP_MD *
ldns_get_digest_function(char *name)
{
	/* TODO replace with openssl's EVP_get_digestbyname
	        (need init somewhere for that)
	*/
	if (strlen(name) == 10 && strncasecmp(name, "hmac-sha1.", 9) == 0) {
		return EVP_sha1();
	} else if (strlen(name) == 25 && strncasecmp(name, "hmac-md5.sig-alg.reg.int.", 25) == 0) {
		return EVP_md5();
	} else {
		return NULL;
	}
}

ldns_status
ldns_create_tsig_mac(
	ldns_rdf **tsig_mac,
	uint8_t *pkt_wire,
	size_t pkt_wire_size,
	const char *key_data,
	ldns_rdf *key_name_rdf,
	ldns_rdf *fudge_rdf,
	ldns_rdf *algorithm_rdf,
	ldns_rdf *time_signed_rdf,
	ldns_rdf *error_rdf,
	ldns_rdf *other_data_rdf,
	ldns_rdf *orig_mac_rdf
)
{
	ldns_buffer *data_buffer = NULL;
	char *wireformat;
	int wiresize;
	unsigned char *mac_bytes;
	unsigned int md_len = EVP_MAX_MD_SIZE;
	unsigned char *key_bytes;
	int key_size;
	const EVP_MD *digester;
	char *algorithm_name;
	ldns_rdf *result = NULL;
	
	/* 
	 * prepare the digestable information
	 */
	data_buffer = ldns_buffer_new(LDNS_MAX_PACKETLEN);
	/* if orig_mac is not NULL, add it too */
	if (orig_mac_rdf) {
		(void) ldns_rdf2buffer_wire(data_buffer, orig_mac_rdf);
 	}
	ldns_buffer_write(data_buffer, pkt_wire, pkt_wire_size);
	(void) ldns_rdf2buffer_wire(data_buffer, key_name_rdf);
	ldns_buffer_write_u16(data_buffer, LDNS_RR_CLASS_ANY);
	ldns_buffer_write_u32(data_buffer, 0);
	(void) ldns_rdf2buffer_wire(data_buffer, algorithm_rdf);
	(void) ldns_rdf2buffer_wire(data_buffer, time_signed_rdf);
	(void) ldns_rdf2buffer_wire(data_buffer, fudge_rdf);
	(void) ldns_rdf2buffer_wire(data_buffer, error_rdf);
	(void) ldns_rdf2buffer_wire(data_buffer, other_data_rdf);
	
	wireformat = (char *) data_buffer->_data;
	wiresize = (int) ldns_buffer_position(data_buffer);
	
	algorithm_name = ldns_rdf2str(algorithm_rdf);
	
	/* prepare the key */
	key_bytes = LDNS_XMALLOC(unsigned char, b64_pton_calculate_size(strlen(key_data)));
	key_size = b64_pton(key_data, key_bytes, strlen(key_data) * 2);
	if (key_size < 0) {
		/* LDNS_STATUS_INVALID_B64 */
		dprintf("%s\n", "Bad base64 string");
		return LDNS_STATUS_INVALID_B64;
	}
	/* hmac it */
	/* 2 spare bytes for the length */
	mac_bytes = LDNS_XMALLOC(unsigned char, md_len);
	memset(mac_bytes, 0, md_len);
	
	digester = ldns_get_digest_function(algorithm_name);
	
	if (digester) {
		(void) HMAC(digester, key_bytes, key_size, (void *)wireformat, wiresize, mac_bytes + 2, &md_len);
	
		write_uint16(mac_bytes, md_len);
		result = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_INT16_DATA, md_len + 2, mac_bytes);
	} else {
		/*dprintf("No digest found for %s\n", algorithm_name);*/
		return LDNS_STATUS_CRYPTO_UNKNOWN_ALGO;
	}
	
	LDNS_FREE(algorithm_name);
	LDNS_FREE(mac_bytes);
	LDNS_FREE(key_bytes);
	ldns_buffer_free(data_buffer);

	*tsig_mac = result;
	
	return LDNS_STATUS_OK;
}


/* THIS FUNC WILL REMOVE TSIG ITSELF */
bool
ldns_pkt_tsig_verify(ldns_pkt *pkt, 
                     uint8_t *wire,
                     size_t wirelen,
                     const char *key_name, 
                     const char *key_data, 
                     ldns_rdf *orig_mac_rdf)
{
	ldns_rdf *fudge_rdf;
	ldns_rdf *algorithm_rdf;
	ldns_rdf *time_signed_rdf;
	ldns_rdf *orig_id_rdf;
	ldns_rdf *error_rdf;
	ldns_rdf *other_data_rdf;
	ldns_rdf *pkt_mac_rdf;
	ldns_rdf *my_mac_rdf;
	ldns_rdf *key_name_rdf = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, key_name);
	uint16_t pkt_id, orig_pkt_id;
	ldns_status status;
	
	uint8_t *prepared_wire = NULL;
	size_t prepared_wire_size = 0;
	
	ldns_rr *orig_tsig = ldns_pkt_tsig(pkt);
	
	if (!orig_tsig) {
		ldns_rdf_free(key_name_rdf);
		return false;
	}
	algorithm_rdf = ldns_rr_rdf(orig_tsig, 0);
	time_signed_rdf = ldns_rr_rdf(orig_tsig, 1);
	fudge_rdf = ldns_rr_rdf(orig_tsig, 2);
	pkt_mac_rdf = ldns_rr_rdf(orig_tsig, 3);
	orig_id_rdf = ldns_rr_rdf(orig_tsig, 4);
	error_rdf = ldns_rr_rdf(orig_tsig, 5);
	other_data_rdf = ldns_rr_rdf(orig_tsig, 6);
	
	/* remove temporarily */
	ldns_pkt_set_tsig(pkt, NULL);
	/* temporarily change the id to the original id */
	pkt_id = ldns_pkt_id(pkt);
	orig_pkt_id = ldns_rdf2native_int16(orig_id_rdf);
	ldns_pkt_set_id(pkt, orig_pkt_id);

	prepared_wire = ldns_tsig_prepare_pkt_wire(wire, wirelen, &prepared_wire_size);
	
	status = ldns_create_tsig_mac(&my_mac_rdf,
	                              prepared_wire,
	                              prepared_wire_size,
	                              key_data, 
	                              key_name_rdf,
	                              fudge_rdf,
	                              algorithm_rdf,
	                              time_signed_rdf,
	                              error_rdf,
	                              other_data_rdf,
	                              orig_mac_rdf
	                             );
	
	if (status != LDNS_STATUS_OK) {
		return false;
	}
	/* Put back the values */
	ldns_pkt_set_tsig(pkt, orig_tsig);
	ldns_pkt_set_id(pkt, pkt_id);
	
	ldns_rdf_free_data(key_name_rdf);
	
	/* TODO: ldns_rdf_cmp in rdata.[ch] */
	if (ldns_rdf_compare(pkt_mac_rdf, my_mac_rdf) == 0) {
		ldns_rdf_free(my_mac_rdf);
		return true;
	} else {
		ldns_rdf_free(my_mac_rdf);
		return false;
	}
}



/* TODO: memory :p */
ldns_status
ldns_pkt_tsig_sign(ldns_pkt *pkt, const char *key_name, const char *key_data, uint16_t fudge, const char *algorithm_name, ldns_rdf *query_mac)
{
	int key_size = 0;
	ldns_rr *tsig_rr;
	ldns_rdf *key_name_rdf = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, key_name);
	ldns_rdf *fudge_rdf = NULL;
	ldns_rdf *orig_id_rdf = NULL;
	ldns_rdf *algorithm_rdf;
	ldns_rdf *error_rdf = NULL;
	ldns_rdf *mac_rdf = NULL;
	ldns_rdf *other_data_rdf = NULL;
	
	ldns_status status = LDNS_STATUS_OK;
	
	uint8_t *pkt_wire = NULL;
	size_t pkt_wire_len;
	
	struct timeval tv_time_signed;
	uint8_t *time_signed = NULL;
	ldns_rdf *time_signed_rdf = NULL;
	
	algorithm_rdf = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, algorithm_name);

	/* eww don't have create tsigtime rdf yet :( */
	/* bleh :p */
	if (gettimeofday(&tv_time_signed, NULL) == 0) {
		time_signed = LDNS_XMALLOC(uint8_t, 6);
		write_uint64_as_uint48(time_signed, tv_time_signed.tv_sec);
	} else {
		status = LDNS_STATUS_INTERNAL_ERR;
		goto clean;
	}

	if (key_size < 0) {
		status = LDNS_STATUS_INVALID_B64;
		goto clean;
	}

	time_signed_rdf = ldns_rdf_new(LDNS_RDF_TYPE_TSIGTIME, 6, time_signed);
	
	fudge_rdf = ldns_native2rdf_int16(LDNS_RDF_TYPE_INT16, fudge);

	orig_id_rdf = ldns_native2rdf_int16(LDNS_RDF_TYPE_INT16, ldns_pkt_id(pkt));

	error_rdf = ldns_native2rdf_int16(LDNS_RDF_TYPE_INT16, 0);
	
	other_data_rdf = ldns_native2rdf_int16_data(0, NULL);

	(void) ldns_pkt2wire(&pkt_wire, pkt, &pkt_wire_len);

	status = ldns_create_tsig_mac(&mac_rdf,
	                              pkt_wire,
	                              pkt_wire_len,
				      key_data,
	                              key_name_rdf, 
	                              fudge_rdf, 
	                              algorithm_rdf,
	                              time_signed_rdf,
	                              error_rdf,
	                              other_data_rdf,
	                              query_mac
	                              );
	
	if (!mac_rdf) {
		status = LDNS_STATUS_ERR;
		goto clean;
	}
	
	LDNS_FREE(pkt_wire);
	
	/* Create the TSIG RR */
	tsig_rr = ldns_rr_new();
	ldns_rr_set_owner(tsig_rr, key_name_rdf);
	ldns_rr_set_class(tsig_rr, LDNS_RR_CLASS_ANY);
	ldns_rr_set_type(tsig_rr, LDNS_RR_TYPE_TSIG);
	ldns_rr_set_ttl(tsig_rr, 0);
	
	ldns_rr_push_rdf(tsig_rr, algorithm_rdf);
	ldns_rr_push_rdf(tsig_rr, time_signed_rdf);
	ldns_rr_push_rdf(tsig_rr, fudge_rdf);
	ldns_rr_push_rdf(tsig_rr, mac_rdf);
	ldns_rr_push_rdf(tsig_rr, orig_id_rdf);
	ldns_rr_push_rdf(tsig_rr, error_rdf);
	ldns_rr_push_rdf(tsig_rr, other_data_rdf);
	
	ldns_pkt_set_tsig(pkt, tsig_rr);

	return status;

	clean:
	ldns_rdf_free(key_name_rdf);
	ldns_rdf_free(algorithm_rdf);
	ldns_rdf_free(time_signed_rdf);
	ldns_rdf_free(fudge_rdf);
	ldns_rdf_free(orig_id_rdf);
	ldns_rdf_free(error_rdf);
	ldns_rdf_free(other_data_rdf);
	return status;
}

ldns_rr *
ldns_key_rr2ds(const ldns_rr *key)
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
	ldns_rr_set_owner(ds, ldns_rdf_deep_clone(
				ldns_rr_owner(key)));
	ldns_rr_set_ttl(ds, ldns_rr_ttl(key));
	ldns_rr_set_class(ds, ldns_rr_get_class(key));

        digest = LDNS_XMALLOC(uint8_t, SHA_DIGEST_LENGTH);
        if (!digest) {
                return NULL;
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
        ldns_rr_push_rdf(ds, ldns_rdf_deep_clone(
                                ldns_rr_rdf(key, 2)));

        /* digest type, only SHA1 is supported */
        sha1hash = 1;
        tmp = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_INT8, sizeof(uint8_t), &sha1hash);
        ldns_rr_push_rdf(ds, tmp);

        /* digest */
        /* owner name */
	if (ldns_rdf2buffer_wire(data_buf, ldns_rr_owner(key)) !=
			LDNS_STATUS_OK) {
		return NULL;
	}

        /* all the rdata's */
	if (ldns_rr_rdata2buffer_wire(data_buf, (ldns_rr*)key) !=
			LDNS_STATUS_OK) { 
		return NULL;
	}

        /* sha1 it */
        (void) SHA1((unsigned char *) ldns_buffer_begin(data_buf),
                    ldns_buffer_position(data_buf),
                    (unsigned char*) digest);

        tmp = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_HEX, SHA_DIGEST_LENGTH,
                        digest);
        ldns_rr_push_rdf(ds, tmp);

	LDNS_FREE(digest);
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

	if (!rrset || !keys) {
		return NULL;
	}

	key_count = 0;
	signatures = ldns_rr_list_new();

	ldns_rr_list_print(stdout, rrset);

	/* prepare a signature and add all the know data
	 * prepare the rrset. Sign this together.  */
	rrset_clone = ldns_rr_list_deep_clone(rrset);
	if (!rrset_clone) {
		return NULL;
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
		current_sig = ldns_rr_new_frm_type(LDNS_RR_TYPE_RRSIG);
		
		/* set the type on the new signature */
		orig_ttl = ldns_key_origttl(current_key);

		/* set the ttl from the priv key on the rrset */
		for (i = 0; i < ldns_rr_list_rr_count(rrset); i++) {
			ldns_rr_set_ttl(
					ldns_rr_list_rr(rrset_clone, i), orig_ttl);
		}

		ldns_rr_set_owner(current_sig, 
				ldns_rr_owner(ldns_rr_list_rr(rrset_clone, 0)));

		/* fill in what we know of the signature */

		/* set the orig_ttl */
		(void)ldns_rr_rrsig_set_origttl(current_sig, ldns_native2rdf_int32(LDNS_RDF_TYPE_INT32, orig_ttl));
		/* the signers name */
		(void)ldns_rr_rrsig_set_signame(current_sig, 
				ldns_key_pubkey_owner(current_key));
		/* label count - get it from the first rr in the rr_list */
		(void)ldns_rr_rrsig_set_labels(current_sig, 
				ldns_native2rdf_int8(LDNS_RDF_TYPE_INT8, ldns_rr_label_count(
						ldns_rr_list_rr(rrset_clone, 0))));
		/* inception, expiration */
		(void)ldns_rr_rrsig_set_inception(current_sig,
				ldns_native2rdf_int32(LDNS_RDF_TYPE_INT32, ldns_key_inception(current_key)));
		(void)ldns_rr_rrsig_set_expiration(current_sig,
				ldns_native2rdf_int32(LDNS_RDF_TYPE_INT32, ldns_key_expiration(current_key)));
		/* key-tag */
		(void)ldns_rr_rrsig_set_keytag(current_sig,
				ldns_native2rdf_int16(LDNS_RDF_TYPE_INT16, ldns_key_keytag(current_key)));

		/* algorithm - check the key and substitute that */
		(void)ldns_rr_rrsig_set_algorithm(current_sig,
				ldns_native2rdf_int8(LDNS_RDF_TYPE_ALG, ldns_key_algorithm(current_key)));
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

		ldns_buffer_free(sign_buf); /* restart for the next key */
        }
	return signatures;
}

ldns_rdf *
ldns_sign_public_dsa(ldns_buffer *to_sign, DSA *key)
{
	unsigned char *sha1_hash;
	unsigned int siglen;
	ldns_rdf *sigdata_rdf;
	ldns_buffer *b64sig;

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
	
	DSA_sign(NID_sha1, sha1_hash, SHA_DIGEST_LENGTH,
			(unsigned char*)ldns_buffer_begin(b64sig),
			&siglen, key);
	
	sigdata_rdf = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_B64, siglen, 
			ldns_buffer_begin(b64sig));
	ldns_buffer_free(b64sig);
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
