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
#include <openssl/hmac.h>

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
	/* the current pos in the buffer is the keysize */
	keysize= ldns_buffer_position(keybuf);

	/* look at the algorithm field */
	if (ldns_rdf2native_int8(ldns_rr_rdf(key, 2)) == LDNS_RSAMD5) {
		/* rsamd5 must be handled seperately */
		/* weird stuff copied from drill0.x XXX */
		if (keysize > 4) {
			memcpy(&ac, &key[keysize - 3], 2);
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

/**
 * verify an rrsig rrset
 */

bool
ldns_verify(ldns_rr_list *rrset, ldns_rr_list *rrsig, ldns_rr_list *keys)
{
	uint16_t i;
	bool result;

	result = false;
	for (i = 0; i < ldns_rr_list_rr_count(rrsig); i++) {
		result = ldns_verify_rrsig(rrset, 
				ldns_rr_list_rr(rrsig, i),
				keys);
		if (result) {
			break;
		}
	}
	return result;
}


/**
 * verify an rrsig 
 * \param[in] rrset the rrset to check
 * \param[in] rrsig the signature of the rrset
 * \param[in] keys the keys to try
 */
/* 
 * to verify:
 * - create the wire fmt of the b64 key rdata
 * - create the wire fmt of the sorted rrset
 * - create the wire fmt of the b64 sig rdata
 * - create the wire fmt of the sig without the b64 rdata
 * - cat the sig data (without b64 rdata) to the rrset
 * - verify the rrset+sig, with the b64 data and the b64 key data
 */
bool
ldns_verify_rrsig(ldns_rr_list *rrset, ldns_rr *rrsig, ldns_rr_list *keys)
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

	/* clone the rrset so that we can fiddle with it */
	rrset_clone = ldns_rr_list_deep_clone(rrset);
	
	/* create the buffers which will certainly hold the raw data */
	rawsig_buf = ldns_buffer_new(MAX_PACKETLEN);
	verify_buf  = ldns_buffer_new(MAX_PACKETLEN);
	
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

	/* should work on copies */
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

	/* no longer needed */
	ldns_rr_list_free(rrset_clone);

	for(i = 0; i < ldns_rr_list_rr_count(keys); i++) {
		current_key = ldns_rr_list_rr(keys, i);
		key_buf = ldns_buffer_new(MAX_PACKETLEN);
		/* put the key-data in a buffer, that's the third rdf, with
		 * the base64 encoded key data */
		if (ldns_rdf2buffer_wire(key_buf,
				ldns_rr_rdf(current_key, 3)) != LDNS_STATUS_OK) {
			ldns_buffer_free(rawsig_buf);
			ldns_buffer_free(verify_buf);
			return false;
		}

		switch(sig_algo) {
			case LDNS_DSA:
				result = ldns_verify_rrsig_dsa(
						rawsig_buf, verify_buf, key_buf);
				break;
			case LDNS_RSASHA1:
				result = ldns_verify_rrsig_rsasha1(
						rawsig_buf, verify_buf, key_buf);
				break;
			case LDNS_RSAMD5:
				result = ldns_verify_rrsig_rsamd5(
						rawsig_buf, verify_buf, key_buf);
				break;
			default:
				/* do you know this alg?! */
				break;
		}

		ldns_buffer_free(key_buf); 
		if (result) {
			/* one of the keys has matched */
			break;
		}
	}

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
			 (int)(ldns_buffer_position(key) - offset), modulus);

	rsa = RSA_new();
	rsa->n = modulus;
	rsa->e = exponent;

	return rsa;
}

/**
 * sign the rrset with all the keys.
 * \param[in] rrset the rrset to sign
 * \param[in] keys the keys to use for the signing
 * \return the signatures created
 */
ldns_rr_list *
ldns_sign(ldns_rr_list *ATTR_UNUSED(rrset), ldns_rr_list *ATTR_UNUSED(keys))
{
	/* how to sign
	 * - create the correct openSSL keys from the keys
	 * - sort and extract the original ttl from the rrset
	 * - type covered, labels, wildcards?!?!
	 * - inception, expiration?!?!
	 *
	 *  signature = sign(RRSIG_RDATA | RR(1) | RR(2)... ) 
	 */

	/* create a hash and sign that??? */
#if 0
	        int RSA_sign(NID_sha1 | NID_md5, unsigned char *m, unsigned int m_len,
           unsigned char *sigret, unsigned int *siglen, RSA *rsa);

        int    DSA_sign(int type, const unsigned char *dgst, int len,
			                       unsigned char *sigret, unsigned int *siglen, DSA *dsa);
#endif 

	/* convert the sigstuff to base64 ... */

	return NULL;
}

ldns_rdf *
ldns_create_tsig_mac(
	ldns_pkt *pkt,
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
	ldns_buffer *data_buffer;
	ldns_rdf *mac_rdf;
	char *wireformat;
	int wiresize;
	unsigned char *mac_bytes;
	unsigned int md_len = EVP_MAX_MD_SIZE;
	unsigned char *key_bytes;
	int key_size;
	
	/* 
	 * prepare the digestable information
	 */
	data_buffer = ldns_buffer_new(MAX_PACKETLEN);
	/* if orig_buf is not NULL, add it too */
	if (orig_mac_rdf && ldns_pkt_qr(pkt)) {
		(void) ldns_rdf2buffer_wire(data_buffer, orig_mac_rdf);
	}
	(void) ldns_pkt2buffer_wire(data_buffer, pkt);
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

	/* prepare the key */
	key_bytes = XMALLOC(unsigned char, b64_pton_calculate_size(strlen(key_data)));
	key_size = b64_pton(key_data, key_bytes, strlen(key_data) * 2);
	
	if (key_size < 0) {
		return NULL;
	}
	/* hmac it */
	/* 2 spare bytes for the length */
	mac_bytes = XMALLOC(unsigned char, md_len);
	memset(mac_bytes, 0, md_len);
	(void) HMAC(EVP_md5(), key_bytes, key_size, (void *)wireformat, wiresize, mac_bytes + 2, &md_len);
	
	write_uint16(mac_bytes, md_len);
	mac_rdf = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_INT16_DATA, md_len + 2, mac_bytes);
	
	FREE(mac_bytes);
	FREE(key_bytes);
	ldns_buffer_free(data_buffer);
	
	return mac_rdf;
}


/**
 * Verifies the tsig rr for the given packet and key (string?)
 * @return true if tsig is correct, false if not, or if tsig is not set
 */
bool
ldns_pkt_tsig_verify(ldns_pkt *pkt, 
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
	
	size_t i;
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
	/* TODO temporarily change the id */
	/* TODO rdf2native? */
	pkt_id = ldns_pkt_id(pkt);
	memcpy(&orig_pkt_id, ldns_rdf_data(orig_id_rdf), 2);
	orig_pkt_id = ntohs(orig_pkt_id);
	ldns_pkt_set_id(pkt, orig_pkt_id);

	my_mac_rdf = ldns_create_tsig_mac(pkt,
	                                  key_data, 
	                                  key_name_rdf,
	                                  fudge_rdf,
	                                  algorithm_rdf,
	                                  time_signed_rdf,
	                                  error_rdf,
	                                  other_data_rdf,
	                                  orig_mac_rdf
	                                  );
	
	ldns_pkt_set_tsig(pkt, orig_tsig);
	ldns_pkt_set_id(pkt, pkt_id);
	
	ldns_rdf_free(key_name_rdf);
	
	/* TODO: ldns_rdf_cmp in rdata.[ch] */
	if (ldns_rdf_size(pkt_mac_rdf) != ldns_rdf_size(my_mac_rdf)) {
		/*
		printf("Mac mismatch:\npkt mac: ");
		ldns_rdf_print(stdout, pkt_mac_rdf);
		printf("\n");
		for(i=0; i<ldns_rdf_size(pkt_mac_rdf); i++) {
			printf("%02x ", ldns_rdf_data(pkt_mac_rdf)[i]);
		}
		printf("\nmy mac:  ");
		ldns_rdf_print(stdout, my_mac_rdf);
		printf("\n");
		for(i=0; i<ldns_rdf_size(my_mac_rdf); i++) {
			printf("%02x ", ldns_rdf_data(my_mac_rdf)[i]);
		}
		printf("\n");
		*/
		ldns_rdf_free(my_mac_rdf);
		return false;
	} else {
		for (i = 0; i < ldns_rdf_size(pkt_mac_rdf); i++) {
			if (
				ldns_rdf_data(pkt_mac_rdf)[i] !=
				ldns_rdf_data(my_mac_rdf)[i]
			) {
				/*
				printf("Mac mismatch:\npkt mac: ");
				ldns_rdf_print(stdout, pkt_mac_rdf);
				printf("\n");
				for(i=0; i<ldns_rdf_size(pkt_mac_rdf); i++) {
					printf("%02x ", ldns_rdf_data(pkt_mac_rdf)[i]);
				}
				printf("\nmy mac:  ");
				ldns_rdf_print(stdout, my_mac_rdf);
				printf("\n");
				for(i=0; i<ldns_rdf_size(my_mac_rdf); i++) {
					printf("%02x ", ldns_rdf_data(my_mac_rdf)[i]);
				}
				printf("\n");
				*/
				ldns_rdf_free(my_mac_rdf);
				return false;
			}
		}
	}

	ldns_rdf_free(my_mac_rdf);
	return true;
}



/**
 * Creates a tsig rr for the given packet and key (string?)
 *
 * @param pkt the packet to sign
 * @param key_name the name of the shared key
 * @param key_data the key in base 64 format
 * @param fudge seconds of error permitted in time signed
 * @param algorithm_name the name of the algorithm used (TODO more than only hmac-md5.sig-alg.reg.int.?)
 * @param querymac is added to the digest if not NULL (so NULL is for signing queries, not NULL is for signing answers)
 * @return status (OK if success)
 */
/* TODO: memory :p */
ldns_status
ldns_pkt_tsig_sign(ldns_pkt *pkt, const char *key_name, const char *key_data, uint16_t fudge, const char *algorithm_name, ldns_rdf *query_mac)
{
	int key_size = 0;
	ldns_rr *tsig_rr;
	ldns_rdf *key_name_rdf = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, key_name);
	uint8_t *fudge_data;
	ldns_rdf *fudge_rdf;
	uint16_t orig_id;
	ldns_rdf *orig_id_rdf;
	ldns_rdf *algorithm_rdf = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, algorithm_name);
	uint8_t *error_data;
	ldns_rdf *error_rdf;
	ldns_rdf *mac_rdf;
	
	struct timeval tv_time_signed;
	uint8_t *time_signed;
	ldns_rdf *time_signed_rdf;
	
	uint8_t *other_data;
	ldns_rdf *other_data_rdf;
	
	/* eww don't have create tsigtime rdf yet :( */
	/* bleh :p */
	if (gettimeofday(&tv_time_signed, NULL) == 0) {
		time_signed = XMALLOC(uint8_t, 6);
		write_uint64_as_uint48(time_signed, tv_time_signed.tv_sec);
	} else {
		return LDNS_STATUS_INTERNAL_ERR;
	}

	time_signed_rdf = ldns_rdf_new(6, LDNS_RDF_TYPE_TSIGTIME, time_signed);
	
	fudge_data = XMALLOC(uint8_t, 2);
	write_uint16(fudge_data, fudge);
	fudge_rdf = ldns_rdf_new(2, LDNS_RDF_TYPE_INT16, fudge_data);

	orig_id = htons(ldns_pkt_id(pkt));
	orig_id_rdf = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_INT16, 2, &orig_id);

	error_data = XMALLOC(uint8_t, 2);
	write_uint16(error_data, 0);
	error_rdf = ldns_rdf_new(2, LDNS_RDF_TYPE_INT16, error_data);

	if (key_size < 0) {
		return LDNS_STATUS_INVALID_B64;
	}
	
	other_data = XMALLOC(uint8_t, 2);
	write_uint16(other_data, 0);
	other_data_rdf = ldns_rdf_new(2, LDNS_RDF_TYPE_INT16_DATA, other_data);
	mac_rdf = ldns_create_tsig_mac(pkt, 
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
		return LDNS_STATUS_ERR;
	}
	
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

	return LDNS_STATUS_OK;
}
