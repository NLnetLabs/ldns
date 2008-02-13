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

#include <ldns/ldns.h>
#include <ldns/dnssec.h>

#include <strings.h>
#include <time.h>

#ifdef HAVE_SSL
/* this entire file is rather useless when you don't have
 * crypto...
 */
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/md5.h>

ldns_rr *
ldns_dnssec_get_rrsig_for_name_and_type(const ldns_rdf *name,
                                        const ldns_rr_type type,
                                        const ldns_rr_list *rrs)
{
	size_t i;
	ldns_rr *candidate;
	
	if (!name || !rrs) {
		return NULL;
	}
	
	for (i = 0; i < ldns_rr_list_rr_count(rrs); i++) {
		candidate = ldns_rr_list_rr(rrs, i);
		if (ldns_rr_get_type(candidate) == LDNS_RR_TYPE_RRSIG) {
			if (ldns_dname_compare(ldns_rr_owner(candidate),
			                       name) == 0 &&
			    ldns_rdf2native_int8(ldns_rr_rrsig_typecovered(candidate)) ==
			    type
			    ) {
				return candidate;
			}
		}
	}
	
	return NULL;
}

ldns_rr *
ldns_dnssec_get_dnskey_for_rrsig(const ldns_rr *rrsig, const ldns_rr_list *rrs)
{
	size_t i;
	ldns_rr *candidate;
	
	if (!rrsig || !rrs) {
		return NULL;
	}
	
	for (i = 0; i < ldns_rr_list_rr_count(rrs); i++) {
		candidate = ldns_rr_list_rr(rrs, i);
		if (ldns_rr_get_type(candidate) == LDNS_RR_TYPE_DNSKEY) {
			if (ldns_dname_compare(ldns_rr_owner(candidate),
			                       ldns_rr_rrsig_signame(rrsig)) == 0 &&
			    ldns_rdf2native_int16(ldns_rr_rrsig_keytag(rrsig)) ==
			    ldns_calc_keytag(candidate)
			    ) {
				return candidate;
			}
		}
	}
	
	return NULL;
}

ldns_rdf *
ldns_nsec_get_bitmap(ldns_rr *nsec) {
	if (ldns_rr_get_type(nsec) == LDNS_RR_TYPE_NSEC) {
		return ldns_rr_rdf(nsec, 1);
	} else if (ldns_rr_get_type(nsec) == LDNS_RR_TYPE_NSEC3) {
		return ldns_rr_rdf(nsec, 5);
	} else {
		return NULL;
	}
}

/*return the owner name of the closest encloser for name from the list of rrs */
/* this is NOT the hash, but the original name! */
/* XXX tmp: verbosity */
int verbosity = 5;

ldns_rdf *
ldns_dnssec_nsec3_closest_encloser(ldns_rdf *qname,
							ldns_rr_type qtype,
							ldns_rr_list *nsec3s)
{
	/* remember parameters, they must match */
	uint8_t algorithm;
	uint32_t iterations;
	uint8_t salt_length;
	uint8_t *salt;

	ldns_rdf *sname, *hashed_sname, *tmp;
	ldns_rr *ce;
	bool flag;
	
	bool exact_match_found;
	bool in_range_found;
	
	ldns_status status;
	ldns_rdf *zone_name;
	
	size_t nsec_i;
	ldns_rr *nsec;
	ldns_rdf *result = NULL;
	
	if (!qname || !nsec3s || ldns_rr_list_rr_count(nsec3s) < 1) {
		return NULL;
	}

	if (verbosity >= 4) {
		printf(";; finding closest encloser for type %d ", qtype);
		ldns_rdf_print(stdout, qname);
		printf("\n");
	}

	nsec = ldns_rr_list_rr(nsec3s, 0);
	algorithm = ldns_nsec3_algorithm(nsec);
	salt_length = ldns_nsec3_salt_length(nsec);
	salt = ldns_nsec3_salt_data(nsec);
	iterations = ldns_nsec3_iterations(nsec);

	sname = ldns_rdf_clone(qname);

	ce = NULL;
	flag = false;
	
	zone_name = ldns_dname_left_chop(ldns_rr_owner(nsec));

	/* algorithm from nsec3-07 8.3 */
	while (ldns_dname_label_count(sname) > 0) {
		exact_match_found = false;
		in_range_found = false;
		
		if (verbosity >= 3) {
			printf(";; ");
			ldns_rdf_print(stdout, sname);
			printf(" hashes to: ");
		}
		hashed_sname = ldns_nsec3_hash_name(sname, algorithm, iterations, salt_length, salt);

		status = ldns_dname_cat(hashed_sname, zone_name);

		if (verbosity >= 3) {
			ldns_rdf_print(stdout, hashed_sname);
			printf("\n");
		}

		for (nsec_i = 0; nsec_i < ldns_rr_list_rr_count(nsec3s); nsec_i++) {
			nsec = ldns_rr_list_rr(nsec3s, nsec_i);
			
			/* check values of iterations etc! */
			
			/* exact match? */
			if (ldns_dname_compare(ldns_rr_owner(nsec), hashed_sname) == 0) {
				if (verbosity >= 4) {
					printf(";; exact match found\n");
				}
			 	exact_match_found = true;
			} else if (ldns_nsec_covers_name(nsec, hashed_sname)) {
				if (verbosity >= 4) {
					printf(";; in range of an nsec\n");
				}
				in_range_found = true;
			}
			
		}
		if (!exact_match_found && in_range_found) {
			flag = true;
		} else if (exact_match_found && flag) {
			result = ldns_rdf_clone(sname);
		} else if (exact_match_found && !flag) {
			// error!
			if (verbosity >= 4) {
				printf(";; the closest encloser is the same name (ie. this is an exact match, ie there is no closest encloser)\n");
			}
			ldns_rdf_deep_free(hashed_sname);
			goto done;
		} else {
			flag = false;
		}
		
		ldns_rdf_deep_free(hashed_sname);
		tmp = sname;
		sname = ldns_dname_left_chop(sname);
		ldns_rdf_deep_free(tmp);
	}

	done:
	LDNS_FREE(salt);
	ldns_rdf_deep_free(zone_name);
	ldns_rdf_deep_free(sname);

	if (!result) {
		if (verbosity >= 4) {
			printf(";; no closest encloser found\n");
		}
	}

	return result;
}

bool
ldns_dnssec_pkt_has_rrsigs(const ldns_pkt *pkt)
{
	size_t i;
	for (i = 0; i < ldns_pkt_ancount(pkt); i++) {
		if (ldns_rr_get_type(ldns_rr_list_rr(ldns_pkt_answer(pkt), i)) ==
		    LDNS_RR_TYPE_RRSIG) {
			return true;
		}
	}
	for (i = 0; i < ldns_pkt_nscount(pkt); i++) {
		if (ldns_rr_get_type(ldns_rr_list_rr(ldns_pkt_authority(pkt), i)) ==
		    LDNS_RR_TYPE_RRSIG) {
			return true;
		}
	}
	return false;
}

ldns_rr_list *
ldns_dnssec_pkt_get_rrsigs_for_name_and_type(const ldns_pkt *pkt, ldns_rdf *name, ldns_rr_type type)
{
	uint16_t t_netorder;
	ldns_rr_list *sigs;
	ldns_rr_list *sigs_covered;
	ldns_rdf *rdf_t;
	
	sigs = ldns_pkt_rr_list_by_name_and_type(pkt,
									 name,
									 LDNS_RR_TYPE_RRSIG,
									 LDNS_SECTION_ANY_NOQUESTION
									 );

	t_netorder = htons(type); /* rdf are in network order! */
	rdf_t = ldns_rdf_new(LDNS_RDF_TYPE_TYPE, sizeof(ldns_rr_type), &t_netorder);
	sigs_covered = ldns_rr_list_subtype_by_rdf(sigs, rdf_t, 0);
	
	ldns_rdf_free(rdf_t);
	ldns_rr_list_deep_free(sigs);

	return sigs_covered;

}

ldns_rr_list *
ldns_dnssec_pkt_get_rrsigs_for_type(const ldns_pkt *pkt, ldns_rr_type type)
{
	uint16_t t_netorder;
	ldns_rr_list *sigs;
	ldns_rr_list *sigs_covered;
	ldns_rdf *rdf_t;
	
	sigs = ldns_pkt_rr_list_by_type(pkt,
	                                LDNS_RR_TYPE_RRSIG,
	                                LDNS_SECTION_ANY_NOQUESTION
							  );

	t_netorder = htons(type); /* rdf are in network order! */
	rdf_t = ldns_rdf_new(LDNS_RDF_TYPE_TYPE, sizeof(ldns_rr_type), &t_netorder);
	sigs_covered = ldns_rr_list_subtype_by_rdf(sigs, rdf_t, 0);
	
	ldns_rdf_free(rdf_t);
	ldns_rr_list_deep_free(sigs);

	return sigs_covered;

}

/* used only on the public key RR */
uint16_t
ldns_calc_keytag(const ldns_rr *key)
{
	uint16_t ac16;
	ldns_buffer *keybuf;
	size_t keysize;

	if (!key) {
		return 0;
	}

	/*
	  printf("calc keytag for key at %p:\n", key);
	  ldns_rr_print(stdout, key);
	*/
	if (ldns_rr_get_type(key) != LDNS_RR_TYPE_DNSKEY &&
	    ldns_rr_get_type(key) != LDNS_RR_TYPE_KEY
	    ) {
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

	ac16 = ldns_calc_keytag_raw(ldns_buffer_begin(keybuf), keysize);
	ldns_buffer_free(keybuf);
	return ac16;
}

uint16_t ldns_calc_keytag_raw(uint8_t* key, size_t keysize)
{
	unsigned int i;
	uint32_t ac32;
	uint16_t ac16;

	if(keysize < 4) {
		return 0;
	}
	/* look at the algorithm field, copied from 2535bis */
	if (key[3] == LDNS_RSAMD5) {
		ac16 = 0;
		if (keysize > 4) {
			memmove(&ac16, key + keysize - 3, 2);
		}
		ac16 = ntohs(ac16);
		return (uint16_t) ac16;
	} else {
		ac32 = 0;
		for (i = 0; (size_t)i < keysize; ++i) {
			ac32 += (i & 1) ? key[i] : key[i] << 8;
		}
		ac32 += (ac32 >> 16) & 0xFFFF;
		return (uint16_t) (ac32 & 0xFFFF);
	}
}

DSA *
ldns_key_buf2dsa(ldns_buffer *key)
{
	return ldns_key_buf2dsa_raw((unsigned char*)ldns_buffer_begin(key),
						   ldns_buffer_position(key));
}

DSA *
ldns_key_buf2dsa_raw(unsigned char* key, size_t len)
{
	uint8_t T;
	uint16_t length;
	uint16_t offset;
	DSA *dsa;
	BIGNUM *Q; BIGNUM *P;
	BIGNUM *G; BIGNUM *Y;

	if(len == 0)
		return NULL;
	T = (uint8_t)key[0];
	length = (64 + T * 8);
	offset = 1;
	
	if (T > 8) {
		return NULL;
	}
	if(len < (size_t)1 + SHA_DIGEST_LENGTH + 3*length)
		return NULL;
	
	Q = BN_bin2bn(key+offset, SHA_DIGEST_LENGTH, NULL);
	offset += SHA_DIGEST_LENGTH;
	
	P = BN_bin2bn(key+offset, (int)length, NULL);
	offset += length;
	
	G = BN_bin2bn(key+offset, (int)length, NULL);
	offset += length;
	
	Y = BN_bin2bn(key+offset, (int)length, NULL);
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
	return ldns_key_buf2rsa_raw((unsigned char*)ldns_buffer_begin(key),
						   ldns_buffer_position(key));
}

RSA *
ldns_key_buf2rsa_raw(unsigned char* key, size_t len)
{
	uint16_t offset;
	uint16_t exp;
	uint16_t int16;
	RSA *rsa;
	BIGNUM *modulus;
	BIGNUM *exponent;

	if (len == 0)
		return NULL;
	if (key[0] == 0) {
		if(len < 3)
			return NULL;
		/* need some smart comment here XXX*/
		/* the exponent is too large so it's places
		 * futher...???? */
		memmove(&int16, key+1, 2);
		exp = ntohs(int16);
		offset = 3;
	} else {
		exp = key[0];
		offset = 1;
	}

	/* key length at least one */
	if(len < (size_t)offset + exp + 1)
		return NULL;
	
	/* Exponent */
	exponent = BN_new();
	(void) BN_bin2bn(key+offset, (int)exp, exponent);
	offset += exp;

	/* Modulus */
	modulus = BN_new();
	/* length of the buffer must match the key length! */
	(void) BN_bin2bn(key+offset, (int)(len - offset), modulus);

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
			ldns_rr_free(ds);
			return NULL;
		}
		break;
	case LDNS_SHA256:
#ifdef SHA256_DIGEST_LENGTH
		digest = LDNS_XMALLOC(uint8_t, SHA256_DIGEST_LENGTH);
		if (!digest) {
			ldns_rr_free(ds);
			return NULL;
		}
#else
		return NULL;
#endif
		break;
	}

	data_buf = ldns_buffer_new(LDNS_MAX_PACKETLEN);
	if (!data_buf) {
		LDNS_FREE(digest);
		ldns_rr_free(ds);
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
	tmp = ldns_rdf_clone(ldns_rr_owner(key));
	ldns_dname2canonical(tmp);
	if (ldns_rdf2buffer_wire(data_buf, tmp) != LDNS_STATUS_OK) {
		LDNS_FREE(digest);
		ldns_buffer_free(data_buf);
		ldns_rr_free(ds);
		ldns_rdf_deep_free(tmp);
		return NULL;
	}
	ldns_rdf_deep_free(tmp);

	/* all the rdata's */
	if (ldns_rr_rdata2buffer_wire(data_buf, (ldns_rr*)key) != LDNS_STATUS_OK) { 
		LDNS_FREE(digest);
		ldns_buffer_free(data_buf);
		ldns_rr_free(ds);
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
#ifdef SHA256_DIGEST_LENGTH
		(void) SHA256((unsigned char *) ldns_buffer_begin(data_buf),
				    ldns_buffer_position(data_buf),
				    (unsigned char*) digest);
		tmp = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_HEX, SHA256_DIGEST_LENGTH,
							   digest);
		ldns_rr_push_rdf(ds, tmp);
#endif
		break;
	}

	LDNS_FREE(digest);
	ldns_buffer_free(data_buf);
	return ds;
}

ldns_rdf *
ldns_dnssec_create_nsec_bitmap(ldns_rr_type rr_type_list[],
						 size_t size,
						 ldns_rr_type nsec_type)
{
	size_t i;
	uint8_t *bitmap;
	uint16_t bm_len = 0;
	uint16_t i_type;
	ldns_rdf *bitmap_rdf;

	uint8_t *data = NULL;
	uint8_t cur_data[32];
	uint8_t cur_window = 0;
	uint8_t cur_window_max = 0;
	uint16_t cur_data_size = 0;

	if (nsec_type != LDNS_RR_TYPE_NSEC &&
	    nsec_type != LDNS_RR_TYPE_NSEC3) {
		return NULL;
	}

	/* the types in the list should be orders, lowest first,
	   so the last one contains the highest type */
	i_type = rr_type_list[size-1];
	if (i_type < nsec_type) {
		i_type = nsec_type;
	}
	bm_len = i_type / 8 + 2;
	bitmap = LDNS_XMALLOC(uint8_t, bm_len);
	for (i = 0; i < bm_len; i++) {
		bitmap[i] = 0;
	}

	for (i = 0; i < size; i++) {
		i_type = rr_type_list[i];
		ldns_set_bit(bitmap + (int) i_type / 8, (int) (7 - (i_type % 8)), true);
	}
	/* always add nsec (if this is not nsec3 and rrsig */
	i_type = LDNS_RR_TYPE_RRSIG;
	ldns_set_bit(bitmap + (int) i_type / 8, (int) (7 - (i_type % 8)), true);
	i_type = nsec_type;
	if (i_type != LDNS_RR_TYPE_NSEC3) {
		ldns_set_bit(bitmap + (int) i_type / 8, (int) (7 - (i_type % 8)), true);
	}

	/* fold it into windows TODO: can this be done directly? */
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
		data = LDNS_XREALLOC(data,
						 uint8_t,
						 cur_data_size + cur_window_max + 3);
		data[cur_data_size] = cur_window;
		data[cur_data_size + 1] = cur_window_max + 1;
		memcpy(data + cur_data_size + 2, cur_data, cur_window_max+1);
		cur_data_size += cur_window_max + 3;
	}
	
	bitmap_rdf = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_NSEC,
								cur_data_size,
								data);

	LDNS_FREE(bitmap);
	LDNS_FREE(data);

	return bitmap_rdf;
}

ldns_rr *
ldns_dnssec_create_nsec(ldns_dnssec_name *from, ldns_dnssec_name *to, ldns_rr_type nsec_type)
{
	ldns_rr *nsec_rr;
	ldns_rr_type types[1024];
	size_t type_count = 0;
	ldns_dnssec_rrsets *cur_rrsets;

	if (!from || !to || (nsec_type != LDNS_RR_TYPE_NSEC &&
					 nsec_type != LDNS_RR_TYPE_NSEC3)) {
		return NULL;
	}

	nsec_rr = ldns_rr_new();
	ldns_rr_set_type(nsec_rr, nsec_type);
	ldns_rr_set_owner(nsec_rr, ldns_rdf_clone(ldns_dnssec_name_name(from)));
	ldns_rr_push_rdf(nsec_rr, ldns_rdf_clone(ldns_dnssec_name_name(to)));

	cur_rrsets = from->rrsets;
	while (cur_rrsets) {
		types[type_count] = cur_rrsets->type;
		type_count++;
		cur_rrsets = cur_rrsets->next;
	}

	ldns_rr_push_rdf(nsec_rr, ldns_dnssec_create_nsec_bitmap(types,
												  type_count,
												  nsec_type));

	return nsec_rr;
}

ldns_rr *
ldns_dnssec_create_nsec3(ldns_dnssec_name *from,
					ldns_dnssec_name *to,
					ldns_rdf *zone_name,
					uint8_t algorithm,
					uint8_t flags,
					uint16_t iterations,
					uint8_t salt_length,
					uint8_t *salt)
{
	ldns_rr *nsec_rr;
	ldns_rr_type types[1024];
	size_t type_count = 0;
	ldns_dnssec_rrsets *cur_rrsets;
	ldns_status status;

	flags = flags;

	if (!from || !to) {
		return NULL;
	}

	nsec_rr = ldns_rr_new_frm_type(LDNS_RR_TYPE_NSEC3);
	ldns_rr_set_owner(nsec_rr, ldns_nsec3_hash_name(ldns_dnssec_name_name(from), algorithm, iterations, salt_length, salt));
	/*	ldns_rr_push_rdf(nsec_rr, ldns_rdf_clone(ldns_dnssec_name_name(to)));*/
	status = ldns_dname_cat(ldns_rr_owner(nsec_rr), zone_name);
	ldns_nsec3_add_param_rdfs(nsec_rr, algorithm, flags, iterations, salt_length, salt);

	/* XXX why the next? */
	cur_rrsets = from->rrsets;
	while (cur_rrsets) {
		types[type_count] = cur_rrsets->type;
		type_count++;
		cur_rrsets = cur_rrsets->next;
	}

	ldns_rr_set_rdf(nsec_rr, NULL, 4);
	ldns_rr_set_rdf(nsec_rr,
				 ldns_dnssec_create_nsec_bitmap(types,
										  type_count,
										  LDNS_RR_TYPE_NSEC3), 5);

	return nsec_rr;
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

	uint8_t *bitmap = LDNS_XMALLOC(uint8_t, 2);
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
				bitmap = LDNS_XREALLOC(bitmap, uint8_t, (i_type / 8) + 2);
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
		bitmap = LDNS_XREALLOC(bitmap, uint8_t, (i_type / 8) + 2);
		/* set to 0 */
		for (; bm_len <= i_type / 8; bm_len++) {
			bitmap[bm_len] = 0;
		}
	}
	ldns_set_bit(bitmap + (int) i_type / 8, (int) (7 - (i_type % 8)), true);
	i_type = LDNS_RR_TYPE_NSEC;

	if (i_type / 8 > bm_len) {
		bitmap = LDNS_XREALLOC(bitmap, uint8_t, (i_type / 8) + 2);
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
ldns_nsec3_hash_name(ldns_rdf *name, uint8_t algorithm, uint16_t iterations, uint8_t salt_length, uint8_t *salt)
{
	char *orig_owner_str;
	size_t hashed_owner_str_len;
	ldns_rdf *hashed_owner;
	char *hashed_owner_str;
	char *hashed_owner_b32;
	int hashed_owner_b32_len;
	uint32_t cur_it;
	char *hash = NULL;
	ldns_status status;
	
	/* prepare the owner name according to the draft section bla */
	orig_owner_str = ldns_rdf2str(name);
	
	/* TODO: mnemonic list for hash algs SHA-1, default to 1 now (sha1) */
	algorithm = algorithm;
	
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

	LDNS_FREE(orig_owner_str);
	LDNS_FREE(hashed_owner_str);
	hashed_owner_str = hash;
	hashed_owner_str_len = SHA_DIGEST_LENGTH;

	hashed_owner_b32 = LDNS_XMALLOC(char, b32_ntop_calculate_size(hashed_owner_str_len) + 1);
	hashed_owner_b32_len = (size_t) b32_ntop_extended_hex((uint8_t *) hashed_owner_str, hashed_owner_str_len, hashed_owner_b32, b32_ntop_calculate_size(hashed_owner_str_len));
	if (hashed_owner_b32_len < 1) {
		fprintf(stderr, "Error in base32 extended hex encoding of hashed owner name (name: ");
		ldns_rdf_print(stderr, name);
		fprintf(stderr, ", return code: %d)\n", hashed_owner_b32_len);
		exit(4);
	}
	hashed_owner_str_len = hashed_owner_b32_len;
	hashed_owner_b32[hashed_owner_b32_len] = '\0';

	status = ldns_str2rdf_dname(&hashed_owner, hashed_owner_b32);
	if (status != LDNS_STATUS_OK) {
		fprintf(stderr, "Error creating rdf from %s\n", hashed_owner_b32);
		exit(1);
	}

	LDNS_FREE(hashed_owner_b32);
	return hashed_owner;
}

void
ldns_nsec3_add_param_rdfs(ldns_rr *rr,
					 uint8_t algorithm, 
					 uint8_t flags,
					 uint16_t iterations,
					 uint8_t salt_length,
					 uint8_t *salt)
{
	ldns_rdf *salt_rdf = NULL;
	uint8_t *salt_data = NULL;
	
	ldns_rr_set_rdf(rr, ldns_rdf_new_frm_data(LDNS_RDF_TYPE_INT8, 1, (void*)&algorithm), 0);
	ldns_rr_set_rdf(rr, ldns_rdf_new_frm_data(LDNS_RDF_TYPE_INT8, 1, (void*)&flags), 1);
	ldns_rr_set_rdf(rr, ldns_native2rdf_int16(LDNS_RDF_TYPE_INT16, iterations), 2);
	
	salt_data = LDNS_XMALLOC(uint8_t, salt_length + 1);
	salt_data[0] = salt_length;
	memcpy(salt_data + 1, salt, salt_length);
	salt_rdf = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_NSEC3_SALT, salt_length + 1, salt_data);

	ldns_rr_set_rdf(rr, salt_rdf, 3);
	LDNS_FREE(salt_data);
}

/* this will NOT return the NSEC3  completed, you will have to run the
   finalize function on the rrlist later! */
ldns_rr *
ldns_create_nsec3(ldns_rdf *cur_owner,
                  ldns_rdf *cur_zone,
                  ldns_rr_list *rrs,
                  uint8_t algorithm,
                  uint8_t flags,
                  uint16_t iterations,
                  uint8_t salt_length,
                  uint8_t *salt,
                  bool emptynonterminal)
{
	size_t i;
	ldns_rr *i_rr;

	uint8_t *bitmap = LDNS_XMALLOC(uint8_t, 1);
	uint16_t bm_len = 0;
	uint16_t i_type;

	ldns_rr *nsec = NULL;
	ldns_rdf *hashed_owner = NULL;
	
	uint8_t *data = NULL;
	uint8_t cur_data[32];
	uint8_t cur_window = 0;
	uint8_t cur_window_max = 0;
	uint16_t cur_data_size = 0;

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
	hashed_owner = ldns_nsec3_hash_name(cur_owner, algorithm, iterations, salt_length, salt);
	status = ldns_dname_cat(hashed_owner, cur_zone);
	
	nsec = ldns_rr_new_frm_type(LDNS_RR_TYPE_NSEC3);
	ldns_rr_set_type(nsec, LDNS_RR_TYPE_NSEC3);
	ldns_rr_set_owner(nsec, hashed_owner);
	/* TODO: TTL? */
	
	ldns_nsec3_add_param_rdfs(nsec, algorithm, flags, iterations, salt_length, salt);
	ldns_rr_set_rdf(nsec, NULL, 4);

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
	if (!emptynonterminal) {
		i_type = LDNS_RR_TYPE_RRSIG;
		if (i_type / 8 > bm_len) {
			bitmap = LDNS_XREALLOC(bitmap, uint8_t, (i_type / 8) + 1);
			/* set to 0 */
			for (; bm_len <= i_type / 8; bm_len++) {
				bitmap[bm_len] = 0;
			}
		}
		ldns_set_bit(bitmap + (int) i_type / 8, (int) (7 - (i_type % 8)), true);
	}

	/* and SOA if owner == zone */
	if (ldns_dname_compare(cur_zone, cur_owner) == 0) {
		i_type = LDNS_RR_TYPE_SOA;
		if (i_type / 8 > bm_len) {
			bitmap = LDNS_XREALLOC(bitmap, uint8_t, (i_type / 8) + 1);
			/* set to 0 */
			for (; bm_len <= i_type / 8; bm_len++) {
				bitmap[bm_len] = 0;
			}
		}
		ldns_set_bit(bitmap + (int) i_type / 8, (int) (7 - (i_type % 8)), true);
	}

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

	ldns_rr_set_rdf(nsec, ldns_rdf_new_frm_data(LDNS_RDF_TYPE_NSEC, cur_data_size, data), 5);

	LDNS_FREE(bitmap);
	LDNS_FREE(data);

	/*
	  printf(";; Created NSEC3 for:\n");
	  printf(";; ");
	  ldns_rdf_print(stdout, cur_owner);
	  printf("\n");
	  printf(";; ");
	  ldns_rr_print(stdout, nsec);
	*/
	return nsec;
}

uint8_t
ldns_nsec3_algorithm(const ldns_rr *nsec3_rr)
{
	if (nsec3_rr && ldns_rr_get_type(nsec3_rr) == LDNS_RR_TYPE_NSEC3 &&
	    ldns_rdf_size(ldns_rr_rdf(nsec3_rr, 0)) > 0
	    ) {
		/*return ldns_rdf_data(ldns_rr_rdf(nsec3_rr, 0))[0];*/
		return ldns_rdf2native_int8(ldns_rr_rdf(nsec3_rr, 0));
	}
	return 0;
}

uint8_t
ldns_nsec3_flags(const ldns_rr *nsec3_rr)
{
	if (nsec3_rr && ldns_rr_get_type(nsec3_rr) == LDNS_RR_TYPE_NSEC3 &&
	    ldns_rdf_size(ldns_rr_rdf(nsec3_rr, 1)) > 0
	    ) {
		/*return ldns_rdf_data(ldns_rr_rdf(nsec3_rr, 0))[0];*/
		return ldns_rdf2native_int8(ldns_rr_rdf(nsec3_rr, 0));
	}
	return 0;
}

bool
ldns_nsec3_optout(const ldns_rr *nsec3_rr)
{
	return (ldns_nsec3_flags(nsec3_rr) & LDNS_NSEC3_VARS_OPTOUT_MASK);
}

uint16_t
ldns_nsec3_iterations(const ldns_rr *nsec3_rr)
{
	if (nsec3_rr && ldns_rr_get_type(nsec3_rr) == LDNS_RR_TYPE_NSEC3 &&
	    ldns_rdf_size(ldns_rr_rdf(nsec3_rr, 2)) > 0
	    ) {
		return ldns_rdf2native_int16(ldns_rr_rdf(nsec3_rr, 2));
	}
	return 0;
	
}

ldns_rdf *
ldns_nsec3_salt(const ldns_rr *nsec3_rr)
{
	if (nsec3_rr && ldns_rr_get_type(nsec3_rr) == LDNS_RR_TYPE_NSEC3) {
		return ldns_rr_rdf(nsec3_rr, 3);
	}
	return NULL;
}

uint8_t
ldns_nsec3_salt_length(const ldns_rr *nsec3_rr)
{
	ldns_rdf *salt_rdf = ldns_nsec3_salt(nsec3_rr);
	if (salt_rdf && ldns_rdf_size(salt_rdf) > 0) {
		return (uint8_t) ldns_rdf_data(salt_rdf)[0];
	}
	return 0;
}

/* allocs data, free with LDNS_FREE() */
uint8_t *
ldns_nsec3_salt_data(const ldns_rr *nsec3_rr)
{
	uint8_t salt_length;
	uint8_t *salt;

	ldns_rdf *salt_rdf = ldns_nsec3_salt(nsec3_rr);
	if (salt_rdf && ldns_rdf_size(salt_rdf) > 0) {
	    	salt_length = ldns_rdf_data(salt_rdf)[0];
		salt = LDNS_XMALLOC(uint8_t, salt_length);
		memcpy(salt, &ldns_rdf_data(salt_rdf)[1], salt_length);
		return salt;
	}
	return NULL;
}

ldns_rdf *
ldns_nsec3_next_owner(const ldns_rr *nsec3_rr)
{
	if (!nsec3_rr || ldns_rr_get_type(nsec3_rr) != LDNS_RR_TYPE_NSEC3) {
		return NULL;
	} else {
		return ldns_rr_rdf(nsec3_rr, 4);
	}
}

ldns_rdf *
ldns_nsec3_bitmap(const ldns_rr *nsec3_rr)
{
	if (!nsec3_rr || ldns_rr_get_type(nsec3_rr) != LDNS_RR_TYPE_NSEC3) {
		return NULL;
	} else {
		return ldns_rr_rdf(nsec3_rr, 5);
	}
}

ldns_rdf *
ldns_nsec3_hash_name_frm_nsec3(const ldns_rr *nsec, ldns_rdf *name)
{
	uint8_t algorithm;
	uint16_t iterations;
	/*	uint8_t *data;*/
	uint8_t salt_length;
	uint8_t *salt = 0;
	/*uint8_t salt_i;*/
	
	ldns_rdf *hashed_owner;

	/*
	  printf("NSEC RDF: ");
	  ldns_rdf_print(stdout, ldns_rr_rdf(nsec, 0));
	  printf("\n\n");
	*/
	algorithm = ldns_nsec3_algorithm(nsec);
	salt_length = ldns_nsec3_salt_length(nsec);
	salt = ldns_nsec3_salt_data(nsec);
	iterations = ldns_nsec3_iterations(nsec);
	
	hashed_owner = ldns_nsec3_hash_name(name, algorithm, iterations, salt_length, salt);
	
	/*
	  printf(";; Iterations: %u, Salt: ", iterations);
	  for (salt_i = 0; salt_i < salt_length; salt_i++) {
	  printf("%02x", salt[salt_i]);
	  }
	  printf("\n");
	*/
	LDNS_FREE(salt);
	return hashed_owner;
}

bool
ldns_nsec_bitmap_covers_type(const ldns_rdf *nsec_bitmap, ldns_rr_type type)
{
	uint8_t window_block_nr;
	uint8_t bitmap_length;
	uint16_t cur_type;
	uint16_t pos = 0;
	uint16_t bit_pos;
	uint8_t *data = ldns_rdf_data(nsec_bitmap);
	
	while(pos < ldns_rdf_size(nsec_bitmap)) {
		window_block_nr = data[pos];
		bitmap_length = data[pos + 1];
		pos += 2;
		
		for (bit_pos = 0; bit_pos < (bitmap_length) * 8; bit_pos++) {
			if (ldns_get_bit(&data[pos], bit_pos)) {
				cur_type = 256 * (uint16_t) window_block_nr + bit_pos;
				if (cur_type == type) {
					return true;
				}
			}
		}
		
		pos += (uint16_t) bitmap_length;
	}
	return false;
}

bool
ldns_nsec_covers_name(const ldns_rr *nsec, const ldns_rdf *name)
{
	ldns_rdf *nsec_owner = ldns_rr_owner(nsec);
	ldns_rdf *hash_next;
	char *next_hash_str;
	ldns_rdf *nsec_next = NULL;
	ldns_status status;
	ldns_rdf *chopped_dname;
	bool result;
	
	if (ldns_rr_get_type(nsec) == LDNS_RR_TYPE_NSEC) {
		nsec_next = ldns_rdf_clone(ldns_rr_rdf(nsec, 0));
	} else if (ldns_rr_get_type(nsec) == LDNS_RR_TYPE_NSEC3) {
		hash_next = ldns_nsec3_next_owner(nsec);
		next_hash_str = ldns_rdf2str(hash_next);
		nsec_next = ldns_dname_new_frm_str(next_hash_str);
		LDNS_FREE(next_hash_str);
		chopped_dname = ldns_dname_left_chop(nsec_owner);
		status = ldns_dname_cat(nsec_next, chopped_dname);
		ldns_rdf_deep_free(chopped_dname);
		if (status != LDNS_STATUS_OK) {
			printf("error catting: %s\n", ldns_get_errorstr_by_id(status));
		}
	} else {
		ldns_rdf_deep_free(nsec_next);
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
	/* in the case of the last nsec */
	if(ldns_dname_compare(nsec_owner, nsec_next) > 0) {
		result = (ldns_dname_compare(nsec_owner, name) <= 0 ||
				ldns_dname_compare(name, nsec_next) < 0);
	} else {
		result = (ldns_dname_compare(nsec_owner, name) <= 0 &&
		          ldns_dname_compare(name, nsec_next) < 0);
	}
	
	ldns_rdf_deep_free(nsec_next);
	return result;
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

#if 0
ldns_rr_list *
ldns_zone_create_nsecs(const ldns_zone *zone, ldns_rr_list *orig_zone_rrs, ldns_rr_list *glue_rrs)
{
	ldns_rr_list *nsec_rrs = ldns_rr_list_new();
	ldns_rdf *start_dname = NULL;
	ldns_rdf *next_dname = NULL;
	ldns_rdf *cur_dname = NULL;

	ldns_rr *nsec = NULL;
	ldns_rr *next_rr = NULL;
	size_t i;

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
					ldns_rr_list_push_rr(nsec_rrs, nsec);
					/*start_dname = next_dname;*/
					cur_dname = next_dname;
				}
			}
		}
	}
	nsec = ldns_create_nsec(cur_dname, 
					    start_dname,
					    orig_zone_rrs);
	ldns_rr_list_push_rr(nsec_rrs, nsec);
	ldns_rr_set_ttl(nsec, ldns_rdf2native_int32(ldns_rr_rdf(ldns_zone_soa(zone), 6)));

	return nsec_rrs;
}


/* return a clone of the given list without RRSIGS and NSEC(3)'s */
/* if removed_rrs is not null, push clones of sigs and nsecs there */
ldns_rr_list *
ldns_rr_list_strip_dnssec(ldns_rr_list *rr_list, ldns_rr_list *removed_rrs)
{
	size_t i;
	ldns_rr_list *new_list;
	ldns_rr *cur_rr;
	
	if (!rr_list) {
		return NULL;
	}

	new_list = ldns_rr_list_new();

	for (i = 0; i < ldns_rr_list_rr_count(rr_list); i++) {
		cur_rr = ldns_rr_list_rr(rr_list, i);
		if (ldns_rr_get_type(cur_rr) != LDNS_RR_TYPE_RRSIG &&
		    ldns_rr_get_type(cur_rr) != LDNS_RR_TYPE_NSEC &&
		    ldns_rr_get_type(cur_rr) != LDNS_RR_TYPE_NSEC3) {
			ldns_rr_list_push_rr(new_list, ldns_rr_clone(cur_rr));
		} else {
			if (removed_rrs) {
				ldns_rr_list_push_rr(removed_rrs, ldns_rr_clone(cur_rr));
			}
		}
	}

	return new_list;
}
#endif

ldns_status
ldns_dnssec_chain_nsec3_list(ldns_rr_list *nsec3_rrs)
{
	size_t i;
	char *next_nsec_owner_str;
	ldns_rdf *next_nsec_owner_label;
	ldns_rdf *next_nsec_rdf;
	ldns_status status = LDNS_STATUS_OK;

	for (i = 0; i < ldns_rr_list_rr_count(nsec3_rrs); i++) {
		if (i == ldns_rr_list_rr_count(nsec3_rrs) - 1) {
			next_nsec_owner_label = ldns_dname_label(ldns_rr_owner(ldns_rr_list_rr(nsec3_rrs, 0)), 0);
			next_nsec_owner_str = ldns_rdf2str(next_nsec_owner_label);
			if (next_nsec_owner_str[strlen(next_nsec_owner_str) - 1] == '.') {
				next_nsec_owner_str[strlen(next_nsec_owner_str) - 1] = '\0';
			}
			status = ldns_str2rdf_b32_ext(&next_nsec_rdf, next_nsec_owner_str);
			if (!ldns_rr_set_rdf(ldns_rr_list_rr(nsec3_rrs, i), next_nsec_rdf, 4)) {
				/* todo: error */
			}

			ldns_rdf_deep_free(next_nsec_owner_label);
			LDNS_FREE(next_nsec_owner_str);
		} else {
			next_nsec_owner_label = ldns_dname_label(ldns_rr_owner(ldns_rr_list_rr(nsec3_rrs, i + 1)), 0);
			next_nsec_owner_str = ldns_rdf2str(next_nsec_owner_label);
			if (next_nsec_owner_str[strlen(next_nsec_owner_str) - 1] == '.') {
				next_nsec_owner_str[strlen(next_nsec_owner_str) - 1] = '\0';
			}
			status = ldns_str2rdf_b32_ext(&next_nsec_rdf, next_nsec_owner_str);
			ldns_rdf_deep_free(next_nsec_owner_label);
			LDNS_FREE(next_nsec_owner_str);
			if (!ldns_rr_set_rdf(ldns_rr_list_rr(nsec3_rrs, i), next_nsec_rdf, 4)) {
				/* todo: error */
			}
		}
	}
	return status;
}

int
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

void
ldns_rr_list_sort_nsec3(ldns_rr_list *unsorted)
{
	qsort(unsorted->_rrs,
	      ldns_rr_list_rr_count(unsorted),
	      sizeof(ldns_rr *),
	      qsort_rr_compare_nsec3);
}

ldns_status
ldns_dnssec_zone_create_nsec3s(ldns_dnssec_zone *zone,
						 ldns_rr_list *new_rrs,
						 uint8_t algorithm,
						 uint8_t flags,
						 uint16_t iterations,
						 uint8_t salt_length,
						 uint8_t *salt)
{
	ldns_rbnode_t *first_name_node;
	ldns_rbnode_t *current_name_node;
	ldns_dnssec_name *first_name;
	ldns_dnssec_name *current_name;
	ldns_status result = LDNS_STATUS_OK;
	ldns_rr *nsec_rr;
	ldns_rr_list *nsec3_list;
	
	if (!zone || !new_rrs || !zone->names) {
		return LDNS_STATUS_ERR;
	}

	nsec3_list = ldns_rr_list_new();

	first_name_node = ldns_rbtree_first(zone->names);
	first_name = (ldns_dnssec_name *) first_name_node->data;
	
	current_name_node = first_name_node;
	current_name = first_name;

	while (ldns_rbtree_next(current_name_node) != LDNS_RBTREE_NULL) {
		nsec_rr = ldns_dnssec_create_nsec3(current_name,
									(ldns_dnssec_name *) ldns_rbtree_next(current_name_node)->data,
								     zone->soa->name,
									algorithm,
									flags,
									iterations,
									salt_length,
									salt);
		ldns_dnssec_name_add_rr(current_name, nsec_rr);
		ldns_rr_list_push_rr(new_rrs, nsec_rr);
		ldns_rr_list_push_rr(nsec3_list, nsec_rr);
		current_name_node = ldns_rbtree_next(current_name_node);
		current_name = (ldns_dnssec_name *) current_name_node->data;
	}
	nsec_rr = ldns_dnssec_create_nsec3(current_name,
							     first_name,
								zone->soa->name,
								algorithm,
								flags,
								iterations,
								salt_length,
								salt);
	result = ldns_dnssec_name_add_rr(current_name, nsec_rr);
	ldns_rr_list_push_rr(new_rrs, nsec_rr);
	ldns_rr_list_push_rr(nsec3_list, nsec_rr);

	ldns_rr_list_sort_nsec3(nsec3_list);
	ldns_dnssec_chain_nsec3_list(nsec3_list);
	if (result != LDNS_STATUS_OK) {
		return result;
	}
	
	ldns_rr_list_free(nsec3_list);
	return result;
}

int
ldns_dnssec_default_add_to_signatures(ldns_rr *sig, void *n)
{
	sig = sig;
	n = n;
	return LDNS_SIGNATURE_LEAVE_ADD_NEW;
}

int
ldns_dnssec_default_leave_signatures(ldns_rr *sig, void *n)
{
	sig = sig;
	n = n;
	return LDNS_SIGNATURE_LEAVE_NO_ADD;
}

int
ldns_dnssec_default_delete_signatures(ldns_rr *sig, void *n)
{
	sig = sig;
	n = n;
	return LDNS_SIGNATURE_REMOVE_NO_ADD;
}

int
ldns_dnssec_default_replace_signatures(ldns_rr *sig, void *n)
{
	sig = sig;
	n = n;
	return LDNS_SIGNATURE_REMOVE_ADD_NEW;
}

#endif /* HAVE_SSL */
