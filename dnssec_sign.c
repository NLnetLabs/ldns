#include <ldns/config.h>

#include <ldns/ldns.h>

#include <ldns/dnssec.h>
#include <ldns/dnssec_sign.h>

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
	ldns_rdf_deep_free(wildcard_label);
	ldns_rdf_deep_free(first_label);

	/* make it canonical */
	for(i = 0; i < ldns_rr_list_rr_count(rrset_clone); i++) {
		ldns_rr2canonical(ldns_rr_list_rr(rrset_clone, i));
	}
	/* sort */
	ldns_rr_list_sort(rrset_clone);
	
	for (key_count = 0; key_count < ldns_key_list_key_count(keys); key_count++) {
		if (!ldns_key_use(ldns_key_list_key(keys, key_count))) {
			continue;
		}
		sign_buf = ldns_buffer_new(LDNS_MAX_PACKETLEN);
		if (!sign_buf) {
			printf("[XX]ERROR NO SIGN BUG, OUT OF MEM?\n");
			ldns_rr_list_print(stdout, rrset_clone);
			while(true) {
				sleep(1);
				printf(".");
				fflush(stdout);
			}
			exit(123);
		}
		b64rdf = NULL;

		current_key = ldns_key_list_key(keys, key_count);
		/* sign all RRs with keys that have ZSKbit, !SEPbit.
		   sign DNSKEY RRs with keys that have ZSKbit&SEPbit */
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
			/*printf("SETTING KEYTAG TO: %u\n", ldns_key_keytag(current_key));*/
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
				/* ERROR */
				ldns_rr_list_deep_free(rrset_clone);
				return NULL;
			}
			/* add the rrset in sign_buf */

			if (ldns_rr_list2buffer_wire(sign_buf, rrset_clone) != LDNS_STATUS_OK) {
				ldns_buffer_free(sign_buf);
				ldns_rr_list_deep_free(rrset_clone);
				return NULL;
			}
			
			switch(ldns_key_algorithm(current_key)) {
			case LDNS_SIGN_DSA:
			case LDNS_DSA_NSEC3:
				b64rdf = ldns_sign_public_evp(sign_buf, ldns_key_evp_key(current_key), EVP_dss1());
				/*					b64rdf = ldns_sign_public_dsa(sign_buf, ldns_key_dsa_key(current_key));*/
				break;
			case LDNS_SIGN_RSASHA1:
			case LDNS_SIGN_RSASHA1_NSEC3:
				b64rdf = ldns_sign_public_evp(sign_buf, ldns_key_evp_key(current_key), EVP_sha1());
				break;
#ifdef SHA256_DIGEST_LENGTH
			case LDNS_SIGN_RSASHA256:
			case LDNS_SIGN_RSASHA256_NSEC3:
				b64rdf = ldns_sign_public_evp(sign_buf, ldns_key_evp_key(current_key), EVP_sha256());
				break;
#endif
#ifdef SHA512_DIGEST_LENGTH
			case LDNS_SIGN_RSASHA512:
			case LDNS_SIGN_RSASHA512_NSEC3:
				b64rdf = ldns_sign_public_evp(sign_buf, ldns_key_evp_key(current_key), EVP_sha512());

				break;
#endif
			case LDNS_SIGN_RSAMD5:
				b64rdf = ldns_sign_public_evp(sign_buf, ldns_key_evp_key(current_key), EVP_md5());
				break;
			default:
				/* do _you_ know this alg? */
				printf("unknown algorithm, is the one used available on this system?\n");
				break;
			}
			if (!b64rdf) {
				/* signing went wrong */
				ldns_rr_list_deep_free(rrset_clone);
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
ldns_sign_public_evp(ldns_buffer *to_sign,
				 EVP_PKEY *key,
				 const EVP_MD *digest_type)
{
	unsigned int siglen;
	ldns_rdf *sigdata_rdf;
	ldns_buffer *b64sig;
	EVP_MD_CTX ctx;
	const EVP_MD *md_type;
	int r;

	siglen = 0;
	b64sig = ldns_buffer_new(LDNS_MAX_PACKETLEN);
	if (!b64sig) {
		return NULL;
	}

	/* initializes a signing context */
	md_type = digest_type;
	if(!md_type) {
		printf("Unknown message digest");
		exit(1);
	}

	EVP_MD_CTX_init(&ctx);
	r = EVP_SignInit(&ctx, md_type);
	if(r == 1)
		r = EVP_SignUpdate(&ctx, (unsigned char*)
					    ldns_buffer_begin(to_sign), 
					    ldns_buffer_position(to_sign));
	if(r == 1)
		r = EVP_SignFinal(&ctx, (unsigned char*)
					   ldns_buffer_begin(b64sig), &siglen, key);
	if(r != 1) {
		ldns_buffer_free(b64sig);
		return NULL;
	}

	sigdata_rdf = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_B64, siglen,
								 ldns_buffer_begin(b64sig));
	ldns_buffer_free(b64sig);
	EVP_MD_CTX_cleanup(&ctx);
	return sigdata_rdf;
}


ldns_rdf *
ldns_sign_public_rsasha1(ldns_buffer *to_sign, RSA *key)
{
	unsigned char *sha1_hash;
	unsigned int siglen;
	ldns_rdf *sigdata_rdf;
	ldns_buffer *b64sig;
	int result;

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

	result = RSA_sign(NID_sha1, sha1_hash, SHA_DIGEST_LENGTH,
				   (unsigned char*)ldns_buffer_begin(b64sig),
				   &siglen, key);
	if (result != 1) {
		return NULL;
	}

	if (result != 1) {
		return NULL;
	}

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

ldns_status
ldns_dnssec_zone_create_nsecs(ldns_dnssec_zone *zone,
						ldns_rr_list *new_rrs,
						ldns_rr_type nsec_type)
{
	ldns_rbnode_t *first_name_node;
	ldns_rbnode_t *current_name_node;
	ldns_dnssec_name *first_name;
	ldns_dnssec_name *current_name;
	ldns_status result = LDNS_STATUS_OK;
	ldns_rr *nsec_rr;

	if (!zone || !new_rrs || !zone->names) {
		return LDNS_STATUS_ERR;
	}

	first_name_node = ldns_rbtree_first(zone->names);
	first_name = (ldns_dnssec_name *) first_name_node->data;
	
	current_name_node = first_name_node;
	current_name = first_name;

	switch (nsec_type) {
	case LDNS_RR_TYPE_NSEC:
		while (ldns_rbtree_next(current_name_node) != LDNS_RBTREE_NULL) {
			nsec_rr = ldns_dnssec_create_nsec(current_name,
									    (ldns_dnssec_name *) ldns_rbtree_next(current_name_node)->data,
									    nsec_type);
			ldns_dnssec_name_add_rr(current_name, nsec_rr);
			ldns_rr_list_push_rr(new_rrs, nsec_rr);
			current_name_node = ldns_rbtree_next(current_name_node);
			current_name = (ldns_dnssec_name *) current_name_node->data;
		}
		nsec_rr = ldns_dnssec_create_nsec(current_name,
								    first_name,
								    nsec_type);
		result = ldns_dnssec_name_add_rr(current_name, nsec_rr);
		if (result != LDNS_STATUS_OK) {
			return result;
		}
		ldns_rr_list_push_rr(new_rrs, nsec_rr);
		break;
	case LDNS_RR_TYPE_NSEC3:
		break;
	default:
		return LDNS_STATUS_ERR;
	}

	return result;
}

ldns_dnssec_rrs *
ldns_dnssec_remove_signatures(ldns_dnssec_rrs *signatures,
						ldns_key_list *key_list,
						int (*func)(ldns_rr *, void *),
						void *arg) {
	ldns_dnssec_rrs *base_rrs = signatures;
	ldns_dnssec_rrs *cur_rr = base_rrs;
	ldns_dnssec_rrs *prev_rr = NULL;
	ldns_dnssec_rrs *next_rr;

	uint16_t keytag;
	size_t i;
	int v;

	key_list = key_list;

	if (!cur_rr) {
		switch(func(NULL, arg)) {
		case LDNS_SIGNATURE_LEAVE_ADD_NEW:
		case LDNS_SIGNATURE_REMOVE_ADD_NEW:
		break;
		case LDNS_SIGNATURE_LEAVE_NO_ADD:
		case LDNS_SIGNATURE_REMOVE_NO_ADD:
		ldns_key_list_set_use(key_list, false);
		break;
		default:
			fprintf(stderr, "[XX] unknown return value from callback\n");
			break;
		}
		return NULL;
	}
	v = func(cur_rr->rr, arg);

	while (cur_rr) {
		next_rr = cur_rr->next;
		
		switch (func(cur_rr->rr, arg)) {
		case  LDNS_SIGNATURE_LEAVE_ADD_NEW:
			prev_rr = cur_rr;
			break;
		case LDNS_SIGNATURE_LEAVE_NO_ADD:
			keytag = ldns_rdf2native_int16(ldns_rr_rrsig_keytag(cur_rr->rr));
			for (i = 0; i < ldns_key_list_key_count(key_list); i++) {
				if (ldns_key_keytag(ldns_key_list_key(key_list, i)) ==
				    keytag) {
					ldns_key_set_use(ldns_key_list_key(key_list, i),
								  false);
				}
			}
			prev_rr = cur_rr;
			break;
		case LDNS_SIGNATURE_REMOVE_NO_ADD:
			keytag = ldns_rdf2native_int16(ldns_rr_rrsig_keytag(cur_rr->rr));
			for (i = 0; i < ldns_key_list_key_count(key_list); i++) {
				if (ldns_key_keytag(ldns_key_list_key(key_list, i)) ==
				    keytag) {
					ldns_key_set_use(ldns_key_list_key(key_list, i),
								  false);
				}
			}
			if (prev_rr) {
				prev_rr->next = next_rr;
			} else {
				base_rrs = next_rr;
			}
			LDNS_FREE(cur_rr);
			break;
		case LDNS_SIGNATURE_REMOVE_ADD_NEW:
			if (prev_rr) {
				prev_rr->next = next_rr;
			} else {
				base_rrs = next_rr;
			}
			LDNS_FREE(cur_rr);
			break;
		default:
			fprintf(stderr, "[XX] unknown return value from callback\n");
			break;
		}
		cur_rr = next_rr;
	}

	return base_rrs;
}

ldns_status
ldns_dnssec_zone_create_rrsigs(ldns_dnssec_zone *zone,
						 ldns_rr_list *new_rrs,
						 ldns_key_list *key_list,
						 int (*func)(ldns_rr *, void*),
						 void *arg) {
	ldns_status result = LDNS_STATUS_OK;
	zone = zone;
	new_rrs = new_rrs;
	key_list = key_list;
	//bool sign_list = true;
	ldns_rbnode_t *cur_node;
	ldns_rr_list *rr_list;

	ldns_dnssec_name *cur_name;
	ldns_dnssec_rrsets *cur_rrset;
	ldns_dnssec_rrs *cur_rr;

	ldns_rr_list *siglist;
	
	size_t i;

	ldns_rr_list *pubkey_list = ldns_rr_list_new();
	for (i = 0; i<ldns_key_list_key_count(key_list); i++) {
		ldns_rr_list_push_rr(pubkey_list, ldns_key2rr(ldns_key_list_key(key_list, i)));
	}
	/* TODO: callback to see is list should be signed */
	/* TODO: remove 'old' signatures from signature list */
	cur_node = ldns_rbtree_first(zone->names);
	while (cur_node != LDNS_RBTREE_NULL) {
		cur_name = (ldns_dnssec_name *) cur_node->data;

		cur_rrset = cur_name->rrsets;
		while (cur_rrset) {
			/* reset keys to use */
			ldns_key_list_set_use(key_list, true);

			/* walk through old sigs, remove the old, and mark which keys (not) to use) */
			cur_rrset->signatures = ldns_dnssec_remove_signatures(cur_rrset->signatures,
													    key_list,
													    func,
													    arg);

			/* TODO: set count to zero? */
			rr_list = ldns_rr_list_new();

			cur_rr = cur_rrset->rrs;
			while (cur_rr) {
				ldns_rr_list_push_rr(rr_list, cur_rr->rr);
				cur_rr = cur_rr->next;
			}

			siglist = ldns_sign_public(rr_list, key_list);
			for (i = 0; i < ldns_rr_list_rr_count(siglist); i++) {
				if (cur_rrset->signatures) {
					ldns_dnssec_rrs_add_rr(cur_rrset->signatures,
									   ldns_rr_list_rr(siglist, i));
				} else {
					cur_rrset->signatures = ldns_dnssec_rrs_new();
					cur_rrset->signatures->rr = ldns_rr_list_rr(siglist, i);
					ldns_rr_list_push_rr(new_rrs, ldns_rr_list_rr(siglist, i));
				}
			}


			ldns_rr_list_free(siglist);
			ldns_rr_list_free(rr_list);

			cur_rrset = cur_rrset->next;
		}

		/* sign the nsec */
		cur_name->nsec_signatures = ldns_dnssec_remove_signatures(cur_name->nsec_signatures,
													   key_list,
													   func,
													   arg);

		rr_list = ldns_rr_list_new();
		ldns_rr_list_push_rr(rr_list, cur_name->nsec);
		siglist = ldns_sign_public(rr_list, key_list);
		
		for (i = 0; i < ldns_rr_list_rr_count(siglist); i++) {
			if (cur_name->nsec_signatures) {
				ldns_dnssec_rrs_add_rr(cur_name->nsec_signatures,
								   ldns_rr_list_rr(siglist, i));
			} else {
				cur_name->nsec_signatures = ldns_dnssec_rrs_new();
				cur_name->nsec_signatures->rr = ldns_rr_list_rr(siglist, i);
				ldns_rr_list_push_rr(new_rrs, ldns_rr_list_rr(siglist, i));
			}
		}

		printf("[XX] Verifying signature for: ");
		ldns_rdf_print(stdout, cur_name->name);
		printf("\n");
		ldns_rr_list_print(stdout, rr_list);
		result = ldns_verify(rr_list, siglist, pubkey_list, NULL);
		printf("%s\n", ldns_get_errorstr_by_id(result));

		ldns_rr_list_free(siglist);
		ldns_rr_list_free(rr_list);

		cur_node = ldns_rbtree_next(cur_node);
	}

	return result;
}

ldns_status
ldns_dnssec_zone_sign(ldns_dnssec_zone *zone,
				  ldns_rr_list *new_rrs,
				  ldns_key_list *key_list,
				  int (*func)(ldns_rr *, void *),
				  void *arg)
{
	ldns_status result = LDNS_STATUS_OK;

	if (!zone || !new_rrs || !key_list) {
		return LDNS_STATUS_ERR;
	}

	/* zone is already sorted */
	
	/* check whether we need to add nsecs */
	if (zone->names && !((ldns_dnssec_name *)zone->names->root->data)->nsec) {
		result = ldns_dnssec_zone_create_nsecs(zone, new_rrs, LDNS_RR_TYPE_NSEC);
		if (result != LDNS_STATUS_OK) {
			return result;
		}
	}

	printf("[XX] Create signatures!\n");
	result = ldns_dnssec_zone_create_rrsigs(zone,
									new_rrs,
									key_list,
									func,
									arg);
	printf("[XX] done\n");

	return result;
}

ldns_status
ldns_dnssec_zone_sign_nsec3(ldns_dnssec_zone *zone,
					   ldns_rr_list *new_rrs,
					   ldns_key_list *key_list,
					   int (*func)(ldns_rr *, void *),
					   void *arg,
					   uint8_t algorithm,
					   uint8_t flags,
					   uint16_t iterations,
					   uint8_t salt_length,
					   uint8_t *salt)
{
	ldns_rr *nsec3, *nsec3params;
	ldns_status result = LDNS_STATUS_OK;

	/* TODO if there are already nsec3s presents and their
	 * parameters are the same as these, we don't have to recreate
	 */
	if (zone->names) {
		/* add empty nonterminals */
		ldns_dnssec_zone_add_empty_nonterminals(zone);

		nsec3 = ((ldns_dnssec_name *)zone->names->root->data)->nsec;
		if (nsec3 && ldns_rr_get_type(nsec3) == LDNS_RR_TYPE_NSEC3) {
			// no need to recreate
		} else {
			if (!ldns_dnssec_zone_find_rrset(zone,
									   zone->soa->name,
									   LDNS_RR_TYPE_NSEC3PARAMS)) {
				/* create and add the nsec3params rr */
				nsec3params = ldns_rr_new_frm_type(LDNS_RR_TYPE_NSEC3PARAMS);
				ldns_rr_set_owner(nsec3params, ldns_rdf_clone(zone->soa->name));
				ldns_nsec3_add_param_rdfs(nsec3params, algorithm, flags, iterations, salt_length, salt);
				ldns_dnssec_zone_add_rr(zone, nsec3params);
				ldns_rr_list_push_rr(new_rrs, nsec3params);
			}
			result = ldns_dnssec_zone_create_nsec3s(zone,
											new_rrs,
											algorithm,
											flags,
											iterations,
											salt_length,
											salt);
			if (result != LDNS_STATUS_OK) {
				return result;
			}
		}

		result = ldns_dnssec_zone_create_rrsigs(zone,
										new_rrs,
										key_list,
										func,
										arg);
	}
	
	return result;
}


ldns_zone *
ldns_zone_sign(const ldns_zone *zone, ldns_key_list *key_list)
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
	zone = zone;
	key_list = key_list;
	return NULL;
#if 0 
	/*TODO: use _dnssec_zone_sign*/
	ldns_zone *signed_zone;
	/*
	  ldns_rr_list *cur_rrset;
	*/
	ldns_rr_list *cur_rrsigs;

	ldns_rr_list *orig_zone_rrs;
	ldns_rr_list *signed_zone_rrs;
	ldns_rr_list *pubkeys;
	ldns_rr_list *glue_rrs;
	ldns_rr_list *rrsig_rrs = NULL;
	
	/*
	ldns_rdf *start_dname = NULL;
	ldns_rdf *cur_dname = NULL;
	ldns_rr *next_rr = NULL;
	ldns_rdf *next_dname = NULL;
	ldns_rr *nsec;
	*/
	ldns_rr *ckey;
	uint16_t i;

	signed_zone = ldns_zone_new();

	/* there should only be 1 SOA, so the soa record is 1 rrset */
	cur_rrsigs = NULL;
	ldns_zone_set_soa(signed_zone, ldns_rr_clone(ldns_zone_soa(zone)));
	ldns_rr2canonical(ldns_zone_soa(signed_zone));
	
	orig_zone_rrs = ldns_rr_list_clone(ldns_zone_rrs(zone));

	ldns_rr_list_push_rr(orig_zone_rrs, ldns_rr_clone(ldns_zone_soa(zone)));
	
	/* canon now, needed for correct nsec creation */
	for (i = 0; i < ldns_rr_list_rr_count(orig_zone_rrs); i++) {
		ldns_rr2canonical(ldns_rr_list_rr(orig_zone_rrs, i));
	}
	glue_rrs = ldns_zone_glue_rr_list(zone);

	/* add the key (TODO: check if it's there already? */
	pubkeys = ldns_rr_list_new();
	for (i = 0; i < ldns_key_list_key_count(key_list); i++) {
		ckey = ldns_key2rr(ldns_key_list_key(key_list, i));
		ldns_rr_list_push_rr(pubkeys, ckey);
	}

	signed_zone_rrs = ldns_rr_list_strip_dnssec(orig_zone_rrs, NULL);

	ldns_rr_list_deep_free(orig_zone_rrs);

	if (!signed_zone_rrs) {
		printf("error!\n");
		exit(1);
	}

	
	ldns_rr_list_sort(signed_zone_rrs);
	/*
	nsec_rrs = ldns_zone_create_nsecs(zone, signed_zone_rrs, glue_rrs);

	ldns_rr_list_cat(signed_zone_rrs, nsec_rrs);
			if (!cur_rrsigs) {
				ldns_zone_deep_free(signed_zone);
				ldns_rr_list_deep_free(signed_zone_rrs);
				ldns_rr_list_deep_free(pubkeys);
				ldns_rr_list_free(glue_rrs);
				return NULL;
			}
	ldns_rr_list_free(nsec_rrs);
	*/
	/*
	rrsig_rrs = ldns_zone_create_rrsigs(signed_zone, signed_zone_rrs, glue_rrs, key_list);
	*/

	ldns_rr_list_cat(signed_zone_rrs, rrsig_rrs);
	ldns_rr_list_free(rrsig_rrs);

	ldns_rr_list_deep_free(ldns_zone_rrs(signed_zone));
	ldns_zone_set_rrs(signed_zone, ldns_rr_list_clone(signed_zone_rrs));
	
	ldns_rr_list_deep_free(signed_zone_rrs);
	ldns_rr_list_deep_free(pubkeys);
	ldns_rr_list_free(glue_rrs);

	return signed_zone;
#endif	
}

ldns_zone *
ldns_zone_sign_nsec3(ldns_zone *zone, ldns_key_list *key_list, uint8_t algorithm, uint8_t flags, uint16_t iterations, uint8_t salt_length, uint8_t *salt)
{
	zone = zone;
	key_list = key_list;
	algorithm = algorithm;
	flags = flags;
	iterations = iterations;
	salt_length = salt_length;
	salt = salt;
	return NULL;
#if 0
	/* TODO use _dnssec_zone_sign */
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
	ldns_rr_list *cur_rrsigs;
	ldns_rr_list *orig_zone_rrs;
	ldns_rr_list *signed_zone_rrs;
	ldns_rr_list *pubkeys;
	ldns_rr_list *glue_rrs;
	ldns_rr_list *nsec3_rrs;
	ldns_rr *nsec3params;
	
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
	uint16_t next_label_count;
	uint16_t cur_label_count;

	/* for the empty nonterminal finding algorithm */
	uint16_t j;
	ldns_rdf *l1, *l2, *post, *post2;
	bool found_difference;
	
	ldns_rr_type cur_rrset_type;
	
	signed_zone = ldns_zone_new();

	/* there should only be 1 SOA, so the soa record is 1 rrset */
	cur_rrsigs = NULL;
	ldns_zone_set_soa(signed_zone, ldns_rr_clone(ldns_zone_soa(zone)));
	/*ldns_rr2canonical(ldns_zone_soa(signed_zone));*/
	
	orig_zone_rrs = ldns_rr_list_clone(ldns_zone_rrs(zone));

	ldns_rr_list_push_rr(orig_zone_rrs, ldns_rr_clone(ldns_zone_soa(zone)));
	
	/* canon now, needed for correct nsec creation */
	/*
	for (i = 0; i < ldns_rr_list_rr_count(orig_zone_rrs); i++) {
		ldns_rr2canonical(ldns_rr_list_rr(orig_zone_rrs, i));
	}
	*/
	glue_rrs = ldns_zone_glue_rr_list(zone);

	/* create and add the nsec3params rr */
	nsec3params = ldns_rr_new_frm_type(LDNS_RR_TYPE_NSEC3PARAMS);
	ldns_rr_set_owner(nsec3params, ldns_rdf_clone(ldns_rr_owner(ldns_zone_soa(signed_zone))));
	ldns_nsec3_add_param_rdfs(nsec3params, algorithm, flags, iterations, salt_length, salt);
/*	ldns_rdf_set_type(ldns_rr_rdf(nsec3params, 0), LDNS_RDF_TYPE_NSEC3_PARAMS_VARS);*/
	ldns_rr_list_push_rr(orig_zone_rrs, nsec3params);
/*
ldns_rr_print(stdout, nsec3params);
exit(0);
*/
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

				/* every ownername should have an nsec3, and every empty nonterminal */
				/* the zone is sorted, so nonterminals should be visible? */
				/* if labels after first differ with previous it's an empty nonterm? */

				/* empty non-terminal detection algorithm 0.001a-pre1
				 * walk backwards to the first different label. for each label that
				 * is not the first label, we have found an empty nonterminal
				 */
				cur_label_count = ldns_dname_label_count(cur_dname);
				next_label_count = ldns_dname_label_count(next_dname);
				post = ldns_dname_new_frm_str(".");
				found_difference = false;
				for (j = 1; j <= cur_label_count && j <= next_label_count && !found_difference; j++) {
					l1 = ldns_dname_label(cur_dname, cur_label_count - j);
					l2 = ldns_dname_label(next_dname, next_label_count - j);
					
					post2 = ldns_dname_cat_clone(l2, post);
					ldns_rdf_deep_free(post);
					post = post2;

					if (ldns_dname_compare(l1, l2) != 0 &&
					    /*j < cur_label_count &&*/
					    j < next_label_count
					   ) {
					        /*
						printf("Found empty non-terminal: ");
						ldns_rdf_print(stdout, post);
						printf("\n");
						*/
						found_difference = true;
						nsec = ldns_create_nsec3(post, 
									ldns_rr_owner(ldns_zone_soa(zone)),
									orig_zone_rrs,
									algorithm,
									false,
									iterations,
									salt_length,
									salt,
									true);
						
						/*printf("Created NSEC3 for: ");
						ldns_rdf_print(stdout, post);
						printf(":\n");
						ldns_rr_print(stdout, nsec);
						*/
						ldns_rr_set_ttl(nsec, ldns_rdf2native_int32(ldns_rr_rdf(ldns_zone_soa(zone), 6)));
						ldns_rr_list_push_rr(nsec3_rrs, nsec);
					}
					ldns_rdf_deep_free(l1);
					ldns_rdf_deep_free(l2);
				}
				/* and if next label is longer than cur + 1, these must be empty nons too */
				/* skip current label (total now equal to cur_dname) */
				if (!found_difference && j < cur_label_count && j < next_label_count) {
					l2 = ldns_dname_label(next_dname, next_label_count - j);
					post2 = ldns_dname_cat_clone(l2, post);
					ldns_rdf_deep_free(post);
					post = post2;
					j++;
				}
				while (j < next_label_count) {
					l2 = ldns_dname_label(next_dname, next_label_count - j);
					post2 = ldns_dname_cat_clone(l2, post);
					ldns_rdf_deep_free(post);
					post = post2;
					/*
					printf("Found empty non-terminal: ");
					ldns_rdf_print(stdout, post);
					printf("\n");
					*/
					ldns_rdf_deep_free(l2);
					j++;	
					nsec = ldns_create_nsec3(post, 
								ldns_rr_owner(ldns_zone_soa(zone)),
								orig_zone_rrs,
								algorithm,
								false,
								iterations,
								salt_length,
								salt,
								true);
/*
					printf("Created NSEC3 for: ");
					ldns_rdf_print(stdout, post);
					printf(":\n");
					ldns_rr_print(stdout, nsec);
*/
					ldns_rr_set_ttl(nsec, ldns_rdf2native_int32(ldns_rr_rdf(ldns_zone_soa(zone), 6)));
					ldns_rr_list_push_rr(nsec3_rrs, nsec);
				}
				ldns_rdf_deep_free(post);

				/* skip glue */
				if (ldns_rr_list_contains_rr(glue_rrs, next_rr)) {
/*					cur_dname = next_dname;*/
					printf("Skip glue: ");
					ldns_rdf_print(stdout, cur_dname);
					printf("\n");
				} else {
					nsec = ldns_create_nsec3(cur_dname, 
								ldns_rr_owner(ldns_zone_soa(zone)),
								orig_zone_rrs,
								algorithm,
								false,
								iterations,
								salt_length,
								salt,
								false);

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
				salt,
				false);
	ldns_rr_list_set_rr(nsec3_rrs, nsec, 4);
	ldns_rr_list_free(orig_zone_rrs);
	ldns_rr_set_ttl(nsec, ldns_rdf2native_int32(ldns_rr_rdf(ldns_zone_soa(zone), 6)));
	ldns_rr_list_push_rr(nsec3_rrs, nsec);

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
			if (!ldns_rr_set_rdf(ldns_rr_list_rr(nsec3_rrs, i), next_nsec_rdf, 4)) {
				/* todo: error */
			}
		} else {
			next_nsec_owner_str = ldns_rdf2str(ldns_dname_label(ldns_rr_owner(ldns_rr_list_rr(nsec3_rrs, i + 1)), 0));
			if (next_nsec_owner_str[strlen(next_nsec_owner_str) - 1] == '.') {
				next_nsec_owner_str[strlen(next_nsec_owner_str) - 1] = '\0';
			}
			status = ldns_str2rdf_b32_ext(&next_nsec_rdf, next_nsec_owner_str);
			if (!ldns_rr_set_rdf(ldns_rr_list_rr(nsec3_rrs, i), next_nsec_rdf, 4)) {
				/* todo: error */
			}
		}
	}
	
	ldns_rr_list_cat(signed_zone_rrs, nsec3_rrs);
/*
printf("going to sort:\n");
ldns_rr_list_print(stdout, signed_zone_rrs);
*/
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
			((ldns_dname_is_subdomain(cur_dname, ldns_rr_owner(ldns_zone_soa(signed_zone)))
			  && cur_rrset_type != LDNS_RR_TYPE_NS
			 ) ||
			 ldns_rdf_compare(cur_dname, ldns_rr_owner(ldns_zone_soa(signed_zone))) == 0
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
			} else {
				printf("VERIFIED\n");
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
	ldns_rr_list_deep_free(signed_zone_rrs);
	ldns_rr_list_deep_free(pubkeys);
	ldns_rr_list_free(glue_rrs);
	return signed_zone;
#endif
	
}

#endif
