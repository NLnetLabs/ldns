/*
 * chasetrace.c
 * Where all the hard work concerning chasing
 * and tracing is done
 * (c) 2005, 2006 NLnet Labs
 *
 * See the file LICENSE for the license
 *
 */

#include "drill.h"
#include <ldns/ldns.h>

/**
 * trace down from the root to name
 */

/* same naive method as in drill0.9 
 * We resolver _ALL_ the names, which is ofcourse not needed
 * We _do_ use the local resolver to do that, so it still is
 * fast, but it can be made to run much faster
 */
ldns_pkt *
do_trace(ldns_resolver *local_res, ldns_rdf *name, ldns_rr_type t,
		ldns_rr_class c)
{
	ldns_resolver *res;
	ldns_pkt *p;
	ldns_rr_list *new_nss_a;
	ldns_rr_list *new_nss_aaaa;
	ldns_rr_list *final_answer;
	ldns_rr_list *new_nss;
	ldns_rr_list *hostnames;
	ldns_rr_list *ns_addr;
	uint16_t loop_count;
	ldns_rdf *pop; 
	ldns_status status;
	size_t i;
	
	loop_count = 0;
	new_nss_a = NULL;
	new_nss_aaaa = NULL;
	new_nss = NULL;
	ns_addr = NULL;
	final_answer = NULL;
	p = ldns_pkt_new();
	res = ldns_resolver_new();

	if (!p || !res) {
                error("Memory allocation failed");
                return NULL;
        }

	/* transfer some properties of local_res to res,
	 * because they were given on the commandline */
	ldns_resolver_set_ip6(res, 
			ldns_resolver_ip6(local_res));
	ldns_resolver_set_port(res, 
			ldns_resolver_port(local_res));
	ldns_resolver_set_debug(res, 
			ldns_resolver_debug(local_res));
	ldns_resolver_set_dnssec(res, 
			ldns_resolver_dnssec(local_res));
	ldns_resolver_set_fail(res, 
			ldns_resolver_fail(local_res));
	ldns_resolver_set_usevc(res, 
			ldns_resolver_usevc(local_res));
	ldns_resolver_set_random(res, 
			ldns_resolver_random(local_res));
	ldns_resolver_set_recursive(res, false);

	/* setup the root nameserver in the new resolver */
	if (ldns_resolver_push_nameserver_rr_list(res, global_dns_root) != LDNS_STATUS_OK) {
		return NULL;
	}

	/* this must be a real query to local_res */
	status = ldns_resolver_send(&p, local_res, ldns_dname_new_frm_str("."), LDNS_RR_TYPE_NS, c, 0);
	/* p can still be NULL */


	if (ldns_pkt_empty(p)) {
		warning("No root server information received");
	} 
	
	if (status == LDNS_STATUS_OK) {
		if (!ldns_pkt_empty(p)) {
			drill_pkt_print(stdout, local_res, p);
		}
	} else {
		error("cannot use local resolver");
		return NULL;
	}

	status = ldns_resolver_send(&p, res, name, t, c, 0);

	while(status == LDNS_STATUS_OK && 
	      ldns_pkt_reply_type(p) == LDNS_PACKET_REFERRAL) {

		if (!p) {
			/* some error occurred, bail out */
			return NULL;
		}

		new_nss_a = ldns_pkt_rr_list_by_type(p,
				LDNS_RR_TYPE_A, LDNS_SECTION_ADDITIONAL);
		new_nss_aaaa = ldns_pkt_rr_list_by_type(p,
				LDNS_RR_TYPE_AAAA, LDNS_SECTION_ADDITIONAL);
		new_nss = ldns_pkt_rr_list_by_type(p,
				LDNS_RR_TYPE_NS, LDNS_SECTION_AUTHORITY);

		if (qdebug != -1) {
			ldns_rr_list_print(stdout, new_nss);
		}
		/* checks itself for qdebug */
		drill_pkt_print_footer(stdout, local_res, p);
		
		/* remove the old nameserver from the resolver */
		while((pop = ldns_resolver_pop_nameserver(res))) { /* do it */ }

		/* also check for new_nss emptyness */

		if (!new_nss_aaaa && !new_nss_a) {
			/* 
			 * no nameserver found!!! 
			 * try to resolve the names we do got 
			 */
			for(i = 0; i < ldns_rr_list_rr_count(new_nss); i++) {
				/* get the name of the nameserver */
				pop = ldns_rr_rdf(ldns_rr_list_rr(new_nss, i), 0);
				if (!pop) {
					break;
				}

				ldns_rr_list_print(stdout, new_nss);
				ldns_rdf_print(stdout, pop);
				/* retrieve it's addresses */
				ns_addr = ldns_rr_list_cat_clone(ns_addr,
					ldns_get_rr_list_addr_by_name(local_res, pop, c, 0));
			}

			if (ns_addr) {
				if (ldns_resolver_push_nameserver_rr_list(res, ns_addr) != 
						LDNS_STATUS_OK) {
					error("Error adding new nameservers");
					ldns_pkt_free(p); 
					return NULL;
				}
				ldns_rr_list_free(ns_addr);
			} else {
				ldns_rr_list_print(stdout, ns_addr);
				error("Could not find the nameserver ip addr; abort");
				ldns_pkt_free(p);
				return NULL;
			}
		}

		/* add the new ones */
		if (new_nss_aaaa) {
			if (ldns_resolver_push_nameserver_rr_list(res, new_nss_aaaa) != 
					LDNS_STATUS_OK) {
				error("adding new nameservers");
				ldns_pkt_free(p); 
				return NULL;
			}
		}
		if (new_nss_a) {
			if (ldns_resolver_push_nameserver_rr_list(res, new_nss_a) != 
					LDNS_STATUS_OK) {
				error("adding new nameservers");
				ldns_pkt_free(p); 
				return NULL;
			}
		}

		if (loop_count++ > 20) {
			/* unlikely that we are doing something usefull */
			error("Looks like we are looping");
			ldns_pkt_free(p); 
			return NULL;
		}
		
		status = ldns_resolver_send(&p, res, name, t, c, 0);
		new_nss_aaaa = NULL;
		new_nss_a = NULL;
		ns_addr = NULL;
	}

	status = ldns_resolver_send(&p, res, name, t, c, 0);

	if (!p) {
		return NULL;
	}

	hostnames = ldns_get_rr_list_name_by_addr(local_res, 
			ldns_pkt_answerfrom(p), 0, 0);

	new_nss = ldns_pkt_authority(p);
	final_answer = ldns_pkt_answer(p);

	if (qdebug != -1) {
		ldns_rr_list_print(stdout, final_answer);
		ldns_rr_list_print(stdout, new_nss);

	}
	drill_pkt_print_footer(stdout, local_res, p);
	ldns_pkt_free(p); 
	return NULL;
}


/* NSEC3 draft -05 */
/*return hash name match*/
ldns_rr *
ldns_nsec3_exact_match(ldns_rdf *qname, ldns_rr_type qtype, ldns_rr_list *nsec3s) {
	uint8_t algorithm;
	uint32_t iterations;
	uint8_t salt_length;
	uint8_t *salt;
	
	ldns_rdf *sname, *hashed_sname;
	
	size_t nsec_i;
	ldns_rr *nsec;
	ldns_rr *result = NULL;
	
	ldns_status status;
	
	ldns_rdf *zone_name;
	
	printf(";; finding exact match for type %d ", qtype);
	ldns_rdf_print(stdout, qname);
	printf("\n");
	if (!qname || !nsec3s || ldns_rr_list_rr_count(nsec3s) < 1) {
		printf("no qname, nsec3s or list empty\n");
		return NULL;
	}

	nsec = ldns_rr_list_rr(nsec3s, 0);
	algorithm = ldns_nsec3_algorithm(nsec);
	salt_length = ldns_nsec3_salt_length(nsec);
	salt = ldns_nsec3_salt(nsec);
	iterations = ldns_nsec3_iterations(nsec);

	sname = ldns_rdf_clone(qname);

	printf(";; owner name hashes to: ");
	hashed_sname = ldns_nsec3_hash_name(sname, algorithm, iterations, salt_length, salt);

	zone_name = ldns_dname_left_chop(ldns_rr_owner(nsec));
	status = ldns_dname_cat(hashed_sname, zone_name);
	ldns_rdf_print(stdout, hashed_sname);
	printf("\n");

	for (nsec_i = 0; nsec_i < ldns_rr_list_rr_count(nsec3s); nsec_i++) {
		nsec = ldns_rr_list_rr(nsec3s, nsec_i);
		
		/* check values of iterations etc! */
		
		/* exact match? */
		if (ldns_dname_compare(ldns_rr_owner(nsec), hashed_sname) == 0) {
			result = nsec;
			goto done;
		}
		
	}

done:
	ldns_rdf_deep_free(sname);
	
	if (result) {
		printf(";; Found.\n");
	} else {
		printf(";; Not foud.\n");
	}
	return result;
}

/*return the owner name of the closest encloser for name from the list of rrs */
/* this is NOT the hash, but the original name! */
ldns_rdf *
ldns_nsec3_closest_encloser(ldns_rdf *qname, ldns_rr_type qtype, ldns_rr_list *nsec3s) {
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
	printf(";; finding closest encloser for type %d ", qtype);
	ldns_rdf_print(stdout, qname);
	printf("\n");

	nsec = ldns_rr_list_rr(nsec3s, 0);
	algorithm = ldns_nsec3_algorithm(nsec);
	salt_length = ldns_nsec3_salt_length(nsec);
	salt = ldns_nsec3_salt(nsec);
	iterations = ldns_nsec3_iterations(nsec);

	sname = ldns_rdf_clone(qname);

	ce = NULL;
	flag = false;
	
	zone_name = ldns_dname_left_chop(ldns_rr_owner(nsec));

	/* algorithm from nsec3-05 6.2. */
	while (ldns_dname_label_count(sname) > 0) {
		exact_match_found = false;
		in_range_found = false;
		
		printf(";; ");
		ldns_rdf_print(stdout, sname);
		printf(" hashes to: ");
		hashed_sname = ldns_nsec3_hash_name(sname, algorithm, iterations, salt_length, salt);

		status = ldns_dname_cat(hashed_sname, zone_name);
		ldns_rdf_print(stdout, hashed_sname);
		printf("\n");

		for (nsec_i = 0; nsec_i < ldns_rr_list_rr_count(nsec3s); nsec_i++) {
			nsec = ldns_rr_list_rr(nsec3s, nsec_i);
			
			/* check values of iterations etc! */
			
			/* exact match? */
			if (ldns_dname_compare(ldns_rr_owner(nsec), hashed_sname) == 0) {
				printf(";; exact match found\n");
			 	exact_match_found = true;
			} else if (ldns_nsec_covers_name(nsec, hashed_sname)) {
				printf(";; in range of an nsec\n");
				in_range_found = true;				
			}
			
		}
		if (!exact_match_found && in_range_found) {
			flag = true;
		} else if (exact_match_found && flag) {
			result = sname;
		} else if (exact_match_found && !flag) {
			// error!
			printf(";; the closes encloser is the same name (ie. this is an exact match, ie there is no closes encloser)\n");
			goto done;
		} else {
			flag = false;
		}
			

/*
		if (!exact_match_found) {
			// no proof -> clear flag
			printf(";; clearing flag\n");
			flag = false;
		} else if (in_range_found) {
			// proof of nonexistence
			printf(";; setting flag\n");
			flag = true;
		} else {
			if (flag) {
				result = sname;
				printf(";; found: an exact match, no in range, and flag set.\n");
				goto done;
			} else {
				// response bogus
				printf(";; bogus? an exact match, no in range, and flag not set\n");
				goto done;
			}
		}
*/		
		tmp = sname;
		sname = ldns_dname_left_chop(sname);
		ldns_rdf_deep_free(tmp);
	}
done:
	if (!result) {
		printf(";; no closest encloser found\n");
		ldns_rdf_deep_free(sname);
	} else {
		ldns_rdf_print(stdout, result);
		printf("\n");
	}
	
	/* todo checks from end of 6.2. here or in caller? */
	return result;
}


/**
 * Chase the given rr to a known and trusted key
 *
 * Based on drill 0.9
 *
 * the last argument prev_key_list, if not null, and type == DS, then the ds
 * rr list we have must all be a ds for the keys in this list
 */
ldns_status
do_chase(ldns_resolver *res, ldns_rdf *name, ldns_rr_type type, ldns_rr_class c,
		ldns_rr_list *trusted_keys, ldns_pkt *pkt_o, uint16_t qflags, ldns_rr_list *prev_key_list)
{
	ldns_rr_list *rrset = NULL;
	ldns_status result;
	
	ldns_rr_list *sigs;
	ldns_rr *cur_sig;
	uint16_t sig_i;
	ldns_rr_list *keys;
	ldns_rr_list *nsecs;
	uint16_t nsec_i;
	uint16_t key_i;
	uint16_t tkey_i;
	ldns_pkt *pkt;
	size_t i,j;
/*	ldns_rr_list *tmp_list;*/
	bool key_matches_ds;
	

	/* use these variables to check the nsec3s */
/*	ldns_rr *nsec3_ce;*/
	ldns_rdf *nsec3_ce;
	ldns_rr *nsec3_ex;
	ldns_rdf *wildcard_name;
	ldns_rdf *anc_name;
/*	ldns_rr *nsec3_wc_ce;*/
	ldns_rdf *nsec3_wc_ce;
	ldns_rr *nsec3_wc_ex;
/*
	uint8_t nsec3_algorithm;
	uint32_t nsec3_iterations;
	bool nsec3_optout;
*/	
	ldns_lookup_table *lt;
	const ldns_rr_descriptor *descriptor;
	
	pkt = ldns_pkt_clone(pkt_o);
	if (!name) {
		mesg("No name to chase");
		ldns_pkt_free(pkt);
		return LDNS_STATUS_EMPTY_LABEL;
	}

	if (qdebug != -1) {
		printf(";; Chasing: ");
			ldns_rdf_print(stdout, name);
			printf(" type %d\n", type);
	}

	if (!trusted_keys || ldns_rr_list_rr_count(trusted_keys) < 1) {
		warning("No trusted keys specified");
	}
	
	if (pkt) {
		rrset = ldns_pkt_rr_list_by_name_and_type(pkt,
				name,
				type,
				LDNS_SECTION_ANSWER
				);
		if (!rrset) {
			/* nothing in answer, try authority */
			rrset = ldns_pkt_rr_list_by_name_and_type(pkt,
					name,
					type,
					LDNS_SECTION_AUTHORITY
					);
		}
	} else {
		/* no packet? */
		return LDNS_STATUS_MEM_ERR;
	}
	
	if (!rrset) {
		/* not found in original packet, try again */
		ldns_pkt_free(pkt);
		pkt = NULL;
		pkt = ldns_resolver_query(res, name, type, c, qflags);
		
		if (!pkt) {
			return LDNS_STATUS_NETWORK_ERR;
		}
		rrset =	ldns_pkt_rr_list_by_name_and_type(pkt,
				name,
				type,
				LDNS_SECTION_ANSWER
				);
	}

	sigs = ldns_pkt_rr_list_by_name_and_type(pkt,
			name,
			LDNS_RR_TYPE_RRSIG,
			LDNS_SECTION_ANY_NOQUESTION
			);
	
	if (rrset) {
		for (sig_i = 0; sig_i < ldns_rr_list_rr_count(sigs); sig_i++) {
			cur_sig = ldns_rr_clone(ldns_rr_list_rr(sigs, sig_i));
			
			keys = ldns_pkt_rr_list_by_name_and_type(pkt,
					ldns_rr_rdf(cur_sig, 7),
					LDNS_RR_TYPE_DNSKEY,
					LDNS_SECTION_ANY_NOQUESTION
					);
			
			if (qdebug != -1) {
				printf(";; Data set: ");
				ldns_rdf_print(stdout, name);

				lt = ldns_lookup_by_id(ldns_rr_classes, c);
				if (lt) {
					printf("\t%s\t", lt->name);
				} else {
					printf("\tCLASS%d\t", c);
				}

				descriptor = ldns_rr_descript(type);

				if (descriptor->_name) {
					printf("%s\t", descriptor->_name);
				} else {
					/* exceptions for qtype */
					if (type == 251) {
						printf("IXFR ");
					} else if (type == 252) {
						printf("AXFR ");
					} else if (type == 253) {
						printf("MAILB ");
					} else if (type == 254) {
						printf("MAILA ");
					} else if (type == 255) {
						printf("ANY ");
					} else {
						printf("TYPE%d\t", type);
					}
				}
				
				printf("\n");
				printf(";; Signed by: ");
				ldns_rdf_print(stdout, ldns_rr_rdf(cur_sig, 7));
				printf("\n");
				if (type == LDNS_RR_TYPE_DS && prev_key_list) {
					for (j = 0; j < ldns_rr_list_rr_count(rrset); j++) {
						key_matches_ds = false;
						for (i = 0; i < ldns_rr_list_rr_count(prev_key_list); i++) {
							if (ldns_rr_compare_ds(ldns_rr_list_rr(prev_key_list, i),
									       ldns_rr_list_rr(rrset, j))) {
								key_matches_ds = true;
							}
						}
						if (!key_matches_ds) {
							/* For now error */
							fprintf(stderr, ";; error no DS for key\n");
							return LDNS_STATUS_ERR;
						}
					}
				}
			}

			if (!keys) {
				ldns_pkt_free(pkt);
				pkt = NULL;
				pkt = ldns_resolver_query(res,
						ldns_rr_rdf(cur_sig, 7),
						LDNS_RR_TYPE_DNSKEY, c, qflags);
				if (!pkt) {
					ldns_rr_list_deep_free(rrset);
					ldns_rr_list_deep_free(sigs);
					return LDNS_STATUS_NETWORK_ERR;
				}

				keys = ldns_pkt_rr_list_by_name_and_type(pkt,
						ldns_rr_rdf(cur_sig, 7),
						LDNS_RR_TYPE_DNSKEY,
						LDNS_SECTION_ANY_NOQUESTION
						);
			}
			if(!keys) {
				mesg("No key for data found in that zone!");
				ldns_rr_list_deep_free(rrset);
				ldns_rr_list_deep_free(sigs);
				ldns_pkt_free(pkt);
				ldns_rr_free(cur_sig);
				return LDNS_STATUS_CRYPTO_NO_DNSKEY;
			} else {
				result = LDNS_STATUS_ERR;
				for (key_i = 0; key_i < ldns_rr_list_rr_count(keys); key_i++) {
					/* only check matching keys */

					if (ldns_calc_keytag(ldns_rr_list_rr(keys, key_i))
					    ==
					    ldns_rdf2native_int16(ldns_rr_rrsig_keytag(cur_sig))
					   ) {
						result = ldns_verify_rrsig(rrset, cur_sig, ldns_rr_list_rr(keys, key_i));
						if (result == LDNS_STATUS_OK) {
							for (tkey_i = 0; tkey_i < ldns_rr_list_rr_count(trusted_keys); tkey_i++) {
								if (ldns_rr_compare_ds(ldns_rr_list_rr(keys, key_i),
										   ldns_rr_list_rr(trusted_keys, tkey_i)
										  )) {
									mesg("Key is trusted");
									ldns_rr_list_deep_free(rrset);
									ldns_rr_list_deep_free(sigs);
									ldns_rr_list_deep_free(keys);
									ldns_pkt_free(pkt);
									ldns_rr_free(cur_sig);
									return LDNS_STATUS_OK;
								}
							}
							result = do_chase(res, ldns_rr_rdf(cur_sig, 7), LDNS_RR_TYPE_DS, c, trusted_keys, pkt, qflags, keys);
							ldns_rr_list_deep_free(rrset);
							ldns_rr_list_deep_free(sigs);
							ldns_rr_list_deep_free(keys);
							ldns_pkt_free(pkt);
							ldns_rr_free(cur_sig);
							return result;
						}
					}
				}
				if (result != LDNS_STATUS_OK) {
					ldns_rr_list_deep_free(rrset);
					ldns_rr_list_deep_free(sigs);
					ldns_rr_list_deep_free(keys);
					ldns_pkt_free(pkt);
					ldns_rr_free(cur_sig);
					return result;
				}
				ldns_rr_list_deep_free(keys);
			}
			ldns_rr_free(cur_sig);
		}
		ldns_rr_list_deep_free(rrset);
	}

	if (rrset && ldns_rr_list_rr_count(sigs) > 0) {
		ldns_rr_list_deep_free(sigs);
		ldns_pkt_free(pkt);
		return LDNS_STATUS_CRYPTO_NO_TRUSTED_DNSKEY;
	} else {
/*
printf("COULD BE NSEC3 IN:\n");
ldns_pkt_print(stdout, pkt);
*/
		/* Try to see if there are NSECS in the packet */
		nsecs = ldns_pkt_rr_list_by_type(pkt, LDNS_RR_TYPE_NSEC, LDNS_SECTION_ANY_NOQUESTION);
		result = LDNS_STATUS_CRYPTO_NO_RRSIG;
		
		for (nsec_i = 0; nsec_i < ldns_rr_list_rr_count(nsecs); nsec_i++) {
			/* there are four options:
			 * - name equals ownername and is covered by the type bitmap
			 * - name equals ownername but is not covered by the type bitmap
			 * - name falls within nsec coverage but is not equal to the owner name
			 * - name falls outside of nsec coverage
			 */
			if (ldns_dname_compare(ldns_rr_owner(ldns_rr_list_rr(nsecs, nsec_i)), name) == 0) {
/*
printf("CHECKING NSEC:\n");
ldns_rr_print(stdout, ldns_rr_list_rr(nsecs, nsec_i));
printf("DAWASEM\n");
*/
				if (ldns_nsec_bitmap_covers_type(ldns_rr_rdf(ldns_rr_list_rr(nsecs, nsec_i), 2), type)) {
					/* Error, according to the nsec this rrset is signed */
					result = LDNS_STATUS_CRYPTO_NO_RRSIG;
				} else {
					/* ok nsec denies existence, chase the nsec now */
					printf(";; Existence of data set with this type denied by NSEC\n");
					result = do_chase(res, ldns_rr_owner(ldns_rr_list_rr(nsecs, nsec_i)), LDNS_RR_TYPE_NSEC, c, trusted_keys, pkt, qflags, NULL);
					if (result == LDNS_STATUS_OK) {
						ldns_pkt_free(pkt);
						printf(";; Verifiably insecure.\n");
						ldns_rr_list_deep_free(nsecs);
						return result;
					}
				}
			} else if (ldns_nsec_covers_name(ldns_rr_list_rr(nsecs, nsec_i), name)) {
				/* Verifably insecure? chase the covering nsec */
				printf(";; Existence of data set with this name denied by NSEC\n");
				result = do_chase(res, ldns_rr_owner(ldns_rr_list_rr(nsecs, nsec_i)), LDNS_RR_TYPE_NSEC, c, trusted_keys, pkt, qflags, NULL);
				if (result == LDNS_STATUS_OK) {
					ldns_pkt_free(pkt);
					printf(";; Verifiably insecure.\n");
					ldns_rr_list_deep_free(nsecs);
					return result;
				}
			} else {
				/* nsec has nothing to do with this data */
			}
		}
		
		nsecs = ldns_pkt_rr_list_by_type(pkt, LDNS_RR_TYPE_NSEC3, LDNS_SECTION_ANY_NOQUESTION);
		nsec_i = 0;
		/* TODO: verify that all nsecs have same iterations and hash values */
		
		if (ldns_rr_list_rr_count(nsecs) != 0) {
			if (qdebug != -1) {
				printf(";; we have nsec3's and no data? prove denial.\n");
ldns_rr_list_print(stdout, nsecs);
			}

			wildcard_name = ldns_dname_new_frm_str("*");
			result = ldns_dname_cat(wildcard_name, ldns_dname_left_chop(name));

//ldns_nsec3_closest_encloser(ldns_rdf *qname, ldns_rr_type qtype, ldns_rr_list *nsec3s) {
			if (ldns_pkt_get_rcode(pkt) == LDNS_RCODE_NXDOMAIN) {
				/* Section 6.3. */
				nsec3_ce = ldns_nsec3_closest_encloser(name, type, nsecs);
				nsec3_wc_ce = ldns_nsec3_closest_encloser(wildcard_name, type, nsecs);				
				if (nsec3_ce && nsec3_wc_ce) {
					printf(";; NAMEERR proven by closest encloser and wildcard encloser NSECS\n");
				} else {
					if (!nsec3_ce) {
						printf(";; NAMEERR oculd not be proven, missing closest encloser\n");
					}
					if (!nsec3_wc_ce) {
						printf(";; NAMEERR oculd not be proven, missing wildcard encloser\n");
					}
				}
			} else if (ldns_pkt_get_rcode(pkt) == LDNS_RCODE_NOERROR) {
				nsec3_ex = ldns_nsec3_exact_match(name, type, nsecs);
				if (nsec3_ex) {
					nsec3_ce = NULL;
				} else {
					nsec3_ce = ldns_nsec3_closest_encloser(name, type, nsecs);
				}
				nsec3_wc_ex = ldns_nsec3_exact_match(name, type, nsecs);
				if (nsec3_wc_ex) {
					nsec3_wc_ce = NULL;
				} else {
					nsec3_wc_ce = ldns_nsec3_closest_encloser(wildcard_name, type, nsecs);				
				}
				nsec3_wc_ex = ldns_nsec3_exact_match(name, type, nsecs);
				if (!nsec3_wc_ex) {
					if (type != LDNS_RR_TYPE_DS) {
						/* Section 6.4. */
						nsec3_ex = ldns_nsec3_exact_match(name, type, nsecs);
						if (nsec3_ex && !ldns_nsec_bitmap_covers_type(ldns_nsec3_bitmap(nsec3_ex), type)) {
							// ok
							printf(";; NODATA/NOERROR proven for type != DS (draft nsec3-05 section 6.4.)\n");
							printf(";; existence denied\n");
						} else {
							printf(";; NODATA/NOERROR NOT proven for type != DS (draft nsec3-05 section 6.4.)\n");
							printf(";; existence not denied\n");
							result = LDNS_STATUS_ERR;
						}
					} else {
						/* Section 6.5. */
						nsec3_ex = ldns_nsec3_exact_match(name, type, nsecs);
						nsec3_ce = ldns_nsec3_closest_encloser(name, type, nsecs);
						if (!nsec3_ex) {
							nsec3_ce = ldns_nsec3_closest_encloser(name, type, nsecs);
							nsec3_ex = ldns_nsec3_exact_match(nsec3_ce, type, nsecs);
							if (nsec3_ex && ldns_nsec3_optout(nsec3_ex)) {
								printf(";; DS record in optout range of NSEC3 (draft nsec3-05 section 6.5.)");
							} else {
								printf(";; DS record in range of NSEC3 but OPTOUT not set (draft nsec3-05 section 6.5.)\n");
								result = LDNS_STATUS_ERR;
							}
						} else {
							if (nsec3_ex && !ldns_nsec_bitmap_covers_type(ldns_nsec3_bitmap(nsec3_ex), type)) {
								// ok
								printf(";; NODATA/NOERROR proven for type == DS (draft nsec3-05 section 6.5.)\n");
								printf(";; existence denied\n");
							} else {
								printf(";; NODATA/NOERROR NOT proven for type == DS (draft nsec3-05 section 6.5.)\n");
								printf(";; existence not denied\n");
								result = LDNS_STATUS_ERR;
							}
						}
					}
				} else {
					if (!ldns_nsec_bitmap_covers_type(ldns_nsec3_bitmap(nsec3_wc_ex), type)) {
						/* Section 6.6 */
						nsec3_ce = ldns_nsec3_closest_encloser(name, type, nsecs);
						if (nsec3_ce) {
							wildcard_name = ldns_dname_new_frm_str("*");
							result = ldns_dname_cat(wildcard_name, nsec3_ce);
							nsec3_wc_ex = ldns_nsec3_exact_match(wildcard_name, type, nsecs);
							if (nsec3_wc_ex) {
								printf(";; Wilcard exists but not for this type (draft nsec3-05 section 6.6.)\n");
							} else {
								printf(";; Error proving wildcard for different type, no proof for wildcard of closest encloser (draft nsec3-05 section 6.6.)\n");
							}
						} else {
							printf(";; NODATA/NOERROR wildcard for other type, error, no closest encloser (draft nsec3-05 section 6.6.)\n");
							result = LDNS_STATUS_ERR;
						}
					} else {
						/* Section 6.7 */
						/* TODO this is not right */
						anc_name = ldns_dname_left_chop(wildcard_name);
						nsec3_wc_ce = ldns_nsec3_closest_encloser(anc_name, type, nsecs);
						if (nsec3_wc_ce) {
							printf(";; wildcard proven (draft nsec3-05 section 6.7.)\n");
						} else {
							printf(";; Error finding wildcard closest encloser, no proof for wildcard (draft nsec3-05 section 6.7.)\n");
							result = LDNS_STATUS_ERR;
						}
					}
					
				}
			}
		}
		
		ldns_pkt_free(pkt);
		ldns_rr_list_deep_free(nsecs);
		return result;
	}
}

