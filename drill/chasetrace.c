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
#include <ldns/dns.h>

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


/**
 * Chase the given rr to a known and trusted key
 *
 * Based on drill 0.9
 * pkt optional? 
 * TODO: lots  ???
 */
ldns_status
do_chase(ldns_resolver *res, ldns_rdf *name, ldns_rr_type type, ldns_rr_class c,
		ldns_rr_list *trusted_keys, ldns_pkt *pkt_o, uint16_t qflags)
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
	
	ldns_lookup_table *lt;
	const ldns_rr_descriptor *descriptor;
	
	pkt = ldns_pkt_clone(pkt_o);
	if (!name) {
		mesg("No name to chase");
		ldns_pkt_free(pkt);
		return LDNS_STATUS_EMPTY_LABEL;
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
						result = do_chase(res, ldns_rr_rdf(cur_sig, 7), LDNS_RR_TYPE_DS, c, trusted_keys, pkt, qflags);
						ldns_rr_list_deep_free(rrset);
						ldns_rr_list_deep_free(sigs);
						ldns_rr_list_deep_free(keys);
						ldns_pkt_free(pkt);
						ldns_rr_free(cur_sig);
						return result;
					}
				}
/*
 else {
					result = LDNS_STATUS_CRYPTO_NO_MATCHING_KEYTAG_DNSKEY;
				}
*/
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
	if (ldns_rr_list_rr_count(sigs) > 0) {
		ldns_rr_list_deep_free(sigs);
		ldns_pkt_free(pkt);
		return LDNS_STATUS_CRYPTO_NO_TRUSTED_DNSKEY;
	} else {
		/* Try to see if there are NSECS in the packet */
		nsecs = ldns_pkt_rr_list_by_type(pkt, LDNS_RR_TYPE_NSEC, LDNS_SECTION_ANY);
		result = LDNS_STATUS_CRYPTO_NO_RRSIG;
		
		for (nsec_i = 0; nsec_i < ldns_rr_list_rr_count(nsecs); nsec_i++) {
			if (ldns_nsec_covers_rrset(ldns_rr_list_rr(nsecs, nsec_i), name, type)) {
				/* Verifably insecure? chase the covering nsec */
				result = do_chase(res, ldns_rr_owner(ldns_rr_list_rr(nsecs, nsec_i)), LDNS_RR_TYPE_NSEC, c, trusted_keys, pkt, qflags);
				if (result == LDNS_STATUS_OK) {
					ldns_pkt_free(pkt);
					return result;
				}
			}
		}
		ldns_pkt_free(pkt);
		return result;
	}
}

