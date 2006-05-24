/*
 * securechasetrace.c
 * Where all the hard work concerning secure tracing is done
 *
 * (c) 2005, 2006 NLnet Labs
 *
 * See the file LICENSE for the license
 *
 */

#include "drill.h"
#include <ldns/dns.h>

#define VAL "[OK]" 


/* See if there is a key/ds in trusted that matches
 * a ds in *ds. If so, we have a trusted path. If 
 * not something is the matter
 */
static ldns_rr_list *
ds_key_match(ldns_rr_list *ds, ldns_rr_list *trusted)
{
	size_t i, j;
	bool match;
	ldns_rr *rr_i, *rr_j;
	ldns_rr_list *trusted_ds;

	if (!trusted || !ds) {
		return NULL;
	}

	match = false;
	trusted_ds = ldns_rr_list_new();
	if (!trusted_ds) {
		return NULL;
	}

	for (i = 0; i < ldns_rr_list_rr_count(trusted); i++) {
		rr_i = ldns_rr_list_rr(trusted, i);
		for (j = 0; j < ldns_rr_list_rr_count(ds); j++) {

			rr_j = ldns_rr_list_rr(ds, j);
			if (ldns_rr_compare_ds(rr_i, rr_j)) {
				match = true;
				ldns_rr_list_push_rr(trusted_ds, rr_j); 
			}
		}
	}

	if (match) {
		return trusted_ds;
	} else {
		return NULL;
	}
}


/*
 * generic function to get some RRset from a nameserver
 * and possible some signatures too (that would be the day...)
 */
static ldns_pkt_type
get_dnssec_rr(ldns_resolver *r, ldns_rdf *name, ldns_rr_type t, 
	ldns_rr_list **rrlist, ldns_rr_list **sig)
{
	ldns_pkt_type pt = LDNS_PACKET_UNKNOWN;
	ldns_pkt *p = NULL;
	ldns_rr_list *rr = NULL;
	ldns_rr_list *sigs = NULL;

	p = ldns_resolver_query(r, name, t, LDNS_RR_CLASS_IN, 0); 
	if (!p) {
		return LDNS_PACKET_UNKNOWN;
	}

	pt = ldns_pkt_reply_type(p);
	if (pt == LDNS_PACKET_NXDOMAIN || pt == LDNS_PACKET_NODATA) {
		return pt;
	}
		
	rr = ldns_pkt_rr_list_by_name_and_type(p, name, t, LDNS_SECTION_ANSWER);
	/* there SHOULD be a sig there too... */
	sigs = ldns_pkt_rr_list_by_name_and_type(p, name, LDNS_RR_TYPE_RRSIG, 
			LDNS_SECTION_ANSWER);

	if (sig) {
		ldns_rr_list_cat(*sig, sigs);
	}
	if (rrlist) {
		*rrlist = rr;
	}
	return LDNS_PACKET_ANSWER;
}

/* 
 * retrieve keys for this zone
 */
static ldns_pkt_type
get_key(ldns_resolver *r, ldns_rdf *apexname, ldns_rr_list **rrlist, ldns_rr_list **opt_sig)
{
	return get_dnssec_rr(r, apexname, LDNS_RR_TYPE_DNSKEY, rrlist, opt_sig);
}

/*
 * check to see if we can find a DS rrset here which we can then follow
 */
static ldns_pkt_type
get_ds(ldns_resolver *r, ldns_rdf *ownername, ldns_rr_list **rrlist, ldns_rr_list **opt_sig)
{
	return get_dnssec_rr(r, ownername, LDNS_RR_TYPE_DS, rrlist, opt_sig);
}

ldns_pkt *
do_secure_trace(ldns_resolver *local_res, ldns_rdf *name, ldns_rr_type t,
		ldns_rr_class c, ldns_rr_list *trusted_keys)
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
	ldns_rdf *authname;
	ldns_rdf **labels;
	ldns_status status;
	ssize_t i, j;
	uint8_t labels_count_current;
	uint8_t labels_count_all;
	ldns_pkt_type pt;

	/* dnssec */
	bool secure;
	ldns_rr_list *key_list;
	ldns_rr_list *sig_list;
	ldns_rr_list *ds_sig_list;
	ldns_rr_list *ds_list;

	ldns_rr_list *TMP_ds_list;

	secure = true;
	authname = NULL;
	loop_count = 0;
	new_nss_a = NULL;
	new_nss_aaaa = NULL;
	new_nss = NULL;
	ns_addr = NULL;
	final_answer = NULL;
	pt = LDNS_PACKET_UNKNOWN;
	p = ldns_pkt_new();
	res = ldns_resolver_new();
	sig_list = ldns_rr_list_new();
	ds_sig_list = ldns_rr_list_new();

	if (!p || !res || !sig_list) {
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
	ldns_resolver_set_fail(res, 
			ldns_resolver_fail(local_res));
	ldns_resolver_set_usevc(res, 
			ldns_resolver_usevc(local_res));
	ldns_resolver_set_random(res, 
			ldns_resolver_random(local_res));
	ldns_resolver_set_recursive(res, false);
	ldns_resolver_set_dnssec(res, true);

	/* setup the root nameserver in the new resolver */
	if (ldns_resolver_push_nameserver_rr_list(res, global_dns_root) != LDNS_STATUS_OK) {
		return NULL;
	}

	/* this must be a real query to local_res */
	status = ldns_resolver_send(&p, local_res, ldns_dname_new_frm_str("."), LDNS_RR_TYPE_NS, c, 0);
	if (ldns_pkt_empty(p)) {
		warning("No root server information received");
	} 
	
	if (status == LDNS_STATUS_OK) {
		if (!ldns_pkt_empty(p)) {
			drill_pkt_print(stdout, local_res, p);
		}
	} else {
		error("Cannot use local resolver");
		return NULL;
	}

	status = ldns_resolver_send(&p, res, name, t, c, 0);
	if (!p) {
		warning("No packet received, aborting");
		return NULL;
	}

	while(status == LDNS_STATUS_OK && 
	      ldns_pkt_reply_type(p) == LDNS_PACKET_REFERRAL) {

		new_nss_a = ldns_pkt_rr_list_by_type(p,
				LDNS_RR_TYPE_A, LDNS_SECTION_ADDITIONAL);
		new_nss_aaaa = ldns_pkt_rr_list_by_type(p,
				LDNS_RR_TYPE_AAAA, LDNS_SECTION_ADDITIONAL);
		new_nss = ldns_pkt_rr_list_by_type(p,
				LDNS_RR_TYPE_NS, LDNS_SECTION_AUTHORITY);

		if (qdebug != -1) {
			ldns_rr_list_print(stdout, new_nss);
		}
		/* remove the old nameserver from the resolver */
		while((pop = ldns_resolver_pop_nameserver(res))) { /* do it */ }

		if (!new_nss_aaaa && !new_nss_a) {
			/* 
			 * no nameserver found!!! 
			 * try to resolve the names we do got 
			 */
			for(i = 0; i < (ssize_t)ldns_rr_list_rr_count(new_nss); i++) {
				/* get the name of the nameserver */
				pop = ldns_rr_rdf(ldns_rr_list_rr(new_nss, (size_t)i), 0);
				if (!pop) {
					break;
				}
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
				error("Adding new nameservers");
				ldns_pkt_free(p); 
				return NULL;
			}
		}
		if (new_nss_a) {
			if (ldns_resolver_push_nameserver_rr_list(res, new_nss_a) != 
					LDNS_STATUS_OK) {
				error("Adding new nameservers");
				ldns_pkt_free(p); 
				return NULL;
			}
		}
		/* DNSSEC */
		if (new_nss) {
			authname = ldns_rr_owner(ldns_rr_list_rr(new_nss, 0));
		} 

		pt = get_key(res, authname, &key_list, &sig_list);
		switch(pt) {
		case LDNS_PACKET_ANSWER:
			printf(";; DNSSEC RRs\n");
			print_rr_list_abbr(stdout, key_list, NULL); 
			print_rr_list_abbr(stdout, sig_list, NULL); 
			if (sig_list) {
				if (ldns_verify(key_list, sig_list, key_list, trusted_keys) ==
						LDNS_STATUS_OK) {
					print_rr_list_abbr(stdout, trusted_keys, VAL); 
				}
			}
			break;
		case LDNS_PACKET_NXDOMAIN:
		case LDNS_PACKET_NODATA:
		default:
			printf(";; No DNSKEYs found, not attemping validation\n");
			break;
		} 

		pt = get_ds(res, authname, &ds_list, &sig_list);
		switch(pt) {
		case LDNS_PACKET_ANSWER:
			print_rr_list_abbr(stdout, ds_list, NULL);
			print_rr_list_abbr(stdout, sig_list, NULL); 

			TMP_ds_list = ds_key_match(ds_list, trusted_keys);
			print_rr_list_abbr(stdout, TMP_ds_list, VAL);

			break;
		case LDNS_PACKET_NXDOMAIN:
		case LDNS_PACKET_NODATA:
		default:
			printf(";; No DSs found, not attemping validation\n");
			break;
		} 
		
		/* /DNSSEC */

		if (loop_count++ > 20) {
			error("Looks like we are looping");
			ldns_pkt_free(p); 
			return NULL;
		}

		ldns_rr_list_deep_free(sig_list);
		sig_list = ldns_rr_list_new();
		
		status = ldns_resolver_send(&p, res, name, t, c, 0);
		new_nss_aaaa = NULL;
		new_nss_a = NULL;
		ns_addr = NULL;
		puts("");
	}

	/* how far did we come */
	labels_count_current = ldns_dname_label_count(authname);

	/* 
	 * het kan zijn dat we nog labels over hebben, omdat ze
	 * allemaal gehost worden op de zelfde server, zie
	 * ok.ok.ok.test.jelte.nlnetlabs.nl
	 *
	 * die moeten hier nog afgegaan worden om een chain
	 * of trust te kunnen opbouwen
	 */

	status = ldns_resolver_send(&p, res, name, t, c, 0);
	if (!p) {
		error("No packet received, aborting");
		return NULL;
	}

	hostnames = ldns_get_rr_list_name_by_addr(local_res, 
			ldns_pkt_answerfrom(p), 0, 0);

	new_nss = ldns_pkt_rr_list_by_type(p,
			LDNS_RR_TYPE_NS, LDNS_SECTION_AUTHORITY);
	final_answer = ldns_pkt_answer(p);
	if (new_nss) {
		authname = ldns_rr_owner(ldns_rr_list_rr(new_nss, 0));
	} 
	labels_count_all = ldns_dname_label_count(name);

	/* reverse the query order for the remaining names
	 * so that we fetch them in the correct DNS order */
	labels = LDNS_XMALLOC(ldns_rdf*, labels_count_all);
	if (!labels) {
		return NULL;
	}
	labels[0] = name;
	for(i = 1 ; i < (ssize_t)labels_count_current; i++) {
		labels[i] = ldns_dname_left_chop(labels[i - 1]);
	}

		/* DNSSEC */
	/* recurse on the name at this server */
	printf(";; Re-querying at current nameservers\n\n");
	for(i = (ssize_t)labels_count_current - 1; i >= 0; i--) {

		/* fake print the nameserver for this node */
		for(j = 0; j < ldns_rr_list_rr_count(new_nss); j++) {
			ldns_rdf_print(stdout, labels[i]);
			printf("\t%d\tIN\tNS\t", ldns_rr_ttl(ldns_rr_list_rr(new_nss, j)));
			ldns_rdf_print(stdout, 
				ldns_rr_rdf(ldns_rr_list_rr(new_nss, j), 0));
			printf("\n");
		}

		pt = get_key(res, labels[i], &key_list, &sig_list);
		switch(pt) {
		case LDNS_PACKET_ANSWER:
			printf(";; DNSSEC RRs\n");
			if (sig_list) {
			print_rr_list_abbr(stdout, sig_list, NULL); 
				if (ldns_verify(key_list, sig_list, key_list, trusted_keys) ==
						LDNS_STATUS_OK) {
				}
			}
			break;
		case LDNS_PACKET_NXDOMAIN:
		case LDNS_PACKET_NODATA:
			printf(";; No data received, giving up\n");
			ldns_pkt_free(p); 
			return NULL;
		default:
			printf(";; No DNSKEYs found, not attemping validation\n");
			break;
		} 

		pt = get_ds(res, labels[i], &ds_list, &ds_sig_list);
		switch(pt) {
		case LDNS_PACKET_ANSWER:
			print_rr_list_abbr(stdout, ds_list, NULL);
			print_rr_list_abbr(stdout, ds_sig_list, NULL);
			if (sig_list) {
				if (ldns_verify(ds_list, sig_list, key_list, trusted_keys) ==
						LDNS_STATUS_OK) {
					print_rr_list_abbr(stdout, trusted_keys, "DS" VAL); 
				} 
			}
			TMP_ds_list = ds_key_match(ds_list, trusted_keys);
			print_rr_list_abbr(stdout, TMP_ds_list, VAL);
			break;
		case LDNS_PACKET_NXDOMAIN:
		case LDNS_PACKET_NODATA:
			printf(";; No data received, giving up\n");
			ldns_pkt_free(p); 
			return NULL;
		default:
			printf(";; No DSs found, not attemping validation\n");
			break;
		} 

		ldns_rr_list_deep_free(sig_list);
		sig_list = ldns_rr_list_new();
		puts("");
		
	}
	/* /DNSSEC */
	
	ldns_pkt_free(p); 
	return NULL;
}
