/*
 * chasetrace.c
 * Where all the hard work concerning chasing
 * and tracing is done
 * (c) 2005 NLnet Labs
 *
 * See the file LICENSE for the license
 *
 */

#include "drill.h"
#include <ldns/dns.h>

/* 
 * retrieve keys for this zone
 */
ldns_rr_list *
get_apex_keys(ldns_resolver *r, ldns_rdf *apexname, ldns_rr_list **opt_sig)
{
	ldns_pkt *p;
	ldns_rr_list *k;

	/* ldns_resolver_set_dnssec(r, true); */

	p = ldns_resolver_query(r, apexname, LDNS_RR_TYPE_DNSKEY, LDNS_RR_CLASS_IN, 0); 
	if (!p) {
		return NULL;
	}

	k = ldns_pkt_rr_list_by_name_and_type(p, apexname, LDNS_RR_TYPE_DNSKEY, 
				LDNS_SECTION_ANSWER);
	/* there must be a sig there too... */
	*opt_sig = ldns_pkt_rr_list_by_name_and_type(p, apexname, LDNS_RR_TYPE_RRSIG, 
				LDNS_SECTION_ANSWER);

	return k;
}

/* do a secure trace - local_res has been setup, so try to use that */
ldns_status
do_secure_trace2(ldns_resolver *res, ldns_rdf *name, ldns_rr_type t,
                ldns_rr_class c, ldns_rr_list *trusted_keys)
{
	/* problem here is that I don't now if *res is a forwarder/cache
	 * or authoritative NS. If we use a cache we should "leave" that
	 * asap and try to find us a real auth. NS ;) 
	 */
	ldns_rr_list *dnskey_cache;
	ldns_rr_list *rrsig_cache;

	ldns_rdf *chopped_dname[11]; /* alloc 10 subparts for a dname */
	uint8_t i, dname_labels;

	rrsig_cache = ldns_rr_list_new();
	dnskey_cache = NULL;

	/* get a list of chopped dnames: www.nlnetlabs.nl, nlnetlabs.nl, nl, . 
	 * This is used to discover what is the zone that is actually hosted
	 * on the resolver we point to in local_res
	 */
	chopped_dname[0] = name;
	for(i = 1; i < 10 && chopped_dname[i - 1]; i++) {
		chopped_dname[i] = ldns_dname_left_chop(chopped_dname[i - 1]);	
	}
	chopped_dname[i] = NULL;
	dname_labels = i - 2; /* set this also before this last NULL */

	for(i = 0; chopped_dname[i]; i++) {
		ldns_rdf_print(stdout, chopped_dname[i]);
		printf("\n");
	}

	/* Now we will find out what is the first zone that 
	 * actually has some key+sig configured at the nameserver
	 * we're looking at. We start at the right side of our dname
	 */
	for(i = dname_labels; i != 0; i--) {
		ldns_rdf_print(stdout, chopped_dname[i]);
		printf("\n");
		dnskey_cache =  get_apex_keys(res, chopped_dname[i], &rrsig_cache);
		if (dnskey_cache) {
			/* aahhh, keys... */
			break;
		}
	}
	printf("\nFirst dname with keys and sigs here */\n");
	ldns_rdf_print(stdout, chopped_dname[i]);

printf("\nkeys\n");
	ldns_rr_list_print(stdout, dnskey_cache);
printf("\nsigs\n");
 	if (!rrsig_cache) {
		/* huh!? the sigs are sent along with the keys... */
		return LDNS_STATUS_ERR;
	}
	ldns_rr_list_print(stdout, rrsig_cache);
	printf("\n");



	return LDNS_STATUS_OK;
}


