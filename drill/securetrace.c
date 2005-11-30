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
 * generic function to get some RRset from a nameserver
 * and possible some signatures too (that would be the day...)
 */
ldns_rr_list *
get_dnssec_rr(ldns_resolver *r, ldns_rdf *name, ldns_rr_type t, ldns_rr_list **sig)
{
	ldns_pkt *p;
	ldns_rr_list *rr;

	/* ldns_resolver_set_dnssec(r, true); */

	p = ldns_resolver_query(r, name, t, LDNS_RR_CLASS_IN, 0); 
	if (!p) {
		return NULL;
	}

	rr = ldns_pkt_rr_list_by_name_and_type(p, name, t, LDNS_SECTION_ANSWER);
	/* there must be a sig there too... */
	if (sig) {
		*sig = ldns_pkt_rr_list_by_name_and_type(p, name, LDNS_RR_TYPE_RRSIG, 
				LDNS_SECTION_ANSWER);
	}
	return rr;
}

/* 
 * retrieve keys for this zone
 */
ldns_rr_list *
get_apex_keys(ldns_resolver *r, ldns_rdf *apexname, ldns_rr_list **opt_sig)
{
	return get_dnssec_rr(r, apexname, LDNS_RR_TYPE_DNSKEY, opt_sig);
}

/*
 * check to see if we can find a DS rrset here which we can then follow
 */
ldns_rr_list *
get_ds(ldns_resolver *r, ldns_rdf *ownername, ldns_rr_list **opt_sig)
{
	return get_dnssec_rr(r, ownername, LDNS_RR_TYPE_DS, opt_sig);
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

	/* chopped_dname[i] is the zone which is configured at the
	 * nameserver pointed to by res. This is our starting point
	 * for the secure trace. Hopefully the trusted keys we got
	 * match the keys we see here
	 */

printf("\nkeys\n");
	ldns_rr_list_print(stdout, dnskey_cache);
printf("\nsigs\n");
 	if (!rrsig_cache) {
		/* huh!? the sigs must be sent along with the keys... 
		 * probably are using some lame forwarder... exit as
		 * we cannot do anything in that case
		 */
		error("Are you using an non DNSSEC-aware forwarder?");
		return LDNS_STATUS_ERR;
	}
	ldns_rr_list_print(stdout, rrsig_cache);
	printf("\n");



	return LDNS_STATUS_OK;
}


