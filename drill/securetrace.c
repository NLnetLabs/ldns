/*
 * securechasetrace.c
 * Where all the hard work concerning secure tracing is done
 *
 * (c) 2005 NLnet Labs
 *
 * See the file LICENSE for the license
 *
 */

#include "drill.h"
#include <ldns/dns.h>

/* 
 * check if the key and the ds are equivalent
 * ie: is the ds made from the key?
 */
bool
check_ds_key_equiv(ldns_rr *key, ldns_rr *ds)
{
	ldns_rr *key_ds;

	key_ds  = ldns_key_rr2ds(key, LDNS_SHA1);
	printf("new ds\n");
		ldns_rr_print(stdout, key_ds);

	if (ldns_rr_compare(key_ds, ds) == 0) {
		return true;
	} else {
		return false;
	}
}

/*
 * return the keys records that match some of the
 * DSs
 */
ldns_rr_list *
check_ds_key_equiv_rr_list(ldns_rr_list *key, ldns_rr_list *ds)
{
	size_t i,j;
	ldns_rr_list *eq;

	ldns_rr *ds_rr, *key_rr;

	eq = ldns_rr_list_new();

	/* check each DS against all the keys for a match */
	for(i = 0; i < ldns_rr_list_rr_count(ds); i++) {
		ds_rr = ldns_rr_list_rr(ds, i);
		for(j = 0; j < ldns_rr_list_rr_count(key); j++) {
			key_rr = ldns_rr_list_rr(key, j);

		printf("checking\n");
		ldns_rr_print(stdout, ds_rr);
		ldns_rr_print(stdout, key_rr);
		printf("\n");
			
			if (check_ds_key_equiv(key_rr, ds_rr)) {
				/* we have a winner */
				ldns_rr_list_push_rr(eq, key_rr);
				break;
			}
		}
	}
	if (ldns_rr_list_rr_count(eq) > 0) {
		return eq;
	} else {
		return NULL;
	}
}


/*
 * generic function to get some RRset from a nameserver
 * and possible some signatures too (that would be the day...)
 */
ldns_rr_list *
get_dnssec_rr(ldns_resolver *r, ldns_rdf *name, ldns_rr_type t, ldns_rr_list **sig)
{
	ldns_pkt *p;
	ldns_rr_list *rr;
	ldns_rr_list *sigs;

	/* ldns_resolver_set_dnssec(r, true); */

	p = ldns_resolver_query(r, name, t, LDNS_RR_CLASS_IN, 0); 
	if (!p) {
		return NULL;
	}

	rr = ldns_pkt_rr_list_by_name_and_type(p, name, t, LDNS_SECTION_ANSWER);
	/* there must be a sig there too... */
	sigs = ldns_pkt_rr_list_by_name_and_type(p, name, LDNS_RR_TYPE_RRSIG, 
			LDNS_SECTION_ANSWER);

	if (sig) {
		ldns_rr_list_cat(*sig, sigs);
	}
	return rr;
}

/* 
 * retrieve keys for this zone
 */
ldns_rr_list *
get_keys(ldns_resolver *r, ldns_rdf *apexname, ldns_rr_list **opt_sig)
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
	ldns_rr_list *dnskey_cache = NULL;
	ldns_rr_list *rrsig_cache = NULL;
	ldns_rr_list *ds_cache = NULL;

	ldns_rdf *chopped_dname[11]; /* alloc 10 subparts for a dname */
	ldns_rr_list *ds;
	int8_t i, dname_labels;
	uint8_t lab_cnt;
	ldns_rr_list *validated_ds;

	rrsig_cache = ldns_rr_list_new();
	dnskey_cache = NULL;

	ldns_resolver_set_dnssec(res, true);
	ldns_resolver_set_dnssec_cd(res, true);

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

	/* Now we will find out what is the first zone that 
	 * actually has some key+sig configured at the nameserver
	 * we're looking at. We start at the right side of our dname
	 */
	for(i = dname_labels; i != 0; i--) {
		ldns_rdf_print(stdout, chopped_dname[i]);
		printf("\n");
		dnskey_cache =  get_keys(res, chopped_dname[i], &rrsig_cache);
		if (dnskey_cache) {
			/* aahhh, keys... */
			break;
		}
	}
	lab_cnt = i;

	/* Print whay we have found until now */
	printf(" ("); 
		ldns_rdf_print(stdout, chopped_dname[i]);
	puts(")");
	resolver_print_nameservers(res);
	puts("");
	print_dnskey(dnskey_cache);
	puts(" |");
			

	/* chopped_dname[i] is the zone which is configured at the
	 * nameserver pointed to by res. This is our starting point
	 * for the secure trace. Hopefully the trusted keys we got
	 * match the keys we see here
	 */

 	if (!rrsig_cache) {
		/* huh!? the sigs must be sent along with the keys... 
		 * probably are using some lame forwarder... exit as
		 * we cannot do anything in that case
		 */
		error("Are you using an non DNSSEC-aware forwarder?");
		return LDNS_STATUS_ERR;
	}

	/* Next try to find out if there is a DS for this name are
	 * a name under that
	 */
	i = lab_cnt;
	for(i = lab_cnt; i >= 0; i--) {
		ds = get_ds(res, chopped_dname[i], NULL);
		if (ds) {
			/* re-query to get the rrsigs */
			ds_cache = get_ds(res, chopped_dname[i], &rrsig_cache);
			dnskey_cache = get_keys(res, chopped_dname[i], &rrsig_cache);
			break;
		}
	}
	printf(" |\n ("); 
		ldns_rdf_print(stdout, chopped_dname[i]);
	puts(")");
	resolver_print_nameservers(res);
	puts("");
	print_dnskey(dnskey_cache);
	puts("");
	print_ds(ds_cache);
	puts("");

	validated_ds = check_ds_key_equiv_rr_list(dnskey_cache, ds_cache); 
	if (validated_ds) {
		print_ds(validated_ds);
	}

	return LDNS_STATUS_OK;
}


/* do a secure trace - ripped from drill < 0.9 */
ldns_status
do_secure_trace3(ldns_resolver *res, ldns_rdf *name, ldns_rr_type t,
		                ldns_rr_class c, ldns_rr_list *trusted_keys)
{
	ldns_pkt *p1 = NULL;
	ldns_pkt *p_keys = NULL;
	ldns_rr_list *key_list = NULL;
	ldns_rr_list *good_key_list = NULL;
	ldns_rr_list *sig_list = NULL;
	unsigned int secure = 1;

	while (ldns_pkt_reply_type(p1 = ldns_resolver_query(res, name, t, c, 0)) == LDNS_PACKET_REFERRAL) {
		ldns_pkt_print(stdout, p1);

		if (secure == 1) {
			/* Try to get the keys from the current nameserver */
			p_keys = ldns_resolver_query(res, name, LDNS_RR_TYPE_DNSKEY, c, 0);
			if (p_keys) {
				key_list = ldns_pkt_rr_list_by_type(
						p_keys, LDNS_RR_TYPE_DNSKEY, LDNS_SECTION_ANSWER);
				if (key_list) {

					ldns_rr_list_print(stdout, key_list);
					
					sig_list = ldns_pkt_rr_list_by_name_and_type(
							p_keys, 
							ldns_rr_owner(ldns_rr_list_rr(key_list, 0)),
							LDNS_RR_TYPE_RRSIG,
							LDNS_SECTION_ANY_NOQUESTION);

					if (sig_list) {
						ldns_rr_list_print(stdout, sig_list);

						if (ldns_verify(key_list, sig_list, key_list, 
									good_key_list)
								== LDNS_STATUS_OK) {
							printf("VALIDATED\n");
						}
					}	
				}
			}
		}
	}
	return LDNS_STATUS_OK;
}
