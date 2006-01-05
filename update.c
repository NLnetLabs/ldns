/* update.c
 *
 * Functions for RFC 2136 Dynamic Update
 *
 * Copyright (c) 2005-2006, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 */

#include <ldns/config.h>

#include <ldns/dns.h>

#include <strings.h>
#include <stdlib.h>
#include <limits.h>

/*
 * RFC 2136 sections mapped to RFC 1035:
 *              zone/ZO -- QD/question
 *     prerequisites/PR -- AN/answers
 *           updates/UP -- NS/authority records
 *   additional data/AD -- AR/additional records
 */

#define _zone    _question
#define _prereq  _answer
#define _updates _authority

/**
 * create an update packet from zone name, class and the rr lists
 * \param[in] zone name of the zone
 * \param[in] class zone class
 * \param[in] pr_rrlist list of Prerequisite Section RRs
 * \param[in] up_rrlist list of Updates Section RRs
 * \param[in] ad_rrlist list of Additional Data Section RRs (currently unused)
 */
ldns_pkt *
ldns_update_pkt_new(ldns_rdf *zone_rdf, ldns_rr_class class,
    ldns_rr_list *pr_rrlist, ldns_rr_list *up_rrlist, ldns_rr_list *ad_rrlist)
{
	ldns_pkt *p;

	if (!zone_rdf || !up_rrlist) {
		dprintf("%s", "bad input to ldns_update_pkt_new()\n");
		return NULL;
	}

	if (class == 0) {
		class = LDNS_RR_CLASS_IN;
	}

	/* Create packet, fill in Zone Section. */
	p = ldns_pkt_query_new(zone_rdf, LDNS_RR_TYPE_SOA, class, LDNS_RD);
	if (!p)
		return NULL;
	zone_rdf = NULL; /* No longer safe to use. */

	ldns_pkt_set_opcode(p, LDNS_PACKET_UPDATE);

	ldns_rr_list_deep_free(p->_updates);
	p->_updates = ldns_rr_list_clone(up_rrlist);
	ldns_update_set_up(p, ldns_rr_list_rr_count(up_rrlist));

	if (pr_rrlist) {
		ldns_rr_list_deep_free(p->_prereq);
		p->_prereq = ldns_rr_list_clone(pr_rrlist);
		ldns_update_set_pr(p, ldns_rr_list_rr_count(pr_rrlist));
	}

	if (ad_rrlist) {
		ldns_rr_list_deep_free(p->_additional);
		p->_additional = ldns_rr_list_clone(ad_rrlist);
		ldns_update_set_ad(p, ldns_rr_list_rr_count(ad_rrlist));
	}

	return p;
}

ldns_status
ldns_update_pkt_tsig_add(ldns_pkt *p, ldns_resolver *r)
{
	uint16_t fudge = 300; /* Recommended fudge. [RFC2845 6.4]  */

	if (ldns_resolver_tsig_keyname(r) && ldns_resolver_tsig_keydata(r))
		return ldns_pkt_tsig_sign(p, ldns_resolver_tsig_keyname(r),
		    ldns_resolver_tsig_keydata(r), fudge,
		    ldns_resolver_tsig_algorithm(r), NULL);

	/* No TSIG to do. */
	return LDNS_STATUS_OK;
}

/* Move to higher.c or similar? */

ldns_status
ldns_update_get_soa_mname(ldns_rdf *zone, ldns_resolver *r,
    ldns_rr_class class, ldns_rdf **mname)
{
	ldns_rr		*soa_rr;
	ldns_pkt	*query, *resp;

	/* Nondestructive, so clone 'zone' here */
	query = ldns_pkt_query_new(ldns_rdf_clone(zone), LDNS_RR_TYPE_SOA,
	    class, LDNS_RD);
	if (!query)
		return LDNS_STATUS_ERR;

	ldns_pkt_set_random_id(query);
	if (ldns_resolver_send_pkt(&resp, r, query) != LDNS_STATUS_OK) {
		dprintf("%s", "SOA query failed (MNAME)\n");
		ldns_pkt_free(query);
		return LDNS_STATUS_ERR;
	}
	ldns_pkt_free(query);
	if (!resp)
		return LDNS_STATUS_ERR;

	/* Expect a SOA answer. */
	*mname = NULL;
	while ((soa_rr = ldns_rr_list_pop_rr(ldns_pkt_answer(resp)))) {
		if (ldns_rr_get_type(soa_rr) != LDNS_RR_TYPE_SOA)
			continue;
		/* [RFC1035 3.3.13] */
		*mname = ldns_rdf_clone(ldns_rr_rdf(soa_rr, 0));
		break;
	}
	ldns_pkt_free(resp);

	return *mname ? LDNS_STATUS_OK : LDNS_STATUS_ERR;
}

/* Try to get zone and MNAME from SOA queries. */
ldns_status
ldns_update_get_soa_zone_mname(const char *fqdn, ldns_resolver *r,
    ldns_rr_class class, ldns_rdf **zone_rdf, ldns_rdf **mname_rdf)
{
	ldns_rr		*soa_rr, *rr;
	ldns_rdf	*soa_zone = NULL, *soa_mname = NULL;
	ldns_rdf	*ipaddr, *fqdn_rdf, *tmp;
	ldns_rdf	**nslist;
	ldns_pkt	*query, *resp;
	size_t		i;

	/* 
	 * XXX Ok, this cannot be the best way to find this...?
	 * XXX (I run into weird cache-related stuff here)
	 */

	/* Step 1 - first find a nameserver that should know *something* */
	fqdn_rdf = ldns_dname_new_frm_str(fqdn);
	query = ldns_pkt_query_new(fqdn_rdf, LDNS_RR_TYPE_SOA, class, LDNS_RD);
	if (!query)
		return LDNS_STATUS_ERR;
	fqdn_rdf = NULL;

	ldns_pkt_set_random_id(query);
	if (ldns_resolver_send_pkt(&resp, r, query) != LDNS_STATUS_OK) {
		dprintf("%s", "SOA query failed\n");
		ldns_pkt_free(query);
		return LDNS_STATUS_ERR;
	}
	ldns_pkt_free(query);
	if (!resp)
		return LDNS_STATUS_ERR;

	/* XXX Is it safe to only look in authority section here? */
	while ((soa_rr = ldns_rr_list_pop_rr(ldns_pkt_authority(resp)))) {
		if (ldns_rr_get_type(soa_rr) != LDNS_RR_TYPE_SOA)
			continue;
		/* [RFC1035 3.3.13] */
		soa_mname = ldns_rdf_clone(ldns_rr_rdf(soa_rr, 0));
		break;
	}
	ldns_pkt_free(resp);
	if (!soa_rr)
		return LDNS_STATUS_ERR;

	/* Step 2 - find SOA MNAME IP address, add to resolver */
	query = ldns_pkt_query_new(soa_mname, LDNS_RR_TYPE_A, class, LDNS_RD);
	if (!query)
		return LDNS_STATUS_ERR;
	soa_mname = NULL;

	ldns_pkt_set_random_id(query);
	if (ldns_resolver_send_pkt(&resp, r, query) != LDNS_STATUS_OK) {
		dprintf("%s", "SOA query 2 failed\n");
		ldns_pkt_free(query);
		return LDNS_STATUS_ERR;
	}
	ldns_pkt_free(query);
	if (!resp)
		return LDNS_STATUS_ERR;

	if (ldns_pkt_ancount(resp) == 0) {
		ldns_pkt_free(resp);
		return LDNS_STATUS_ERR;
	}

	/* XXX There may be more than one answer RR here. */
	rr = ldns_rr_list_pop_rr(ldns_pkt_answer(resp));
	ipaddr = ldns_rr_rdf(rr, 0);

	/* Put the SOA mname IP first in the nameserver list. */
	nslist = ldns_resolver_nameservers(r);
	for (i = 0; i < ldns_resolver_nameserver_count(r); i++) {
		if (ldns_rdf_compare(ipaddr, nslist[i]) == 0) {
			if (i) {
				tmp = nslist[0];
				nslist[0] = nslist[i];
				nslist[i] = tmp;
			}
			break;
		}
	}
	if (i >= ldns_resolver_nameserver_count(r)) {
		/* SOA mname was not part of the resolver so add it first. */
		(void) ldns_resolver_push_nameserver(r, ipaddr);
		nslist = ldns_resolver_nameservers(r);
		i = ldns_resolver_nameserver_count(r) - 1;
		tmp = nslist[0];
		nslist[0] = nslist[i];
		nslist[i] = tmp;
	}
	ldns_pkt_free(resp);

	/* Make sure to ask the first in the list, i.e SOA mname */
	ldns_resolver_set_random(r, false);

	/* Step 3 - Redo SOA query, sending to SOA MNAME directly. */
	fqdn_rdf = ldns_dname_new_frm_str(fqdn);
	query = ldns_pkt_query_new(fqdn_rdf, LDNS_RR_TYPE_SOA, class, LDNS_RD);
	if (!query)
		return LDNS_STATUS_ERR;
	fqdn_rdf = NULL;

	ldns_pkt_set_random_id(query);
	if (ldns_resolver_send_pkt(&resp, r, query) != LDNS_STATUS_OK) {
		dprintf("%s", "SOA query failed\n");
		ldns_pkt_free(query);
		return LDNS_STATUS_ERR;
	}
	ldns_pkt_free(query);
	if (!resp)
		return LDNS_STATUS_ERR;

	/* XXX Is it safe to only look in authority section here, too? */
	while ((soa_rr = ldns_rr_list_pop_rr(ldns_pkt_authority(resp)))) {
		if (ldns_rr_get_type(soa_rr) != LDNS_RR_TYPE_SOA)
			continue;
		/* [RFC1035 3.3.13] */
		soa_mname = ldns_rdf_clone(ldns_rr_rdf(soa_rr, 0));
		soa_zone = ldns_rdf_clone(ldns_rr_owner(soa_rr));
		break;
	}
	ldns_pkt_free(resp);
	if (!soa_rr)
		return LDNS_STATUS_ERR;

	/* That seems to have worked, pass results to caller. */
	*zone_rdf = soa_zone;
	*mname_rdf = soa_mname;
	return LDNS_STATUS_OK;
}	

/**
 * Create a resolver suitable for use with UPDATE. [RFC2136 4.3]
 * SOA MNAME is used as the "primary master".
 * \param[in] fqdn FQDN of a host in a zone
 * \param[in] zone zone name, if explicitly given, otherwise use SOA
 * \param[in] class zone class
 * \param[in] tsig_cred TSIG credentials
 * \param[out] zone returns zone/owner rdf from the 'fqdn' SOA MNAME query 
 */
ldns_resolver *
ldns_update_resolver_new(const char *fqdn, const char *zone,
    ldns_rr_class class, ldns_tsig_credentials *tsig_cred, ldns_rdf **zone_rdf)
{
	ldns_resolver	*r1, *r2;
	ldns_pkt	*query = NULL, *resp;
	ldns_rr_list	*nslist, *iplist;
	ldns_rdf	*soa_zone, *soa_mname, *ns_name;
	size_t		i;

	if (class == 0)
		class = LDNS_RR_CLASS_IN;

	/* First, get data from /etc/resolv.conf */
	r1 = ldns_resolver_new_frm_file(NULL);
	if (!r1)
		return NULL;

	r2 = ldns_resolver_new();
	if (!r2)
		goto bad;

	/* TSIG key data available? Copy into the resolver. */
	if (tsig_cred) {
		ldns_resolver_set_tsig_algorithm(r2,
		    ldns_tsig_algorithm(tsig_cred));
		ldns_resolver_set_tsig_keyname(r2,
		    ldns_tsig_keyname_clone(tsig_cred));
		/*
		 * XXX Weird that ldns_resolver_deep_free() will free()
		 * keyname but not hmac key data?
		 */
		ldns_resolver_set_tsig_keydata(r2,
		    ldns_tsig_keydata_clone(tsig_cred));
	}
	
	/* Now get SOA zone, mname, NS, and construct r2. [RFC2136 4.3] */

	/* Explicit 'zone' or no? */
	if (zone) {
		soa_zone = ldns_dname_new_frm_str(zone);
		if (ldns_update_get_soa_mname(soa_zone, r1, class, &soa_mname)
		    != LDNS_STATUS_OK)
			goto bad;
	} else {
		if (ldns_update_get_soa_zone_mname(fqdn, r1, class, &soa_zone,
			&soa_mname) != LDNS_STATUS_OK)
			goto bad;
	}
	
	/* Pass zone_rdf on upwards. */
	*zone_rdf = ldns_rdf_clone(soa_zone);
	
	/* NS */
	query = ldns_pkt_query_new(soa_zone, LDNS_RR_TYPE_NS, class, LDNS_RD);
	if (!query)
		goto bad;
	soa_zone = NULL;

	ldns_pkt_set_random_id(query);
	if (ldns_resolver_send_pkt(&resp, r1, query) != LDNS_STATUS_OK) {
		dprintf("%s", "NS query failed!\n");
		goto bad;
	}
	ldns_pkt_free(query);
	if (!resp)
		goto bad;

	/* Match SOA MNAME to NS list, adding it first */
	nslist = ldns_pkt_answer(resp);
	for (i = 0; i < ldns_rr_list_rr_count(nslist); i++) {
		ns_name = ldns_rr_rdf(ldns_rr_list_rr(nslist, i), 0);
		if (!ns_name)
			continue;
		if (ldns_rdf_compare(soa_mname, ns_name) == 0) {
			/* Match */
			iplist = ldns_get_rr_list_addr_by_name(r1, ns_name,
			    class, 0);
			(void) ldns_resolver_push_nameserver_rr_list(r2, iplist);
			break;
		}
	}

	/* Then all the other NSs. XXX Randomize? */
	for (i = 0; i < ldns_rr_list_rr_count(nslist); i++) {
		ns_name = ldns_rr_rdf(ldns_rr_list_rr(nslist, i), 0);
		if (!ns_name)
			continue;
		if (ldns_rdf_compare(soa_mname, ns_name) != 0) {
			/* No match, add it now. */
			iplist = ldns_get_rr_list_addr_by_name(r1, ns_name,
			    class, 0);
			(void) ldns_resolver_push_nameserver_rr_list(r2, iplist);
		}
	}

	/* Cleanup and return. */
	ldns_resolver_set_random(r2, false);
	ldns_pkt_free(resp);
	ldns_resolver_deep_free(r1);
	return r2;
	
  bad:
	if (r1)
		ldns_resolver_deep_free(r1);
	if (r2)
		ldns_resolver_deep_free(r2);
	if (query)
		ldns_pkt_free(query);
	if (resp)
		ldns_pkt_free(resp);
	return NULL;
}

/*
 * ldns_update_{get,set}_{zo,pr,up,ad}.
 */

uint16_t
ldns_update_get_zo(const ldns_pkt *p)
{
	return ldns_pkt_qdcount(p);
}

uint16_t
ldns_update_get_pr(const ldns_pkt *p)
{
	return ldns_pkt_ancount(p);
}

uint16_t
ldns_update_get_up(const ldns_pkt *p)
{
	return ldns_pkt_nscount(p);
}

uint16_t
ldns_update_get_ad(const ldns_pkt *p)
{
	return ldns_pkt_arcount(p);
}

void
ldns_update_set_zo(ldns_pkt *p, uint16_t v)
{
	ldns_pkt_set_qdcount(p, v);
}

void
ldns_update_set_pr(ldns_pkt *p, uint16_t v)
{
	ldns_pkt_set_ancount(p, v);
}

void
ldns_update_set_up(ldns_pkt *p, uint16_t v)
{
	ldns_pkt_set_nscount(p, v);
}

void
ldns_update_set_ad(ldns_pkt *p, uint16_t v)
{
	ldns_pkt_set_arcount(p, v);
}


