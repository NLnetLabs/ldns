/*
 * rr_function.c
 *
 * function that operate on specific rr types
 *
 * (c) NLnet Labs, 2004, 2005
 * See the file LICENSE for the license
 */

/*
 * these come strait from perldoc Net::DNS::RR::xxxx
 * first the read variant, then the write
 */

#include <config.h>

#include <limits.h>
#include <strings.h>

#include <ldns/rr.h>
#include <ldns/dns.h>

#include "util.h"


/* handle A / AAAA records */
ldns_rdf *
ldns_rr_address(ldns_rr *r)
{
	if (!r || (ldns_rr_get_type(r) != LDNS_RR_TYPE_A &&
			ldns_rr_get_type(r) != LDNS_RR_TYPE_AAAA)) {
		return NULL;
	}
	return ldns_rr_rdf(r, 0);
}

void
ldns_rr_set_address(ldns_rr *r)
{
	if (!r || (ldns_rr_get_type(r) != LDNS_RR_TYPE_A &&
			ldns_rr_get_type(r) != LDNS_RR_TYPE_AAAA)) {
		return;
	}
	/* pop it? or need a set function which can 
	 * set specific rfd's? */
}

/* NS records */
ldns_rdf *
ldns_rr_nsdname(ldns_rr *r)
{
	if (!r || (ldns_rr_get_type(r) != LDNS_RR_TYPE_NS)) {
		return NULL;
	}
	return ldns_rr_rdf(r, 0);
}

/* MX records */
ldns_rdf *
ldns_rr_preference(ldns_rr *r)
{
	if (!r || (ldns_rr_get_type(r) != LDNS_RR_TYPE_MX)) {
		return NULL;
	}
	return ldns_rr_rdf(r, 0);
}

ldns_rdf *
ldns_rr_exchange(ldns_rr *r)
{
	if (!r || (ldns_rr_get_type(r) != LDNS_RR_TYPE_MX)) {
		return NULL;
	}
	return ldns_rr_rdf(r, 1);
}

/* RRSIG records */
ldns_rdf *
ldns_rr_typecovered(ldns_rr *r)
{
	if (!r || (ldns_rr_get_type(r) != LDNS_RR_TYPE_RRSIG)) {
		return NULL;
	}
	return ldns_rr_rdf(r, 0);
}

ldns_rdf *
ldns_rr_algorithm(ldns_rr *r)
{
	if (!r || (ldns_rr_get_type(r) != LDNS_RR_TYPE_RRSIG)) {
		return NULL;
	}
	return ldns_rr_rdf(r, 1);
}

ldns_rdf *
ldns_rr_labels(ldns_rr *r)
{
	if (!r || (ldns_rr_get_type(r) != LDNS_RR_TYPE_RRSIG)) {
		return NULL;
	}
	return ldns_rr_rdf(r, 2);
}

ldns_rdf *
ldns_rr_origttl(ldns_rr *r)
{
	if (!r || (ldns_rr_get_type(r) != LDNS_RR_TYPE_RRSIG)) {
		return NULL;
	}
	return ldns_rr_rdf(r, 3);
}
	
ldns_rdf *
ldns_rr_expiration(ldns_rr *r)
{
	if (!r || (ldns_rr_get_type(r) != LDNS_RR_TYPE_RRSIG)) {
		return NULL;
	}
	return ldns_rr_rdf(r, 4);
}

ldns_rdf *
ldns_rr_inception(ldns_rr *r)
{
	if (!r || (ldns_rr_get_type(r) != LDNS_RR_TYPE_RRSIG)) {
		return NULL;
	}
	return ldns_rr_rdf(r, 5);
}

ldns_rdf *
ldns_rr_keytag(ldns_rr *r)
{
	if (!r || (ldns_rr_get_type(r) != LDNS_RR_TYPE_RRSIG)) {
		return NULL;
	}
	return ldns_rr_rdf(r, 6);
}

ldns_rdf *
ldns_rr_signame(ldns_rr *r)
{
	if (!r || (ldns_rr_get_type(r) != LDNS_RR_TYPE_RRSIG)) {
		return NULL;
	}
	return ldns_rr_rdf(r, 7);
}

ldns_rdf *
ldns_rr_sig(ldns_rr *r)
{
	if (!r || (ldns_rr_get_type(r) != LDNS_RR_TYPE_RRSIG)) {
		return NULL;
	}
	return ldns_rr_rdf(r, 8);
}
