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
#include <ldns/rr_functions.h>

#include "util.h"


/* handle A / AAAA records */
ldns_rdf *
ldns_rr_address(ldns_rr *r)
{
	/* 2 types to check, cannot use the macro */
	if (!r || (ldns_rr_get_type(r) != LDNS_RR_TYPE_A &&
			ldns_rr_get_type(r) != LDNS_RR_TYPE_AAAA)) {
		return NULL;
	}
	return ldns_rr_rdf(r, 0);
}

/* write -
 * if there is a value in the rr - is is _freed_! 
 */
bool
ldns_rr_set_address(ldns_rr *r, ldns_rdf *f)
{
	/* 2 types to check, cannot use the macro... */
	ldns_rdf *pop;
	if (!r || (ldns_rr_get_type(r) != LDNS_RR_TYPE_A &&
			ldns_rr_get_type(r) != LDNS_RR_TYPE_AAAA)) {
		return false;
	}
	pop = ldns_rr_set_rdf(r, f, 0);
	if (pop) {
		FREE(pop);
		return true;
	} else {
		return false;
	}
}

/* NS records */
ldns_rdf *
ldns_rr_nsdname(ldns_rr *r)
{
	_LDNS_RR_FUNCTION(r, 0, LDNS_RR_TYPE_NS);
}

/* MX records */
ldns_rdf *
ldns_rr_preference(ldns_rr *r)
{
	_LDNS_RR_FUNCTION(r, 0, LDNS_RR_TYPE_MX);
}

ldns_rdf *
ldns_rr_exchange(ldns_rr *r)
{
	_LDNS_RR_FUNCTION(r, 1, LDNS_RR_TYPE_MX);
}

/* RRSIG record */
ldns_rdf *
ldns_rr_typecovered(ldns_rr *r)
{
	_LDNS_RR_FUNCTION(r, 0, LDNS_RR_TYPE_RRSIG);
}

bool
ldns_rr_set_typecovered(ldns_rr *r, ldns_rdf *f)
{
	_LDNS_RR_SET_FUNCTION(r, f, 0, LDNS_RR_TYPE_RRSIG);
}

ldns_rdf *
ldns_rr_algorithm(ldns_rr *r)
{
	_LDNS_RR_FUNCTION(r, 1, LDNS_RR_TYPE_RRSIG);
}

bool
ldns_rr_set_algorithm(ldns_rr *r, ldns_rdf *f)
{
	_LDNS_RR_SET_FUNCTION(r, f, 1, LDNS_RR_TYPE_RRSIG);
}

ldns_rdf *
ldns_rr_labels(ldns_rr *r)
{
	_LDNS_RR_FUNCTION(r, 2, LDNS_RR_TYPE_RRSIG);
}
bool
ldns_rr_set_labels(ldns_rr *r, ldns_rdf *f)
{
	_LDNS_RR_SET_FUNCTION(r, f, 2, LDNS_RR_TYPE_RRSIG);
}

ldns_rdf *
ldns_rr_origttl(ldns_rr *r)
{
	_LDNS_RR_FUNCTION(r, 3, LDNS_RR_TYPE_RRSIG);
}
bool
ldns_rr_set_origtll(ldns_rr *r, ldns_rdf *f)
{
	_LDNS_RR_SET_FUNCTION(r, f, 3, LDNS_RR_TYPE_RRSIG);
}
	
ldns_rdf *
ldns_rr_expiration(ldns_rr *r)
{
	_LDNS_RR_FUNCTION(r, 4, LDNS_RR_TYPE_RRSIG);
}
bool
ldns_rr_set_expiration(ldns_rr *r, ldns_rdf *f)
{
	_LDNS_RR_SET_FUNCTION(r, f, 4, LDNS_RR_TYPE_RRSIG);
}

ldns_rdf *
ldns_rr_inception(ldns_rr *r)
{
	_LDNS_RR_FUNCTION(r, 5, LDNS_RR_TYPE_RRSIG);
}
bool
ldns_rr_set_inception(ldns_rr *r, ldns_rdf *f)
{
	_LDNS_RR_SET_FUNCTION(r, f, 5, LDNS_RR_TYPE_RRSIG);
}

ldns_rdf *
ldns_rr_keytag(ldns_rr *r)
{
	_LDNS_RR_FUNCTION(r, 6, LDNS_RR_TYPE_RRSIG);
}

bool
ldns_rr_set_keytag(ldns_rr *r, ldns_rdf *f)
{
	_LDNS_RR_SET_FUNCTION(r, f, 6, LDNS_RR_TYPE_RRSIG);
}
ldns_rdf *
ldns_rr_signame(ldns_rr *r)
{
	_LDNS_RR_FUNCTION(r, 7, LDNS_RR_TYPE_RRSIG);
}
bool
ldns_rr_set_signame(ldns_rr *r, ldns_rdf *f)
{
	_LDNS_RR_SET_FUNCTION(r, f, 7, LDNS_RR_TYPE_RRSIG);
}

ldns_rdf *
ldns_rr_sig(ldns_rr *r)
{
	_LDNS_RR_FUNCTION(r, 8, LDNS_RR_TYPE_RRSIG);
}

bool
ldns_rr_set_sig(ldns_rr *r, ldns_rdf *f)
{
	_LDNS_RR_SET_FUNCTION(r, f, 8, LDNS_RR_TYPE_RRSIG);
}
