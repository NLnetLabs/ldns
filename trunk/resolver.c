/*
 * resolver.c
 *
 * resolver implementation
 *
 * a Net::DNS like library for C
 *
 * (c) NLnet Labs, 2004
 *
 * See the file LICENSE for the license
 */

#include <config.h>

#include <ldns/rdata.h>
#include <ldns/error.h>
#include <ldns/resolver.h>

#include "util.h"

/* Access function for reading 
 * and setting the different Resolver 
 * options
 */

/* read */
uint16_t
ldns_resolver_port(ldns_resolver *r)
{
	return r->_port;
}

ldns_rr_list *
ldns_resolver_nameservers(ldns_resolver *r)
{
	return r->_nameservers;
}

uint8_t
ldns_resolver_recursive(ldns_resolver *r)
{
	return r->_recursive;
}

uint8_t
ldns_resolver_debug(ldns_resolver *r)
{
	return r->_debug;
}

ldns_rdf *
ldns_resolver_domain(ldns_resolver *r)
{
	return r->_domain;
}

ldns_rdf *
ldns_resolver_searchlist(ldns_resolver *r)
{
	return r->_searchlist;
}

/* write */
void
ldns_resolver_set_port(ldns_resolver *r, uint16_t p)
{
	r->_port = p;
}

void 
ldns_resolver_set_nameservers(ldns_resolver *r, ldns_rr_list *n)
{
	r->_nameservers = n;
}

void
ldns_resolver_set_recursive(ldns_resolver *r, uint8_t re)
{
	r->_recursive = re;
}

void
ldns_resolver_set_debug(ldns_resolver *r, uint8_t d)
{
	r->_debug = d;
}

void 
ldns_resolver_set_domain(ldns_resolver *r, ldns_rdf *d)
{
	if (ldns_rdf_get_type(d) != LDNS_RDF_TYPE_DNAME) {
		return;
	} 
	r->_domain = d;
}

/* this is not the way to go for the search list XXX */
void 
ldns_resolver_set_searchlist(ldns_resolver *r, ldns_rdf *s)
{
	if (ldns_rdf_get_type(s) != LDNS_RDF_TYPE_DNAME) {
		return;
	} 
	r->_searchlist = s;
}
