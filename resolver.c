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
ldns_resolver_set_dnssec(ldns_resolver *r, uint8_t d)
{
	r->_dnssec = d;
}

void
ldns_resolver_set_igntc(ldns_resolver *r, uint8_t i)
{
	r->_igntc = i;
}

void
ldns_resolver_set_usevc(ldns_resolver *r, uint8_t vc)
{
	r->_usevc = vc;
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

uint8_t
ldns_resolver_dnssec(ldns_resolver *r)
{
	return r->_dnssec;
}

uint8_t
ldns_resolver_igntc(ldns_resolver *r)
{
	return r->_igntc;
}

uint8_t
ldns_resolver_usevc(ldns_resolver *r)
{
	return r->_usevc;
}

/* more sophisticated functions */

/* search for information in the DNS.
 * search() applies the search list.
 * See Net::DNS::Resolver for details
 */
ldns_pkt *
ldns_search()
{
	return NULL;
}

/* only adds the default domain */
ldns_pkt *
ldns_query()
{
	return NULL;
}

/* send the query as-is */
ldns_pkt *
ldns_send()
{
	return NULL;
}

/* send the query as-is. but use a callback */
ldns_pkt *
ldns_bgsend()
{
	return NULL;
}
