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
#include <ldns/rdata.h>

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

ldns_dname *
ldns_resolver_domain(ldns_resolver *r)
{
	return r->_domain;
}

ldns_dname **
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

ldns_status
ldns_resolver_push_nameserver(ldns_resolver *r, ldns_rdf *n)
{
	/* LDNS_RDF_TYPE_A | LDNS_RDF_TYPE_AAAA | LDNS_RDF_TYPE_DNAME */
	r->_nameservers[++r->_nameserver_count] = n;
	return LDNS_STATUS_OK;
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
ldns_resolver_set_domain(ldns_resolver *r, ldns_dname *d)
{
	r->_domain = d;
}

/* this is not the way to go for the search list XXX */
ldns_status
ldns_resolver_push_searchlist(ldns_resolver *r, ldns_dname *d)
{
	r->_searchlist[++r->_searchlist_count] = d;
	return LDNS_STATUS_OK;
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

/** 
 * \brief create a new resolver structure 
 * \param[in] void
 * \return ldns_resolver* pointer to new strcture
 */
ldns_resolver *
ldns_resover_new(void)
{
	ldns_resolver *r;

	r = MALLOC(ldns_resolver);

	r->_configured = 0; /* no config has happened yet */
	r->_searchlist_count = 0; /* no searchlist */

	/* no defaults are filled out (yet) */
	return r;
}

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

/**
 * \brief Send the query for *name as-is 
 * \param[in] *r operate using this resolver
 * \param[in] *name query for this name
 * \param[in] *type query for this type (may be NULL, defaults to A)
 * \param[in] *class query for this class (may be NULL, default to IN)
 * \return ldns_pkt* a packet with the reply from the nameserver
 */
ldns_pkt *
ldns_send(ldns_resolver *r, ldns_dname *name, ldns_rr_type *type, ldns_rr_class *class)
{
	assert(r != NULL);
	assert(name != NULL);
	
	/* do all the preprocessing here, then fire of an query to 
	 * the network
	 */

	return NULL;
}

/* send the query as-is. but use a callback */
ldns_pkt *
ldns_bgsend()
{
	return NULL;
}
