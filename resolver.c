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
#include <ldns/net.h>
#include <ldns/host2str.h>
#include <ldns/dns.h>

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
ldns_resolver_ip6(ldns_resolver *r)
{
	return r->_ip6;
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

uint8_t 
ldns_resolver_configured(ldns_resolver *r)
{
	return r->_configured;
}

ldns_rdf *
ldns_resolver_domain(ldns_resolver *r)
{
	return r->_domain;
}

ldns_rdf **
ldns_resolver_searchlist(ldns_resolver *r)
{
	return r->_searchlist;
}

ldns_rdf **
ldns_resolver_nameservers(ldns_resolver *r)
{
	return r->_nameservers;
}

size_t
ldns_resolver_nameserver_count(ldns_resolver *r)
{
	return r->_nameserver_count;
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
	ldns_rdf **nameservers;

	nameservers = ldns_resolver_nameservers(r);

	/* XXX do something smart when 3 is reached,
	 * or always REALLOC here */
	printf("number of nameservers %d\n",
			ldns_resolver_nameserver_count(r));

	ldns_rdf_print(stdout, n);
	printf("\n");
	/*
	nameservers[
		ldns_resolver_nameserver_count(r)] = n;
		*/
	r->_nameservers[0] = n;

	/* increase */
	ldns_resolver_incr_nameserver_count(r);

	printf("number of nameservers %d\n",
			ldns_resolver_nameserver_count(r));

	ldns_rdf_print(stdout, r->_nameservers[0]);
	printf("\n");

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
ldns_resolver_set_configured(ldns_resolver *r, uint8_t c)
{
	r->_configured = c;
}

void
ldns_resolver_set_searchlist_count(ldns_resolver *r, size_t c)
{
	r->_searchlist_count = c;
}

void
ldns_resolver_set_nameserver_count(ldns_resolver *r, size_t c)
{
	r->_nameserver_count = c;
}

void
ldns_resolver_incr_nameserver_count(ldns_resolver *r)
{
	size_t c;

	c = ldns_resolver_nameserver_count(r);
	ldns_resolver_set_nameserver_count(r, ++c);
}

ldns_status
ldns_resolver_set_domain(ldns_resolver *r, ldns_rdf *d)
{
	r->_domain = d;
	return LDNS_STATUS_OK;
}

/* this is not the way to go for the search list XXX */
ldns_status
ldns_resolver_push_searchlist(ldns_resolver *r, ldns_rdf *d)
{
	r->_searchlist[++r->_searchlist_count] = d;
	return LDNS_STATUS_OK;
}

/* more sophisticated functions */

/** 
 * \brief create a new resolver structure 
 * \param[in] void
 * \return ldns_resolver* pointer to new strcture
 */
ldns_resolver *
ldns_resolver_new(void)
{
	ldns_resolver *r;

	r = MALLOC(ldns_resolver);

	/* allow for 3 of these each */
	r->_searchlist = XMALLOC(ldns_rdf *, 3);
	r->_nameservers = XMALLOC(ldns_rdf *, 3);
	
	/* defaults are filled out */
	ldns_resolver_set_configured(r, 0);
	ldns_resolver_set_searchlist_count(r, 0);
	ldns_resolver_set_nameserver_count(r, 0);
	ldns_resolver_set_port(r, LDNS_PORT);
	return r;
}

/* search for information in the DNS.
 * search() applies the search list.
 * See Net::DNS::Resolver for details
 */
ldns_pkt *
ldns_resolver_search()
{
	return NULL;
}

/* only adds the default domain */
ldns_pkt *
ldns_resolver_query()
{
	return NULL;
}

/**
 * \brief Send the query for *name as-is 
 * \param[in] *r operate using this resolver
 * \param[in] *name query for this name
 * \param[in] *type query for this type (may be 0, defaults to A)
 * \param[in] *class query for this class (may be 0, default to IN)
 * \return ldns_pkt* a packet with the reply from the nameserver
 */
ldns_pkt *
ldns_resolver_send(ldns_resolver *r, ldns_rdf *name, ldns_rr_type type, ldns_rr_class class)
{
	ldns_pkt *query_pkt;
	ldns_pkt *answer_pkt;

	assert(r != NULL);
	assert(name != NULL);
	
	/* do all the preprocessing here, then fire of an query to 
	 * the network */

	if (type == 0) {
		type = LDNS_RR_TYPE_A;
	}
	if (class == 0) {
		class = LDNS_RR_CLASS_IN;
	}
	if (0 == ldns_resolver_configured(r)) {
		printf("resolver is not configued\n");
		return NULL;
	}
	if (ldns_rdf_get_type(name) != LDNS_RDF_TYPE_DNAME) {
		printf("query type is not correct type\n");
		return NULL;
	}
	
	/* prepare a question pkt from the parameters
	 * and then send this */
	query_pkt = ldns_pkt_query_new(name, type, class);
	if (!query_pkt) {
		printf("Failed to generate pkt\n");
	}

	/* return NULL on error */
	answer_pkt = ldns_send(r, query_pkt);
		
	return answer_pkt;
}

/* send the query as-is. but use a callback */
ldns_pkt *
ldns_resolver_bgsend()
{
	return NULL;
}
