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
#include <ldns/dname.h>

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

bool
ldns_resolver_ip6(ldns_resolver *r)
{
	return r->_ip6;
}

bool
ldns_resolver_recursive(ldns_resolver *r)
{
	return r->_recursive;
}

bool
ldns_resolver_debug(ldns_resolver *r)
{
	return r->_debug;
}

bool
ldns_resolver_dnsrch(ldns_resolver *r)
{
	return r->_dnsrch;
}

bool
ldns_resolver_defnames(ldns_resolver *r)
{
	return r->_defnames;
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

bool
ldns_resolver_dnssec(ldns_resolver *r)
{
	return r->_dnssec;
}

bool
ldns_resolver_igntc(ldns_resolver *r)
{
	return r->_igntc;
}

bool
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

/**
 * push a new nameserver to the resolver. It must be an IP
 * address v4 or v6.
 * \param[in] r the resolver
 * \param[in] n the ip address
 * \return ldns_status a status
 */
ldns_status
ldns_resolver_push_nameserver(ldns_resolver *r, ldns_rdf *n)
{
	/* LDNS_RDF_TYPE_A | LDNS_RDF_TYPE_AAAA */
	ldns_rdf **nameservers;

	if (ldns_rdf_get_type(n) != LDNS_RDF_TYPE_A &&
			ldns_rdf_get_type(n) != LDNS_RDF_TYPE_AAAA) {
		return LDNS_STATUS_ERR;
	}

	nameservers = ldns_resolver_nameservers(r);

	/* make room for the next one */
	nameservers = XREALLOC(nameservers, ldns_rdf *, 
			(ldns_resolver_nameserver_count(r) + 1));

	/* slide *n in its slot */
	nameservers[
		ldns_resolver_nameserver_count(r)] = n;

	ldns_resolver_incr_nameserver_count(r);
	return LDNS_STATUS_OK;
}

void
ldns_resolver_set_recursive(ldns_resolver *r, bool re)
{
	r->_recursive = re;
}

void
ldns_resolver_set_dnssec(ldns_resolver *r, bool d)
{
	r->_dnssec = d;
}

void
ldns_resolver_set_igntc(ldns_resolver *r, bool i)
{
	r->_igntc = i;
}

void
ldns_resolver_set_usevc(ldns_resolver *r, bool vc)
{
	r->_usevc = vc;
}

void
ldns_resolver_set_debug(ldns_resolver *r, bool d)
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
ldns_resolver_set_dnsrch(ldns_resolver *r, bool d)
{
	r->_dnsrch = d;
}

void
ldns_resolver_set_defnames(ldns_resolver *r, bool d)
{
	r->_defnames = d;
}

void
ldns_resolver_incr_nameserver_count(ldns_resolver *r)
{
	size_t c;

	c = ldns_resolver_nameserver_count(r);
	ldns_resolver_set_nameserver_count(r, ++c);
}

void
ldns_resolver_set_domain(ldns_resolver *r, ldns_rdf *d)
{
	r->_domain = d;
}

void
ldns_resolver_push_searchlist(ldns_resolver *r, ldns_rdf *d)
{
	r->_searchlist[++r->_searchlist_count] = d;
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
	r->_searchlist = MALLOC(ldns_rdf *);
	r->_nameservers = MALLOC(ldns_rdf *);
	
	/* defaults are filled out */
	ldns_resolver_set_configured(r, 0);
	ldns_resolver_set_searchlist_count(r, 0);
	ldns_resolver_set_nameserver_count(r, 0);
	ldns_resolver_set_port(r, LDNS_PORT);
	ldns_resolver_set_domain(r, NULL);
	ldns_resolver_set_defnames(r, false);
	return r;
}

/** 
 * Send the query 
 * \param[in] *r operate using this resolver
 * \param[in] *name query for this name
 * \param[in] *type query for this type (may be 0, defaults to A)
 * \param[in] *class query for this class (may be 0, default to IN)
 * \return ldns_pkt* a packet with the reply from the nameserver
 * if _dnsrch is true add the searchlist
 */
ldns_pkt *
ldns_resolver_search(ldns_resolver *r, ldns_rdf *name, ldns_rr_type type, 
                ldns_rr_class class, uint16_t flags)
{
	/* dummy use parameters */
	printf("%p %p %d %d %02x\n", (void *) r, (void *) name, type, class,
	                             (unsigned int) flags);
	return NULL;
}

/**
 * Send a qeury to a nameserver
 * \param[in] *r operate using this resolver
 * \param[in] *name query for this name
 * \param[in] *type query for this type (may be 0, defaults to A)
 * \param[in] *class query for this class (may be 0, default to IN)
 * \return ldns_pkt* a packet with the reply from the nameserver
 * if _defnames is true the default domain will be added
 */
ldns_pkt *
ldns_resolver_query(ldns_resolver *r, ldns_rdf *name, ldns_rr_type type, ldns_rr_class class,
                uint16_t flags)
{
	ldns_rdf *newname;
	
	if (!ldns_resolver_defnames(r)) {
		return ldns_resolver_send(r, name, type, class, flags);
	}
	if (!ldns_resolver_domain(r)) {
		/* _defnames is set, but the domain is not....?? */
		return ldns_resolver_send(r, name, type, class, flags);
	}

	newname = ldns_dname_concat(name, ldns_resolver_domain(r));
	if (!newname) {
		return NULL;
	}
	ldns_rdf_print(stdout, newname);
	printf("the new name\n");
	return ldns_resolver_send(r, newname, type, class, flags);
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
ldns_resolver_send(ldns_resolver *r, ldns_rdf *name, ldns_rr_type type, ldns_rr_class class,
		uint16_t flags)
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
	query_pkt = ldns_pkt_query_new(name, type, class, flags);
	if (!query_pkt) {
		printf("Failed to generate pkt\n");
		return NULL;
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
