/*
 * resolver.h
 *
 * DNS Resolver definitions
 *
 * a Net::DNS like library for C
 *
 * (c) NLnet Labs, 2004
 *
 * See the file LICENSE for the license
 */

#ifndef _LDNS_RESOLVER_H
#define _LDNS_RESOLVER_H

#include <ldns/error.h>
#include <ldns/common.h>
#include <ldns/rr.h>
#include <ldns/packet.h>

/**
 * \brief Structure of a dns resolver
 *
 * 
 */
struct ldns_struct_resolver
{
	/** \brief On which port to run */
	uint16_t _port;

	/** \brief List of nameservers to query */
	ldns_rr_list *_nameservers; 

	/** \brief Wether or not to be recursive */
	uint8_t _recursive;

	/** \brief Print debug information */
	uint8_t _debug;
	
	/* XXX both types below could be done better, mabye rr_list? */
	/** \brief Default domain to add */
	ldns_rdf *_domain; /* LDNS_RDF_TYPE_DNAME */

	/** \brief Searchlist */
	ldns_rdf *_searchlist; /* LDNS_RFD_TYPE_DNAME */

	/** \brief How many retries */
	uint8_t _retry;
	/** \brief Wether to do DNSSEC */
	uint8_t _dnssec;
	/** \brief Wether to use tcp */
	uint8_t _usevc;
	/** \brief Wether to ignore the tc bit */
	uint8_t _igntc;
	
};
	
typedef struct ldns_struct_resolver ldns_resolver;

/* prototypes */
uint16_t ldns_resolver_port(ldns_resolver *);
ldns_rr_list * ldns_resolver_nameservers(ldns_resolver *);
uint8_t ldns_resolver_recursive(ldns_resolver *);
uint8_t ldns_resolver_debug(ldns_resolver *);
ldns_rdf * ldns_resolver_domain(ldns_resolver *);
ldns_rdf * ldns_resolver_searchlist(ldns_resolver *);

void ldns_resolver_set_port(ldns_resolver *, uint16_t);
void ldns_resolver_set_nameservers(ldns_resolver *, ldns_rr_list *);
void ldns_resolver_set_recursive(ldns_resolver *, uint8_t);
void ldns_resolver_set_debug(ldns_resolver *, uint8_t);
void ldns_resolver_set_domain(ldns_resolver *, ldns_rdf *);
void ldns_resolver_set_searchlist(ldns_resolver *, ldns_rdf *);

ldns_pkt * ldns_search();
ldns_pkt * ldns_query();
ldns_pkt * ldns_send(ldns_resolver *, uint8_t*, uint8_t*, uint8_t*);
ldns_pkt * ldns_bgsend();

#endif  /* !_LDNS_RESOLVER_H */
