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
#include <ldns/rdata.h>
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

	/** \brief List of nameservers to query (IP addresses or dname) */
	ldns_rdf **_nameservers; 
	size_t _nameserver_count; /* how many do we have */

	/** \brief Wether or not to be recursive */
	uint8_t _recursive;

	/** \brief Print debug information */
	uint8_t _debug;
	
	/** \brief Default domain to add */
	ldns_dname *_domain; 

	/** \brief Searchlist array */
	ldns_dname **_searchlist;
	size_t _searchlist_count;

	/** \brief How many retries */
	uint8_t _retry;
	/** \brief Wether to do DNSSEC */
	uint8_t _dnssec;
	/** \brief Wether to use tcp */
	uint8_t _usevc;
	/** \brief Wether to ignore the tc bit */
	uint8_t _igntc;
	/** \brief Wether to use ip6 */
	uint8_t _ip6;
	/** \brief 1 if the resolver is properly configured */
	uint8_t _configured;
	
};
	
typedef struct ldns_struct_resolver ldns_resolver;

/* prototypes */
uint16_t ldns_resolver_port(ldns_resolver *);
/* ldns_rr_list * ldns_resolver_nameservers(ldns_resolver *) pop>? */
uint8_t ldns_resolver_recursive(ldns_resolver *);
uint8_t ldns_resolver_debug(ldns_resolver *);
ldns_dname * ldns_resolver_domain(ldns_resolver *);
ldns_dname ** ldns_resolver_searchlist(ldns_resolver *);
ldns_dname ** ldns_resolver_nameservers(ldns_resolver *);

void ldns_resolver_set_port(ldns_resolver *, uint16_t);
void ldns_resolver_set_recursive(ldns_resolver *, uint8_t);
void ldns_resolver_set_debug(ldns_resolver *, uint8_t);

ldns_status ldns_resolver_set_domain(ldns_resolver *, ldns_dname *);
ldns_status ldns_resolver_push_searchlist(ldns_resolver *, ldns_dname *);
ldns_status ldns_resolver_push_nameserver(ldns_resolver *, ldns_rdf *);

ldns_pkt * ldns_resolver_search();
ldns_pkt * ldns_resolver_query();
ldns_pkt * ldns_resolver_bgsend();
ldns_pkt * ldns_resolver_send(ldns_resolver *, ldns_dname*, ldns_rr_type, ldns_rr_class);

ldns_resolver *ldns_resolver_new(void);

#endif  /* !_LDNS_RESOLVER_H */
