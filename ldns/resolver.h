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
	ldns_rr_list _nameservers; 

	/** \brief Wether or not to be recursive */
	uint8_t _recursive;

	/** \brief Print debug information */
	uint8_t _debug;
	
	/* XXX both types below could be done better */
	/** \brief Default domain to add */
	ldns_rdf_type _domain; /* LDNS_RDF_TYPE_DNAME */

	/** \brief Searchlist */
	ldns_rdf_type _searchlist[3]; /* LDNS_RFD_TYPE_DNAME */

	/** \brief How many retries */
	uint8_t _retry;
};
	
typedef struct ldns_struct_resolver ldns_resolver;

#endif  /* !_LDNS_RESOLVER_H */
