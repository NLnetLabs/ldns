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
#include <sys/time.h>


/** \brief where to find the resolv.conf file */
#define RESOLV_CONF	"/etc/resolv.conf"
#define MAXLINE_LEN	256
#define RESOLV_KEYWORD		0
#define RESOLV_DEFDOMAIN	1
#define RESOLV_NAMESERVER	2

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
	bool _recursive;

	/** \brief Print debug information */
	bool _debug;
	
	/** \brief Default domain to add */
	ldns_rdf *_domain; 

	/** \brief Searchlist array */
	ldns_rdf **_searchlist;
	size_t _searchlist_count;

	/** \brief How many retries */
	uint8_t _retry;
	/** \brief Wether to do DNSSEC */
	bool _dnssec;
	/** \brief Wether to use tcp */
	bool _usevc;
	/** \brief Wether to ignore the tc bit */
	bool _igntc;
	/** \brief Wether to use ip6, 0->ip4, 1->ip6 */
	bool _ip6;
	/** \brief if true append the default domain */
	bool _defnames;
	/** \brief if true apply the search list */
	bool _dnsrch;

	/** timeout for socket connections */
	struct timeval _timeout;

	/** keep some things for axfr */
	int _socket;
	int _axfr_soa_count;
	/* when axfring we get complete packets from the server
	   but we want to give the caller 1 rr at a time, so
	   keep the current pkt */
	ldns_pkt *_cur_axfr_pkt;
	uint16_t _axfr_i;
};
typedef struct ldns_struct_resolver ldns_resolver;

/* prototypes */
uint16_t ldns_resolver_port(ldns_resolver *);
/* ldns_rr_list * ldns_resolver_nameservers(ldns_resolver *) pop>? */
bool ldns_resolver_recursive(ldns_resolver *);
bool ldns_resolver_debug(ldns_resolver *);
bool ldns_resolver_usevc(ldns_resolver *);

size_t ldns_resolver_nameserver_count(ldns_resolver *);

ldns_rdf * ldns_resolver_domain(ldns_resolver *);
struct timeval ldns_resolver_timeout(ldns_resolver *);
ldns_rdf ** ldns_resolver_searchlist(ldns_resolver *);
ldns_rdf ** ldns_resolver_nameservers(ldns_resolver *);

void ldns_resolver_set_port(ldns_resolver *, uint16_t);
void ldns_resolver_set_recursive(ldns_resolver *, bool);
void ldns_resolver_set_debug(ldns_resolver *, bool);
void ldns_resolver_incr_nameserver_count(ldns_resolver *);
void ldns_resolver_set_nameserver_count(ldns_resolver *, size_t);

void ldns_resolver_set_domain(ldns_resolver *, ldns_rdf *);
void ldns_resolver_set_timeout(ldns_resolver *r, struct timeval timeout);
void ldns_resolver_push_searchlist(ldns_resolver *, ldns_rdf *);
ldns_status ldns_resolver_push_nameserver(ldns_resolver *, ldns_rdf *);

ldns_pkt * ldns_resolver_bgsend();
ldns_pkt * ldns_resolver_send(ldns_resolver *, ldns_rdf*, ldns_rr_type, ldns_rr_class, uint16_t);
ldns_pkt * ldns_resolver_query(ldns_resolver *, ldns_rdf*, ldns_rr_type, ldns_rr_class, uint16_t);
ldns_pkt * ldns_resolver_search(ldns_resolver *, ldns_rdf*, ldns_rr_type, ldns_rr_class, uint16_t);

ldns_resolver *ldns_resolver_new(void);
ldns_resolver *ldns_resolver_new_frm_file(const char *);
void ldns_resolver_free(ldns_resolver *);
void ldns_resolver_set_defnames(ldns_resolver *, bool);
void ldns_resolver_set_usevc(ldns_resolver *, bool);
void ldns_resolver_set_dnsrch(ldns_resolver *, bool);

/**
 * Prepares the resolver for an axfr query
 * The query is sent and the answers can be read with ldns_axfr_next
 */
ldns_status ldns_axfr_start(ldns_resolver *resolver, ldns_rdf *domain, ldns_rr_class class);
ldns_rr *ldns_axfr_next(ldns_resolver *resolver);

#endif  /* !_LDNS_RESOLVER_H */
