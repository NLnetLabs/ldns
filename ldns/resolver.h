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
#define RESOLV_HOSTS	"/etc/hosts"

#define RESOLV_KEYWORD		0
#define RESOLV_DEFDOMAIN	1
#define RESOLV_NAMESERVER	2

#define LDNS_RESOLV_INETANY		0
#define LDNS_RESOLV_INET		1
#define LDNS_RESOLV_INET6		2

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

	/** \brief How many retries to try, before giving up */
	uint8_t _retry;
	/** \brief Re-trans interval */
	uint8_t _retrans;
	/** \brief Wether to do DNSSEC */
	bool _dnssec;
	/** \brief Wether to use tcp */
	bool _usevc;
	/** \brief Wether to ignore the tc bit */
	bool _igntc;
	/** \brief Wether to use ip6, 0->does not matter, 1 ipv4, 2->ip6 */
	uint8_t _ip6;
	/** \brief if true append the default domain */
	bool _defnames;
	/** \brief if true apply the search list */
	bool _dnsrch;
	/** timeout for socket connections */
	struct timeval _timeout;
	/** \brief only try the first nameserver */
	bool _fail;
	/** keep some things for axfr */
	int _socket;
	int _axfr_soa_count;
	/* when axfring we get complete packets from the server
	   but we want to give the caller 1 rr at a time, so
	   keep the current pkt */
	ldns_pkt *_cur_axfr_pkt;
	uint16_t _axfr_i;
	/* EDNS0 stuff only bufsize atm */
	uint16_t _edns_udp_size;
	
	/* Optional tsig key for signing queries,
	outgoing messages are signed if and only if both are set
	*/
	char *_tsig_keyname;
	char *_tsig_keydata;
	char *_tsig_algorithm;
};
typedef struct ldns_struct_resolver ldns_resolver;

/* prototypes */
/* read access functions */
uint16_t ldns_resolver_port(ldns_resolver *);
uint8_t ldns_resolver_retry(ldns_resolver *);
uint8_t ldns_resolver_retrans(ldns_resolver *);
uint8_t ldns_resolver_ip6(ldns_resolver *);
uint16_t ldns_resolver_edns_udp_size(ldns_resolver *);
bool ldns_resolver_recursive(ldns_resolver *);
bool ldns_resolver_debug(ldns_resolver *);
bool ldns_resolver_usevc(ldns_resolver *);
bool ldns_resolver_fail(ldns_resolver *);
bool ldns_resolver_dnssec(ldns_resolver *);
bool ldns_resolver_igntc(ldns_resolver *r);
size_t ldns_resolver_nameserver_count(ldns_resolver *);
ldns_rdf * ldns_resolver_domain(ldns_resolver *);
struct timeval ldns_resolver_timeout(ldns_resolver *);
ldns_rdf ** ldns_resolver_searchlist(ldns_resolver *);
ldns_rdf ** ldns_resolver_nameservers(ldns_resolver *);
char *ldns_resolver_tsig_keyname(ldns_resolver *r);
char *ldns_resolver_tsig_algorithm(ldns_resolver *r);
char *ldns_resolver_tsig_keydata(ldns_resolver *r);
/**
 * pop the last nameserver from the resolver.
 * \param[in] r the resolver
 * \return the popped address or NULL if empty
 */
ldns_rdf * ldns_resolver_pop_nameserver(ldns_resolver *);

/* write access function */
void ldns_resolver_set_port(ldns_resolver *, uint16_t);
void ldns_resolver_set_recursive(ldns_resolver *, bool);
void ldns_resolver_set_debug(ldns_resolver *, bool);
void ldns_resolver_incr_nameserver_count(ldns_resolver *);
void ldns_resolver_dec_nameserver_count(ldns_resolver *);
void ldns_resolver_set_nameserver_count(ldns_resolver *, size_t);
void ldns_resolver_set_nameservers(ldns_resolver *, ldns_rdf **);
void ldns_resolver_set_domain(ldns_resolver *, ldns_rdf *);
void ldns_resolver_set_timeout(ldns_resolver *r, struct timeval timeout);
void ldns_resolver_push_searchlist(ldns_resolver *, ldns_rdf *);
void ldns_resolver_set_defnames(ldns_resolver *, bool);
void ldns_resolver_set_usevc(ldns_resolver *, bool);
void ldns_resolver_set_dnsrch(ldns_resolver *, bool);
void ldns_resolver_set_dnssec(ldns_resolver *, bool);
void ldns_resolver_set_retrans(ldns_resolver *, uint8_t);
void ldns_resolver_set_retry(ldns_resolver *, uint8_t);
void ldns_resolver_set_ip6(ldns_resolver *, uint8_t);
void ldns_resolver_set_fail(ldns_resolver *, bool);
void ldns_resolver_set_igntc(ldns_resolver *, bool);
void ldns_resolver_set_edns_udp_size(ldns_resolver *, uint16_t);
void ldns_resolver_set_tsig_keyname(ldns_resolver *r, char *tsig_keyname);
void ldns_resolver_set_tsig_algorithm(ldns_resolver *r, char *tsig_algorithm);
void ldns_resolver_set_tsig_keydata(ldns_resolver *r, char *tsig_keydata);


/**
 * push a new nameserver to the resolver. It must be an IP
 * address v4 or v6.
 * \param[in] r the resolver
 * \param[in] n the ip address
 * \return ldns_status a status
 */
ldns_status ldns_resolver_push_nameserver(ldns_resolver *, ldns_rdf *);

/**
 * push a new nameserver to the resolver. It must be an 
 * A or AAAA RR record type
 * \param[in] r the resolver
 * \param[in] rr the resource record 
 * \return ldns_status a status
 */
ldns_status ldns_resolver_push_nameserver_rr(ldns_resolver *, ldns_rr *);

/**
 * push a new nameserver rr_list to the resolver.
 * \param[in] r the resolver
 * \param[in] rrlist the rr_list to push
 * \return ldns_status a status
 */
ldns_status ldns_resolver_push_nameserver_rr_list(ldns_resolver *, ldns_rr_list *);

/**
 * send the query as-is. but return a socket 
 * \todo TODO
 */
int ldns_resolver_bgsend();

/* no comment found */
ldns_pkt * ldns_resolver_search(ldns_resolver *, ldns_rdf*, ldns_rr_type, ldns_rr_class, uint16_t);

/**
 * \brief Send the query for *name as-is 
 * \param[out] **answer, a pointer to a ldns_pkt pointer (initialized by this function)
 * \param[in] *r operate using this resolver
 * \param[in] *name query for this name
 * \param[in] *type query for this type (may be 0, defaults to A)
 * \param[in] *class query for this class (may be 0, default to IN)
 * \param[in] flags the query flags
 * \return ldns_pkt* a packet with the reply from the nameserver
 */
ldns_status ldns_resolver_send(ldns_pkt **answer, ldns_resolver *, ldns_rdf*, ldns_rr_type, ldns_rr_class, uint16_t);

/**
 * \brief Send the given packet to a nameserver
 * \param[out] **answer, a pointer to a ldns_pkt pointer (initialized by this function)
 * \param[in] *r operate using this resolver
 * \param[in] *query_pkt query
 */
ldns_status ldns_resolver_send_pkt(ldns_pkt **answer, ldns_resolver *, ldns_pkt *query_pkt);

/**
 * Send a qeury to a nameserver
 * \param[in] *r operate using this resolver
 * \param[in] *name query for this name
 * \param[in] *type query for this type (may be 0, defaults to A)
 * \param[in] *class query for this class (may be 0, default to IN)
 * \param[in] flags the query flags
 * \return ldns_pkt* a packet with the reply from the nameserver
 * if _defnames is true the default domain will be added
 */
ldns_pkt * ldns_resolver_query(ldns_resolver *, ldns_rdf*, ldns_rr_type, ldns_rr_class, uint16_t);


/** 
 * \brief create a new resolver structure 
 * \return ldns_resolver* pointer to new strcture
 */
ldns_resolver *ldns_resolver_new(void);

/**
 * Create a resolver structure from a file like /etc/resolv.conf
 * \param[in] fp file pointer to create new resolver from
 *      if NULL use /etc/resolv.conf
 * \return ldns_resolver structure
 */
ldns_resolver * ldns_resolver_new_frm_fp(FILE *fp);

/**
 * configure a resolver by means of a resolv.conf file 
 * The file may be NULL in which case there will  be
 * looked the RESOLV_CONF (defaults to /etc/resolv.conf
 * \param[in] filename the filename to use
 * \return ldns_resolver pointer
 */                             
/* keyword recognized:                          
 * nameserver                   
 * domain                       
 */                     
ldns_resolver *ldns_resolver_new_frm_file(const char *);

/**                             
 * Frees the allocated space for this resolver and all it's data
 * \param res resolver to free  
 */     
void ldns_resolver_free(ldns_resolver *);

/**
 * Prepares the resolver for an axfr query
 * The query is sent and the answers can be read with ldns_axfr_next
 */
ldns_status ldns_axfr_start(ldns_resolver *resolver, ldns_rdf *domain, ldns_rr_class class);

/**
 *  get the next stream of RRs in a AXFR 
 */
ldns_rr *ldns_axfr_next(ldns_resolver *resolver);

#endif  /* !_LDNS_RESOLVER_H */
