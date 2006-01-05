/*
 * resolver.h
 *
 * DNS Resolver definitions
 *
 * a Net::DNS like library for C
 *
 * (c) NLnet Labs, 2005-2006
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
#define LDNS_RESOLV_CONF	"/etc/resolv.conf"
#define LDNS_RESOLV_HOSTS	"/etc/hosts"

#define LDNS_RESOLV_KEYWORD     -1	
#define LDNS_RESOLV_DEFDOMAIN	0
#define LDNS_RESOLV_NAMESERVER	1
#define LDNS_RESOLV_SEARCH	2

#define LDNS_RESOLV_KEYWORDS    3

#define LDNS_RESOLV_INETANY		0
#define LDNS_RESOLV_INET		1
#define LDNS_RESOLV_INET6		2

#define LDNS_RESOLV_RTT_INF             0       /* infinity */
#define LDNS_RESOLV_RTT_MIN             1       /* reacheable */

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

        /** \brief round trip time; 0 -> infinity. Unit: ms? */
        size_t *_rtt;

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
	/** \brief Wether to set the CD bit on DNSSEC requests */
	bool _dnssec_cd;
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
	/** \brief randomly choose a nameserver */
	bool _random;
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

/**
 * Get the port the resolver should use
 * \param[in] r the resolver
 * \return the port number 
 */
uint16_t ldns_resolver_port(ldns_resolver *r);

/**
 * Is the resolver set to recurse
 * \param[in] r the resolver
 * \return true if so, otherwise false
 */
bool ldns_resolver_recursive(ldns_resolver *r);

/**
 * Get the debug status of the resolver
 * \param[in] r the resolver
 * \return true if so, otherwise false
 */
bool ldns_resolver_debug(ldns_resolver *r);

/**
 * Get the number of retries
 * \param[in] r the resolver
 * \return the number of retries
 */
uint8_t ldns_resolver_retry(ldns_resolver *r);

/**
 * Get the retransmit interval
 * \param[in] r the resolver
 * \return the retransmit interval
 */
uint8_t ldns_resolver_retrans(ldns_resolver *r);

/**
 * Does the resolver use ip6 or ip4
 * \param[in] r the resolver
 * \return 0: both, 1: ip4, 2:ip6
 */
uint8_t ldns_resolver_ip6(ldns_resolver *r);

/**
 * Get the resolver's udp size
 * \param[in] r the resolver
 * \return the udp mesg size
 */
uint16_t ldns_resolver_edns_udp_size(ldns_resolver *r);
/**
 * Does the resolver use tcp or udp
 * \param[in] r the resolver
 * \return true: tcp, false: udp
 */
bool ldns_resolver_usevc(ldns_resolver *r);
/**
 * Does the resolver only try the first nameserver
 * \param[in] r the resolver
 * \return true: yes, fail, false: no, try the others
 */
bool ldns_resolver_fail(ldns_resolver *r);
/**
 * Does the resolver do DNSSEC
 * \param[in] r the resolver
 * \return true: yes, false: no
 */
bool ldns_resolver_dnssec(ldns_resolver *r);
/**
 * Does the resolver set the CD bit 
 * \param[in] r the resolver
 * \return true: yes, false: no
 */
bool ldns_resolver_dnssec_cd(ldns_resolver *r);
/**
 * Does the resolver ignore the TC bit (truncated)
 * \param[in] r the resolver
 * \return true: yes, false: no
 */
bool ldns_resolver_igntc(ldns_resolver *r);
/**
 * Does the resolver randomize the nameserver before usage
 * \param[in] r the resolver
 * \return true: yes, false: no
 */
bool ldns_resolver_random(ldns_resolver *r);
/**
 * How many nameserver are configured in the resolver
 * \param[in] r the resolver
 * \return number of nameservers
 */
size_t ldns_resolver_nameserver_count(ldns_resolver *r);
/**
 * What is the default dname to add to relative queries
 * \param[in] r the resolver
 * \return the dname which is added
 */
ldns_rdf *ldns_resolver_domain(ldns_resolver *r);
/**
 * What is the timeout on socket connections
 * \param[in] r the resolver
 * \return the timeout as struct timeval
 */
struct timeval ldns_resolver_timeout(ldns_resolver *r);
/**
 * What is the searchlist as used by the resolver
 * \param[in] r the resolver
 * \return a ldns_rdf pointer to a list of the addresses
 */
ldns_rdf** ldns_resolver_searchlist(ldns_resolver *r);
/**
 * Return the configured nameserver ip address
 * \param[in] r the resolver
 * \return a ldns_rdf pointer to a list of the addresses
 */
ldns_rdf** ldns_resolver_nameservers(ldns_resolver *r);
/**
 * Return the used round trip times for the nameservers
 * \param[in] r the resolver
 * \return a size_t* pointer to the list.
 * yet)
 */
size_t * ldns_resolver_rtt(ldns_resolver *r);
/**
 * Return the used round trip time for a specific nameserver
 * \param[in] r the resolver
 * \param[in] pos the index to the nameserver
 * \return the rrt, 0: infinite, >0: undefined (as of * yet)
 */
size_t ldns_resolver_nameserver_rtt(ldns_resolver *r, size_t pos);
/**
 * Return the tsig keyname as used by the nameserver
 * \param[in] r the resolver
 * \return the name used.
 */
char *ldns_resolver_tsig_keyname(ldns_resolver *r);
/**
 * Return the tsig algorithm as used by the nameserver
 * \param[in] r the resolver
 * \return the algorithm used.
 */
char *ldns_resolver_tsig_algorithm(ldns_resolver *r);
/**
 * Return the tsig keydata as used by the nameserver
 * \param[in] r the resolver
 * \return the keydata used.
 */
char *ldns_resolver_tsig_keydata(ldns_resolver *r);
/**
 * pop the last nameserver from the resolver.
 * \param[in] r the resolver
 * \return the popped address or NULL if empty
 */
ldns_rdf* ldns_resolver_pop_nameserver(ldns_resolver *r);

/* write access function */
/**
 * Set the port the resolver should use
 * \param[in] r the resolver
 * \param[in] p the port number
 */
void ldns_resolver_set_port(ldns_resolver *r, uint16_t p);

/**
 * Set the resolver recursion
 * \param[in] r the resolver
 * \param[in] b true: set to recurse, false: unset
 */
void ldns_resolver_set_recursive(ldns_resolver *r, bool b);

void ldns_resolver_set_debug(ldns_resolver *r, bool b);
void ldns_resolver_incr_nameserver_count(ldns_resolver *r);
void ldns_resolver_dec_nameserver_count(ldns_resolver *r);
void ldns_resolver_set_nameserver_rrlist(ldns_resolver *r, ldns_rr_list *ns);
void ldns_resolver_set_nameserver_count(ldns_resolver *r, size_t c);
void ldns_resolver_set_nameservers(ldns_resolver *r, ldns_rdf **rd);
void ldns_resolver_set_domain(ldns_resolver *r, ldns_rdf *rd);
void ldns_resolver_set_timeout(ldns_resolver *r, struct timeval timeout);
void ldns_resolver_push_searchlist(ldns_resolver *r, ldns_rdf *rd);
void ldns_resolver_set_defnames(ldns_resolver *r, bool b);
void ldns_resolver_set_usevc(ldns_resolver *r, bool b);
void ldns_resolver_set_dnsrch(ldns_resolver *r, bool b);
void ldns_resolver_set_dnssec(ldns_resolver *r, bool b);
void ldns_resolver_set_dnssec_cd(ldns_resolver *r, bool b);
void ldns_resolver_set_retrans(ldns_resolver *r, uint8_t re);
void ldns_resolver_set_retry(ldns_resolver *r, uint8_t re);
void ldns_resolver_set_ip6(ldns_resolver *r, uint8_t i);
void ldns_resolver_set_fail(ldns_resolver *r, bool b);
void ldns_resolver_set_igntc(ldns_resolver *r, bool b);
void ldns_resolver_set_edns_udp_size(ldns_resolver *r, uint16_t s);
void ldns_resolver_set_tsig_keyname(ldns_resolver *r, char *tsig_keyname);
void ldns_resolver_set_tsig_algorithm(ldns_resolver *r, char *tsig_algorithm);
void ldns_resolver_set_tsig_keydata(ldns_resolver *r, char *tsig_keydata);
void ldns_resolver_set_rtt(ldns_resolver *r, size_t *rtt);
void ldns_resolver_set_nameserver_rtt(ldns_resolver *r, size_t pos, size_t value);
void ldns_resolver_set_random(ldns_resolver *r, bool b);

/**
 * push a new nameserver to the resolver. It must be an IP
 * address v4 or v6.
 * \param[in] r the resolver
 * \param[in] n the ip address
 * \return ldns_status a status
 */
ldns_status ldns_resolver_push_nameserver(ldns_resolver *r, ldns_rdf *n);

/**
 * push a new nameserver to the resolver. It must be an 
 * A or AAAA RR record type
 * \param[in] r the resolver
 * \param[in] rr the resource record 
 * \return ldns_status a status
 */
ldns_status ldns_resolver_push_nameserver_rr(ldns_resolver *r, ldns_rr *rr);

/**
 * push a new nameserver rr_list to the resolver.
 * \param[in] r the resolver
 * \param[in] rrlist the rr_list to push
 * \return ldns_status a status
 */
ldns_status ldns_resolver_push_nameserver_rr_list(ldns_resolver *r, ldns_rr_list *rrlist);

/**
 * send the query as-is. but return a socket 
 * \todo TODO
 */
int ldns_resolver_bgsend();

/**
 * Send the query for using the resolver and take the search list into * account
 * \param[in] *r operate using this resolver
 * \param[in] *rdf query for this name
 * \param[in] t query for this type (may be 0, defaults to A)
 * \param[in] c query for this class (may be 0, default to IN)
 * \param[in] flags the query flags
 * \return ldns_pkt* a packet with the reply from the nameserver
 */
ldns_pkt* ldns_resolver_search(ldns_resolver *r, ldns_rdf *rdf, ldns_rr_type t, ldns_rr_class c, uint16_t flags);

/**
 * \brief Send the query for *name as-is 
 * \param[out] **answer a pointer to a ldns_pkt pointer (initialized by this function)
 * \param[in] *r operate using this resolver
 * \param[in] *name query for this name
 * \param[in] t query for this type (may be 0, defaults to A)
 * \param[in] c query for this class (may be 0, default to IN)
 * \param[in] flags the query flags
 * \return ldns_pkt* a packet with the reply from the nameserver
 */
ldns_status ldns_resolver_send(ldns_pkt **answer, ldns_resolver *r, ldns_rdf *name, ldns_rr_type t, ldns_rr_class c, uint16_t flags);

/**
 * \brief Send the given packet to a nameserver
 * \param[out] **answer a pointer to a ldns_pkt pointer (initialized by this function)
 * \param[in] *r operate using this resolver
 * \param[in] *query_pkt query
 */
ldns_status ldns_resolver_send_pkt(ldns_pkt **answer, ldns_resolver *r, ldns_pkt *query_pkt);

/**
 * Send a query to a nameserver
 * \param[in] *r operate using this resolver
 * \param[in] *name query for this name
 * \param[in] *type query for this type (may be 0, defaults to A)
 * \param[in] *class query for this class (may be 0, default to IN)
 * \param[in] flags the query flags
 * \return ldns_pkt* a packet with the reply from the nameserver
 * if _defnames is true the default domain will be added
 */
ldns_pkt* ldns_resolver_query(ldns_resolver *r, ldns_rdf *name, ldns_rr_type type, ldns_rr_class class, uint16_t flags);


/** 
 * \brief create a new resolver structure 
 * \return ldns_resolver* pointer to new strcture
 */
ldns_resolver* ldns_resolver_new(void);

/**
 * Create a resolver structure from a file like /etc/resolv.conf
 * \param[in] fp file pointer to create new resolver from
 *      if NULL use /etc/resolv.conf
 * \return ldns_resolver structure
 */
ldns_resolver* ldns_resolver_new_frm_fp(FILE *fp);

/**
 * Create a resolver structure from a file like /etc/resolv.conf
 * \param[in] fp file pointer to create new resolver from
 *      if NULL use /etc/resolv.conf
 * \param[in] line_nr pointer to an integer containing the current line number (for debugging purposes)
 * \return ldns_resolver structure
 */
ldns_resolver* ldns_resolver_new_frm_fp_l(FILE *fp, int *line_nr);

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
ldns_resolver* ldns_resolver_new_frm_file(const char *filename);

/**                             
 * Frees the allocated space for this resolver
 * \param res resolver to free  
 */     
void ldns_resolver_free(ldns_resolver *res);

/**                             
 * Frees the allocated space for this resolver and all it's data
 * \param res resolver to free  
 */     
void ldns_resolver_deep_free(ldns_resolver *res);

/**
 *  get the next stream of RRs in a AXFR 
 * \param[in] resolver the resolver to use. First ldns_axfr_start() must be
 * called
 * \return ldns_rr the next RR from the AXFR stream
 */
ldns_rr* ldns_axfr_next(ldns_resolver *resolver);

/**
 * returns true if the axfr transfer has completed (i.e. 2 SOA RRs and no errors were encountered 
 * \param[in] resolver the resolver that is used
 * \return bool true if axfr transfer was completed without error
 */
bool ldns_axfr_complete(ldns_resolver *resolver);

/**
 * returns a pointer to the last ldns_pkt that was sent by the server in the AXFR transfer
 * uasable for instance to get the error code on failure
 * \param[in] res the resolver that was used in the axfr transfer
 * \return ldns_pkt the last packet sent
 */
ldns_pkt *ldns_axfr_last_pkt(ldns_resolver *res);

/**
 * randomize the nameserver list in the resolver
 * \param[in] r the resolver
 */
void ldns_resolver_nameservers_randomize(ldns_resolver *r);

#endif  /* !_LDNS_RESOLVER_H */
