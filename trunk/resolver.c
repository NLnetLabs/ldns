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
#include <stdio.h>

#include <ldns/rdata.h>
#include <ldns/error.h>
#include <ldns/resolver.h>
#include <ldns/rdata.h>
#include <ldns/net.h>
#include <ldns/host2str.h>
#include <ldns/dns.h>
#include <ldns/dname.h>

#include <strings.h>

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

struct timeval
ldns_resolver_timeout(ldns_resolver *r)
{
	return r->_timeout;
} 

/* write */
void
ldns_resolver_set_port(ldns_resolver *r, uint16_t p)
{
	r->_port = p;
}

/**
 * pop the last nameserver from the resolver.
 * \param[in] r the resolver
 * \return the popped address or NULL if empty
 */
ldns_rdf *
ldns_resolver_pop_nameserver(ldns_resolver *r)
{
	ldns_rdf **nameservers;
	ldns_rdf *pop;

	if (ldns_resolver_nameserver_count(r) == 0) {
		return NULL;
	}
	
	nameservers = ldns_resolver_nameservers(r);
	
	pop = nameservers[ldns_resolver_nameserver_count(r)];

	/* delete the room of the last one */
	nameservers = XREALLOC(nameservers, ldns_rdf *, 
			(ldns_resolver_nameserver_count(r) - 1));

	ldns_resolver_dec_nameserver_count(r);
	return pop;
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

/**
 * push a new nameserver to the resolver. It must be an 
 * A or AAAA RR record type
 * \param[in] r the resolver
 * \param[in] r the rr 
 * \return ldns_status a status
 */
ldns_status
ldns_resolver_push_nameserver_rr(ldns_resolver *r, ldns_rr *rr)
{
	ldns_rdf *address;

	if (ldns_rr_get_type(rr) != LDNS_RR_TYPE_A &&
			ldns_rr_get_type(rr) != LDNS_RR_TYPE_AAAA) {
		return LDNS_STATUS_ERR;
	}
	address = ldns_rr_rdf(rr, 0); /* extract the ip number */
	return ldns_resolver_push_nameserver(r, address);
}

/**
 * push a new nameserver rr_list to the resolver.
 * \param[in] r the resolver
 * \param[in] rrlist the rr_list to push
 * \return ldns_status a status
 */
ldns_status
ldns_resolver_push_nameserver_rr_list(ldns_resolver *r, ldns_rr_list *rrlist)
{
	ldns_rr *rr;
	ldns_status stat;
	uint16_t i;

	stat = LDNS_STATUS_OK;
	for(i = 0; i < ldns_rr_list_rr_count(rrlist); i++) {
		rr = ldns_rr_list_rr(rrlist, i);
		if (ldns_resolver_push_nameserver_rr(r, rr) !=
				LDNS_STATUS_OK) {
			stat = LDNS_STATUS_ERR;
		}
	}
	return stat;
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
ldns_resolver_dec_nameserver_count(ldns_resolver *r)
{
	size_t c;

	c = ldns_resolver_nameserver_count(r);
	if (c == 0) {
		return;
	} else {
		ldns_resolver_set_nameserver_count(r, --c);
	}
}

void
ldns_resolver_set_domain(ldns_resolver *r, ldns_rdf *d)
{
	r->_domain = d;
}

void
ldns_resolver_set_timeout(ldns_resolver *r, struct timeval timeout)
{
	r->_timeout.tv_sec = timeout.tv_sec;
	r->_timeout.tv_usec = timeout.tv_usec;
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
	if (!r) {
		return NULL;
	}

	r->_searchlist = MALLOC(ldns_rdf *);
	r->_nameservers = MALLOC(ldns_rdf *);
	if (!r->_searchlist || !r->_nameservers) {
		return NULL;
	}

	/* defaults are filled out */
	ldns_resolver_set_searchlist_count(r, 0);
	ldns_resolver_set_nameserver_count(r, 0);
	ldns_resolver_set_usevc(r, 0);
	ldns_resolver_set_port(r, LDNS_PORT);
	ldns_resolver_set_domain(r, NULL);
	ldns_resolver_set_defnames(r, false);

	r->_timeout.tv_sec = LDNS_DEFAULT_TIMEOUT_SEC;
	r->_timeout.tv_usec = LDNS_DEFAULT_TIMEOUT_USEC;

	r->_socket = 0;
	r->_axfr_soa_count = 0;
	r->_axfr_i = 0;
	r->_cur_axfr_pkt = NULL;
	return r;
}


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
ldns_resolver *
ldns_resolver_new_frm_file(const char *filename)
{
	ldns_resolver *r;
	FILE *fp;
	const char *keyword[2];
	char *word;
	uint8_t expect;
	uint8_t i;
	ldns_rdf *tmp;

	/* do this better 
	 * expect = 
	 * 0: keyword
	 * 1: default domain dname
	 * 2: NS aaaa or a record
	 */

	/* recognized keywords */
	keyword[0] = "domain";
	keyword[1] = "nameserver";
	word = XMALLOC(char, MAXLINE_LEN);
	expect = 0;

	r = ldns_resolver_new();
	if (!r) {
		return NULL;
	}
	if (!filename) {
		fp = fopen(RESOLV_CONF, "r");

	} else {
		fp = fopen(filename, "r");
	}
	if (!fp) {
		return NULL;
	}
	/* the file is opened. it's line based - this will be a bit messy
	 */

	while (readword(word, fp, MAXLINE_LEN) != -1) {
		/* do something */
		switch(expect) {
			case RESOLV_KEYWORD:
				/* keyword */
				for(i = 0; i < 2; i++) {
					if (strcasecmp(keyword[i], word) == 0) {
						/* chosen the keyword and
						 * expect values carefully
						 */
						expect = i + 1;
						break;
					}
				}
				/* no keyword recognized */
				if (expect == 0) {
					/*	printf("[%s] unreg keyword\n", word); */
				}
				break;
			case RESOLV_DEFDOMAIN:
				/* default domain dname */
				tmp = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, word);
				if (!tmp) {
					expect = RESOLV_KEYWORD;
					break;
				}
				ldns_resolver_set_domain(r, tmp);
				expect = RESOLV_KEYWORD;
				break;
			case RESOLV_NAMESERVER:
				/* NS aaaa or a record */
				tmp = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_AAAA, word);
				if (!tmp) {
					/* try ip4 */
					tmp = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, word);
				}
				if (!tmp) {
					expect = RESOLV_KEYWORD;
					break;
				}
				(void)ldns_resolver_push_nameserver(r, tmp);
				expect = RESOLV_KEYWORD;
				break;
			default:
				/* huh?! */
				printf("BIG FAT WARNING should never reach this\n");
				expect = RESOLV_KEYWORD;
				break;
		}
	}

	fclose(fp);
	return r;
}


/**
 * Frees the allocated space for this resolver and all it's data
 *
 * \param res resolver to free
 */
void
ldns_resolver_free(ldns_resolver *res)
{
	FREE(res->_searchlist);
	FREE(res->_nameservers);
	FREE(res);
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
	ldns_pkt *pkt;
	
	if (!ldns_resolver_defnames(r)) {
		return ldns_resolver_send(r, name, type, class, flags);
	}
	if (!ldns_resolver_domain(r)) {
		/* _defnames is set, but the domain is not....?? */
		return ldns_resolver_send(r, name, type, class, flags);
	}

	newname = ldns_dname_cat(name, ldns_resolver_domain(r));

	if (!newname) {
		return NULL;
	}
	pkt = ldns_resolver_send(r, newname, type, class, flags);
	ldns_rdf_free(newname);
	return pkt;
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

	if (0 == type) {
		type = LDNS_RR_TYPE_A;
	}
	if (0 == class) {
		class = LDNS_RR_CLASS_IN;
	}
	if (0 == ldns_resolver_nameserver_count(r)) {
		printf("resolver is not configued\n");
		return NULL;
	}
	if (ldns_rdf_get_type(name) != LDNS_RDF_TYPE_DNAME) {
		printf("query type is not correct type\n");
		return NULL;
	}
	/* prepare a question pkt from the parameters
	 * and then send this */
	query_pkt = ldns_pkt_query_new(ldns_rdf_deep_clone(name), type, class, flags);
	if (!query_pkt) {
		printf("Failed to generate pkt\n");
		return NULL;
	}

	/* return NULL on error */
	answer_pkt = ldns_send(r, query_pkt);
	
	ldns_pkt_free(query_pkt);
		
	return answer_pkt;
}

/* send the query as-is. but use a callback */
ldns_pkt *
ldns_resolver_bgsend()
{
	return NULL;
}

/*
 * Start an axfr, send the query and keep the connection open
 */
ldns_status
ldns_axfr_start(ldns_resolver *resolver, 
                ldns_rdf *domain,
                ldns_rr_class class)
{
        ldns_pkt *query;
        ldns_buffer *query_wire;

        struct sockaddr_storage *ns;
        struct sockaddr_in *ns4;
        struct sockaddr_in6 *ns6;
        socklen_t ns_len = 0;
        ldns_status status;

        if (!resolver || ldns_resolver_nameserver_count(resolver) < 1) {
        	return LDNS_STATUS_ERR;
	}
	
        /* Create the query */
	query = ldns_pkt_query_new(ldns_rdf_deep_clone(domain),
	                           LDNS_RR_TYPE_AXFR,
	                           class,
	                           0);
	                                    

	if (!query) {
		return LDNS_STATUS_ADDRESS_ERROR;
	}
	/* For AXFR, we have to make the connection ourselves */
	ns = ldns_rdf2native_sockaddr_storage(resolver->_nameservers[0]);

	/* Determine the address size.
	 */
	switch(ns->ss_family) {
		case AF_INET:
			ns4 = (struct sockaddr_in*) ns;
			ns4->sin_port = htons(
					ldns_resolver_port(resolver));
			ns_len = (socklen_t)sizeof(struct sockaddr_in);
			break;
		case AF_INET6:
			ns6 = (struct sockaddr_in6*) ns;
			ns6->sin6_port = htons(
					ldns_resolver_port(resolver));
			ns_len = (socklen_t)sizeof(struct sockaddr_in6);
			break;
                default:
                	printf("unkown inet family\n");
                	return -1;
	}

	resolver->_socket = ldns_tcp_connect(ns, ns_len, ldns_resolver_timeout(resolver));
	if (resolver->_socket == 0) {
               	ldns_pkt_free(query);
		return LDNS_STATUS_NETWORK_ERROR;
	}
	
	/* Convert the query to a buffer
	 * Is this necessary?
	 */
	query_wire = ldns_buffer_new(MAX_PACKETLEN);
	status = ldns_pkt2buffer_wire(query_wire, query);
	if (status != LDNS_STATUS_OK) {
               	ldns_pkt_free(query);
		return status;
	}

	/* Send the query */
	if (ldns_tcp_send_query(query_wire, resolver->_socket, ns, ns_len) == 0) {
		ldns_pkt_free(query);
		ldns_buffer_free(query_wire);
		return LDNS_STATUS_NETWORK_ERROR;
	}
	
	ldns_pkt_free(query);
	ldns_buffer_free(query_wire);

	/*
	 * The AXFR is done once the second SOA record is sent
	 */
	resolver->_axfr_soa_count = 0;
	
	return LDNS_STATUS_OK;
}

ldns_rr *
ldns_axfr_next(ldns_resolver *resolver)
{
	ldns_rr *cur_rr;
	
	/* check if start() has been called */
	if (!resolver || resolver->_socket == 0) {
		return NULL;
	}
	
	if (resolver->_cur_axfr_pkt) {
		if (resolver->_axfr_i == ldns_pkt_ancount(resolver->_cur_axfr_pkt)) {
			ldns_pkt_free(resolver->_cur_axfr_pkt);
			resolver->_cur_axfr_pkt = NULL;
			return ldns_axfr_next(resolver);
		}
		cur_rr = ldns_rr_deep_clone(ldns_rr_list_rr(ldns_pkt_answer(resolver->_cur_axfr_pkt), resolver->_axfr_i));
		resolver->_axfr_i++;
		if (ldns_rr_get_type(cur_rr) == LDNS_RR_TYPE_SOA) {
			resolver->_axfr_soa_count++;
			if (resolver->_axfr_soa_count >= 2) {
				close(resolver->_socket);
				resolver->_socket = 0;
				ldns_pkt_free(resolver->_cur_axfr_pkt);
			}
		}
		return cur_rr;
	} else {
		resolver->_cur_axfr_pkt = ldns_tcp_read_packet(resolver->_socket);

		resolver->_axfr_i = 0;
		return ldns_axfr_next(resolver);
		
		if (!resolver->_cur_axfr_pkt)  {
			fprintf(stderr, "[ldns_axfr_next] error reading packet\n");
			return NULL;
		}
		
		if (ldns_pkt_rcode(resolver->_cur_axfr_pkt) != 0) {
			fprintf(stderr, "Got error code\n");
			close(resolver->_socket);
			resolver->_socket = 0;
			ldns_pkt_free(resolver->_cur_axfr_pkt);
			resolver->_cur_axfr_pkt = NULL;
			return NULL;
		}
		
	}
	
}

#if 0
/* print a resolver state to fp */
void
ldns_resolver_print(FILE *fp, ldns_resolver *res)
{
}
#endif
