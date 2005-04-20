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

#include <ldns/ldns.h>

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

uint16_t
ldns_resolver_edns_udp_size(ldns_resolver *r)
{
	        return r->_edns_udp_size;
}

uint8_t
ldns_resolver_retry(ldns_resolver *r)
{
	return r->_retry;
}

uint8_t
ldns_resolver_retrans(ldns_resolver *r)
{
	return r->_retrans;
}

uint8_t
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
ldns_resolver_fail(ldns_resolver *r)
{
	return r->_fail;
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

char *
ldns_resolver_tsig_keyname(ldns_resolver *r)
{
	return r->_tsig_keyname;
}

char *
ldns_resolver_tsig_algorithm(ldns_resolver *r)
{
	return r->_tsig_algorithm;
}

char *
ldns_resolver_tsig_keydata(ldns_resolver *r)
{
	return r->_tsig_keydata;
}

/* write */
void
ldns_resolver_set_port(ldns_resolver *r, uint16_t p)
{
	r->_port = p;
}

ldns_rdf *
ldns_resolver_pop_nameserver(ldns_resolver *r)
{
	ldns_rdf **nameservers;
	ldns_rdf *pop;
	size_t ns_count;

	ns_count = ldns_resolver_nameserver_count(r);
	if (ns_count == 0) {
		return NULL;
	}
	
	nameservers = ldns_resolver_nameservers(r);
	if (!nameservers) {
		return NULL;
	}
	
	pop = nameservers[ns_count - 1];

	nameservers = XREALLOC(nameservers, ldns_rdf *, 
			(ns_count - 1));

	ldns_resolver_set_nameservers(r, nameservers);
	/* decr the count */
	ldns_resolver_dec_nameserver_count(r);
	return pop;
}

ldns_status
ldns_resolver_push_nameserver(ldns_resolver *r, ldns_rdf *n)
{
	ldns_rdf **nameservers;
	uint16_t ns_count;

	if (ldns_rdf_get_type(n) != LDNS_RDF_TYPE_A &&
			ldns_rdf_get_type(n) != LDNS_RDF_TYPE_AAAA) {
		return LDNS_STATUS_ERR;
	}

	ns_count = ldns_resolver_nameserver_count(r);
	nameservers = ldns_resolver_nameservers(r);

	/* make room for the next one */
	nameservers = XREALLOC(nameservers, ldns_rdf *, (ns_count + 1));

	/* set the new value in the resolver */
	ldns_resolver_set_nameservers(r, nameservers);

	/* slide n in its slot */
	nameservers[ns_count] = n;
	ldns_resolver_incr_nameserver_count(r);
	return LDNS_STATUS_OK;
}

ldns_status
ldns_resolver_push_nameserver_rr(ldns_resolver *r, ldns_rr *rr)
{
	ldns_rdf *address;
	if ((!rr) || (ldns_rr_get_type(rr) != LDNS_RR_TYPE_A &&
			ldns_rr_get_type(rr) != LDNS_RR_TYPE_AAAA)) {
		return LDNS_STATUS_ERR;
	}
	address = ldns_rr_rdf(rr, 0); /* extract the ip number */
	return ldns_resolver_push_nameserver(r, address);
}

ldns_status
ldns_resolver_push_nameserver_rr_list(ldns_resolver *r, ldns_rr_list *rrlist)
{
	ldns_rr *rr;
	ldns_status stat;
	size_t i;

	stat = LDNS_STATUS_OK;
	if (rrlist) {
		for(i = 0; i < ldns_rr_list_rr_count(rrlist); i++) {
			rr = ldns_rr_list_rr(rrlist, i);
			if (ldns_resolver_push_nameserver_rr(r, rr) !=
					LDNS_STATUS_OK) {
				stat = LDNS_STATUS_ERR;
			}
		}
		return stat;
	} else {
		return LDNS_STATUS_ERR;
	}
}

void
ldns_resolver_set_edns_udp_size(ldns_resolver *r, uint16_t s)
{
	        r->_edns_udp_size = s;
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
ldns_resolver_set_ip6(ldns_resolver *r, uint8_t ip6)
{
	r->_ip6 = ip6;
}

void
ldns_resolver_set_fail(ldns_resolver *r, bool f)
{
	r->_fail =f;
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
ldns_resolver_set_retry(ldns_resolver *r, uint8_t retry)
{
	r->_retry = retry;
}

void
ldns_resolver_set_retrans(ldns_resolver *r, uint8_t retrans)
{
	r->_retrans = retrans;
}

void
ldns_resolver_set_nameservers(ldns_resolver *r, ldns_rdf **n)
{
	r->_nameservers = n;
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

void
ldns_resolver_set_tsig_keyname(ldns_resolver *r, char *tsig_keyname)
{
	r->_tsig_keyname = tsig_keyname;
}

void
ldns_resolver_set_tsig_algorithm(ldns_resolver *r, char *tsig_algorithm)
{
	r->_tsig_algorithm = tsig_algorithm;
}

void
ldns_resolver_set_tsig_keydata(ldns_resolver *r, char *tsig_keydata)
{
	r->_tsig_keydata = tsig_keydata;
}

/* more sophisticated functions */
ldns_resolver *
ldns_resolver_new(void)
{
	ldns_resolver *r;

	r = MALLOC(ldns_resolver);
	if (!r) {
		return NULL;
	}

	r->_searchlist = NULL;
	r->_nameservers = NULL;

	/* defaults are filled out */
	ldns_resolver_set_searchlist_count(r, 0);
	ldns_resolver_set_nameserver_count(r, 0);
	ldns_resolver_set_usevc(r, 0);
	ldns_resolver_set_port(r, LDNS_PORT);
	ldns_resolver_set_domain(r, NULL);
	ldns_resolver_set_defnames(r, false);
	ldns_resolver_set_retry(r, 4);
	ldns_resolver_set_retrans(r, 5);
	ldns_resolver_set_fail(r, false);
	ldns_resolver_set_edns_udp_size(r, 0);

	r->_timeout.tv_sec = LDNS_DEFAULT_TIMEOUT_SEC;
	r->_timeout.tv_usec = LDNS_DEFAULT_TIMEOUT_USEC;

	r->_socket = 0;
	r->_axfr_soa_count = 0;
	r->_axfr_i = 0;
	r->_cur_axfr_pkt = NULL;
	
	r->_tsig_keyname = NULL;
	r->_tsig_keydata = NULL;
	r->_tsig_algorithm = NULL;
	return r;
}

ldns_resolver *
ldns_resolver_new_frm_fp(FILE *fp)
{
	ldns_resolver *r;
	const char *keyword[2];
	char *word;
	uint8_t expect;
	uint8_t i;
	ldns_rdf *tmp;
	ssize_t gtr;

	/* do this better 
	 * expect = 
	 * 0: keyword
	 * 1: default domain dname
	 * 2: NS aaaa or a record
	 */

	/* recognized keywords */
	keyword[0] = "domain";
	keyword[1] = "nameserver";
	word = XMALLOC(char, MAXLINE_LEN + 1);
	expect = RESOLV_KEYWORD;

	r = ldns_resolver_new();
	if (!r) {
		return NULL;
	}
	gtr = ldns_fget_token(fp, word, LDNS_PARSE_NORMAL, 0);
	while (gtr > 0) {
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
						dprintf("[%s] unreg keyword\n", word); 
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
				dprintf("%s", "BIG FAT WARNING should never reach this\n");
				expect = RESOLV_KEYWORD;
				break;
		}
		gtr = ldns_fget_token(fp, word, LDNS_PARSE_NORMAL, 0);
	}
	
	FREE(word);
	return r;
}

ldns_resolver *
ldns_resolver_new_frm_file(const char *filename)
{
	ldns_resolver *r;
	FILE *fp;

	if (!filename) {
		fp = fopen(RESOLV_CONF, "r");

	} else {
		fp = fopen(filename, "r");
	}
	if (!fp) {
		return NULL;
	}
	/* the file is opened. it's line based - this will be a bit messy */

	r =  ldns_resolver_new_frm_fp(fp);

	fclose(fp);
	return r;
}

void
ldns_resolver_free(ldns_resolver *res)
{
	size_t i;
	
	if (res) {
		if (res->_searchlist) {
			for (i = 0; i < res->_searchlist_count; i++) {
				ldns_rdf_free_data(res->_searchlist[i]);
			}
		}
		FREE(res->_searchlist);
		if (res->_nameservers) {
			for (i = 0; i < res->_nameserver_count; i++) {
				ldns_rdf_free_data(res->_nameservers[i]);
			}
		}
		FREE(res->_nameservers);
		FREE(res);
	}
}

#if 0
/** 
 * Send the query 
 * \param[in] *r operate using this resolver
 * \param[in] *name query for this name
 * \param[in] *type query for this type (may be 0, defaults to A)
 * \param[in] *class query for this class (may be 0, default to IN)
 * \param[in] flags the query flags
 * \return ldns_pkt* a packet with the reply from the nameserver
 * if _dnsrch is true add the searchlist
 */
ldns_pkt *
ldns_resolver_search(ldns_resolver *r, ldns_rdf *name, ldns_rr_type type, 
                ldns_rr_class class, uint16_t flags)
{
	return NULL;
}
#endif

ldns_pkt *
ldns_resolver_query(ldns_resolver *r, ldns_rdf *name, ldns_rr_type type, ldns_rr_class class,
                uint16_t flags)
{
	ldns_rdf *newname;
	ldns_pkt *pkt;
	ldns_status status;

	if (!ldns_resolver_defnames(r)) {
		status = ldns_resolver_send(&pkt, r, name, type, class, flags);
		return pkt;
	}
	if (!ldns_resolver_domain(r)) {
		/* _defnames is set, but the domain is not....?? */
		status - ldns_resolver_send(&pkt, r, name, type, class, flags);
		return pkt;
	}

	newname = ldns_dname_cat(name, ldns_resolver_domain(r));
	if (!newname) {
		return NULL;
	}
	status = ldns_resolver_send(&pkt, r, newname, type, class, flags);
	ldns_rdf_free(newname);
	return pkt;
}

ldns_status
ldns_resolver_send_pkt(ldns_pkt **answer, ldns_resolver *r, ldns_pkt *query_pkt)
{
	uint8_t  retries;
	ldns_pkt *answer_pkt = NULL;

	/* return NULL on error */
	for (retries = ldns_resolver_retry(r); retries > 0; retries--) {
		answer_pkt = ldns_send(r, query_pkt);
		if (answer_pkt) {
			break;
		}
	}
	
	*answer = answer_pkt;
	return LDNS_STATUS_OK;
}

/* TODO: other error codes than _ERR */
ldns_status
ldns_resolver_send(ldns_pkt **answer, ldns_resolver *r, ldns_rdf *name, 
		ldns_rr_type type, ldns_rr_class class, uint16_t flags)
{
	ldns_pkt *query_pkt;
	ldns_pkt *answer_pkt;
	uint16_t id;
	ldns_status status;

	assert(r != NULL);
	assert(name != NULL);

	answer_pkt = NULL;
	
	/* do all the preprocessing here, then fire of an query to 
	 * the network */

	if (0 == type) {
		type = LDNS_RR_TYPE_A;
	}
	if (0 == class) {
		class = LDNS_RR_CLASS_IN;
	}
	if (0 == ldns_resolver_nameserver_count(r)) {
		dprintf("%s", "resolver has no nameservers\n");
		return LDNS_STATUS_ERR;
	}
	if (ldns_rdf_get_type(name) != LDNS_RDF_TYPE_DNAME) {
		dprintf("%s", "query type is not correct type\n");
		return LDNS_STATUS_ERR;
	}
	/* prepare a question pkt from the parameters
	 * and then send this */
	query_pkt = ldns_pkt_query_new(ldns_rdf_deep_clone(name), type, class, flags);
	if (!query_pkt) {
		dprintf("%s", "Failed to generate pkt\n");
		return LDNS_STATUS_ERR;
	}

	/* transfer the udp_edns_size from the resolver to the packet */
	if (ldns_resolver_edns_udp_size(r) != 0) {
		ldns_pkt_set_edns_udp_size(query_pkt,
				ldns_resolver_edns_udp_size(r));
	}

	/* set DO bit if necessary */
	/* TODO: macro or inline function for bit */
	if (ldns_resolver_dnssec(r) != 0) {
		ldns_pkt_set_edns_z(query_pkt,
		                    ldns_pkt_edns_z(query_pkt) | 0x8000
		                   );
	}

	if (ldns_resolver_debug(r)) {
		ldns_pkt_print(stdout, query_pkt);
	}
	
	/* TODO: time is a terrible seed */
	srandom((unsigned) time(NULL) ^ getpid());
	id = (uint16_t) random();

	ldns_pkt_set_id(query_pkt, id);

	/* if tsig values are set, tsign it */
	/* TODO: make last 3 arguments optional too? maybe make complete
	         rr instead of seperate values in resolver (and packet)
	*/
	if (ldns_resolver_tsig_keyname(r) && ldns_resolver_tsig_keydata(r)) {
		status = ldns_pkt_tsig_sign(query_pkt,
		                            ldns_resolver_tsig_keyname(r),
		                            ldns_resolver_tsig_keydata(r),
		                            300,
		                            ldns_resolver_tsig_algorithm(r),
		                            NULL);
		/* TODO: no print and feedback to caller */
		if (status != LDNS_STATUS_OK) {
			dprintf("error creating tsig: %u\n", status);
			return LDNS_STATUS_ERR;
		}
	}

	status = ldns_resolver_send_pkt(&answer_pkt, r, query_pkt);

	ldns_pkt_free(query_pkt);
	
	*answer = answer_pkt;
	return LDNS_STATUS_OK;
}

int
ldns_resolver_bgsend()
{
	return 0;
}
 
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
                	dprintf("%s", "unkown inet family\n");
                	return LDNS_STATUS_UNKNOWN_INET;
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
	uint8_t *packet_wire;
	size_t packet_wire_size;
	
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
		packet_wire = ldns_tcp_read_wire(resolver->_socket, &packet_wire_size);
		
		(void) ldns_wire2pkt(&resolver->_cur_axfr_pkt, packet_wire, packet_wire_size);
		free(packet_wire);
/*		resolver->_cur_axfr_pkt = ldns_tcp_read_packet(resolver->_socket);*/

		resolver->_axfr_i = 0;
		return ldns_axfr_next(resolver);
		
		if (!resolver->_cur_axfr_pkt)  {
			dprintf("%s", "[ldns_axfr_next] error reading packet\n");
			return NULL;
		}
		
		if (ldns_pkt_rcode(resolver->_cur_axfr_pkt) != 0) {
			dprintf("%s", "Got error code\n");
			close(resolver->_socket);
			resolver->_socket = 0;
			ldns_pkt_free(resolver->_cur_axfr_pkt);
			resolver->_cur_axfr_pkt = NULL;
			return NULL;
		}
		
	}
	
}
