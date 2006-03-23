/*
 * resolver.c
 *
 * resolver implementation
 *
 * a Net::DNS like library for C
 *
 * (c) NLnet Labs, 2004-2006
 *
 * See the file LICENSE for the license
 */

#include <ldns/config.h>

#include <ldns/dns.h>
#include <strings.h>

/* Access function for reading 
 * and setting the different Resolver 
 * options */

/* read */
uint16_t
ldns_resolver_port(const ldns_resolver *r)
{
	return r->_port;
}

uint16_t
ldns_resolver_edns_udp_size(const ldns_resolver *r)
{
	        return r->_edns_udp_size;
}

uint8_t
ldns_resolver_retry(const ldns_resolver *r)
{
	return r->_retry;
}

uint8_t
ldns_resolver_retrans(const ldns_resolver *r)
{
	return r->_retrans;
}

uint8_t
ldns_resolver_ip6(const ldns_resolver *r)
{
	return r->_ip6;
}

bool
ldns_resolver_recursive(const ldns_resolver *r)
{
	return r->_recursive;
}

bool
ldns_resolver_debug(const ldns_resolver *r)
{
	return r->_debug;
}

bool
ldns_resolver_dnsrch(const ldns_resolver *r)
{
	return r->_dnsrch;
}

bool
ldns_resolver_fail(const ldns_resolver *r)
{
	return r->_fail;
}

bool
ldns_resolver_defnames(const ldns_resolver *r)
{
	return r->_defnames;
}

ldns_rdf *
ldns_resolver_domain(const ldns_resolver *r)
{
	return r->_domain;
}

ldns_rdf **
ldns_resolver_searchlist(const ldns_resolver *r)
{
	return r->_searchlist;
}

ldns_rdf **
ldns_resolver_nameservers(const ldns_resolver *r)
{
	return r->_nameservers;
}

size_t
ldns_resolver_nameserver_count(const ldns_resolver *r)
{
	return r->_nameserver_count;
}

bool
ldns_resolver_dnssec(const ldns_resolver *r)
{
	return r->_dnssec;
}

bool
ldns_resolver_dnssec_cd(const ldns_resolver *r)
{
	return r->_dnssec_cd;
}

bool
ldns_resolver_igntc(const ldns_resolver *r)
{
	return r->_igntc;
}

bool
ldns_resolver_usevc(const ldns_resolver *r)
{
	return r->_usevc;
}

size_t *
ldns_resolver_rtt(const ldns_resolver *r)
{
	return r->_rtt;
}

size_t
ldns_resolver_nameserver_rtt(const ldns_resolver *r, size_t pos)
{
	size_t *rtt;

	assert(r != NULL);
	
	rtt = ldns_resolver_rtt(r);
	
	if (pos >= ldns_resolver_nameserver_count(r)) {
		/* error ?*/
		return 0;
	} else {
		return rtt[pos];
	}

}

struct timeval
ldns_resolver_timeout(const ldns_resolver *r)
{
	return r->_timeout;
} 

char *
ldns_resolver_tsig_keyname(const ldns_resolver *r)
{
	return r->_tsig_keyname;
}

char *
ldns_resolver_tsig_algorithm(const ldns_resolver *r)
{
	return r->_tsig_algorithm;
}

char *
ldns_resolver_tsig_keydata(const ldns_resolver *r)
{
	return r->_tsig_keydata;
}

bool
ldns_resolver_random(const ldns_resolver *r)
{
	return r->_random;
}

size_t
ldns_resolver_searchlist_count(const ldns_resolver *r)
{
	return r->_searchlist_count;
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
	size_t *rtt;

	assert(r != NULL);

	ns_count = ldns_resolver_nameserver_count(r);
	nameservers = ldns_resolver_nameservers(r);
	rtt = ldns_resolver_rtt(r);
	if (ns_count == 0 || !nameservers) {
		return NULL;
	}
	
	pop = nameservers[ns_count - 1];

	nameservers = LDNS_XREALLOC(nameservers, ldns_rdf *, (ns_count - 1));
	rtt = LDNS_XREALLOC(rtt, size_t, (ns_count - 1));

	ldns_resolver_set_nameservers(r, nameservers);
	ldns_resolver_set_rtt(r, rtt);
	/* decr the count */
	ldns_resolver_dec_nameserver_count(r);
	return pop;
}

ldns_status
ldns_resolver_push_nameserver(ldns_resolver *r, ldns_rdf *n)
{
	ldns_rdf **nameservers;
	size_t ns_count;
	size_t *rtt;

	if (ldns_rdf_get_type(n) != LDNS_RDF_TYPE_A &&
			ldns_rdf_get_type(n) != LDNS_RDF_TYPE_AAAA) {
		return LDNS_STATUS_ERR;
	}

	ns_count = ldns_resolver_nameserver_count(r);
	nameservers = ldns_resolver_nameservers(r);
	rtt = ldns_resolver_rtt(r);

	/* make room for the next one */
	nameservers = LDNS_XREALLOC(nameservers, ldns_rdf *, (ns_count + 1));
	/* don't forget the rtt */
	rtt = LDNS_XREALLOC(rtt, size_t, (ns_count + 1));
	
	/* set the new value in the resolver */
	ldns_resolver_set_nameservers(r, nameservers);

	/* slide n in its slot. */
	/* we clone it here, because then we can free the original
	 * rr's where it stood */
	nameservers[ns_count] = ldns_rdf_clone(n);
	rtt[ns_count] = LDNS_RESOLV_RTT_MIN;
	ldns_resolver_incr_nameserver_count(r);
	ldns_resolver_set_rtt(r, rtt);
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
			if (ldns_resolver_push_nameserver_rr(r, rr) != LDNS_STATUS_OK) {
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
ldns_resolver_set_dnssec_cd(ldns_resolver *r, bool d)
{
	r->_dnssec_cd = d;
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
ldns_resolver_set_rtt(ldns_resolver *r, size_t *rtt)
{
	r->_rtt = rtt;
}

void
ldns_resolver_set_nameserver_rtt(ldns_resolver *r, size_t pos, size_t value)
{
	size_t *rtt;

	assert(r != NULL);

	rtt = ldns_resolver_rtt(r);
	
	if (pos >= ldns_resolver_nameserver_count(r)) {
		/* error ?*/
	} else {
		rtt[pos] = value;
	}

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
	ldns_rdf **searchlist;
	size_t list_count;

	if (ldns_rdf_get_type(d) != LDNS_RDF_TYPE_DNAME) {
		return;
	}

	list_count = ldns_resolver_searchlist_count(r);
	searchlist = ldns_resolver_searchlist(r);

	searchlist = LDNS_XREALLOC(searchlist, ldns_rdf *, (list_count + 1));
	if (searchlist) {
		r->_searchlist = searchlist;

		searchlist[list_count] = ldns_rdf_clone(d);
		ldns_resolver_set_searchlist_count(r, list_count + 1);
	}
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

void
ldns_resolver_set_random(ldns_resolver *r, bool b)
{
	r->_random = b;
}

/* more sophisticated functions */
ldns_resolver *
ldns_resolver_new(void)
{
	ldns_resolver *r;

	r = LDNS_MALLOC(ldns_resolver);
	if (!r) {
		return NULL;
	}

	r->_searchlist = NULL;
	r->_nameservers = NULL;
	r->_rtt = NULL;

	/* defaults are filled out */
	ldns_resolver_set_searchlist_count(r, 0);
	ldns_resolver_set_nameserver_count(r, 0);
	ldns_resolver_set_usevc(r, 0);
	ldns_resolver_set_port(r, LDNS_PORT);
	ldns_resolver_set_domain(r, NULL);
	ldns_resolver_set_defnames(r, false);
	ldns_resolver_set_retry(r, 3);
	ldns_resolver_set_retrans(r, 2);
	ldns_resolver_set_fail(r, false);
	ldns_resolver_set_edns_udp_size(r, 0);
	ldns_resolver_set_dnssec(r, false);
	ldns_resolver_set_dnssec_cd(r, false);
	ldns_resolver_set_ip6(r, LDNS_RESOLV_INETANY);

	/* randomize the nameserver to be queried
	 * when there are multiple
	 */
	ldns_resolver_set_random(r, true);

	ldns_resolver_set_debug(r, 0);
	
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
	return ldns_resolver_new_frm_fp_l(fp, NULL);
}

ldns_resolver *
ldns_resolver_new_frm_fp_l(FILE *fp, int *line_nr)
{
	ldns_resolver *r;
	const char *keyword[LDNS_RESOLV_KEYWORDS];
	char *word;
	int8_t expect;
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
	keyword[LDNS_RESOLV_DEFDOMAIN] = "domain";
	keyword[LDNS_RESOLV_NAMESERVER] = "nameserver";
	keyword[LDNS_RESOLV_SEARCH] = "search";
	word = LDNS_XMALLOC(char, LDNS_MAX_LINELEN + 1);
	expect = LDNS_RESOLV_KEYWORD;

	r = ldns_resolver_new();
	if (!r) {
		return NULL;
	}
	gtr = ldns_fget_token_l(fp, word, LDNS_PARSE_NORMAL, 0, line_nr);
	while (gtr > 0) {
		/* check comments */
		if (word[0] == '#') {
			/* read the rest of the line, should be 1 word */
			gtr = ldns_fget_token_l(fp, word, LDNS_PARSE_NORMAL, 0, line_nr);
			/* prepare the next string for furhter parsing */
			gtr = ldns_fget_token_l(fp, word, LDNS_PARSE_NORMAL, 0, line_nr);
			continue;
		}
		switch(expect) {
			case LDNS_RESOLV_KEYWORD:
				/* keyword */
				for(i = 0; i < LDNS_RESOLV_KEYWORDS; i++) {
					if (strcasecmp(keyword[i], word) == 0) {
						/* chosen the keyword and
						 * expect values carefully
						 */
						expect = i;
						break;
					}
				}
				/* no keyword recognized */
				if (expect == LDNS_RESOLV_KEYWORD) {
					LDNS_FREE(word);
					return NULL;
				}
				break;
			case LDNS_RESOLV_DEFDOMAIN:
				/* default domain dname */
				tmp = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, word);
				if (!tmp) {
					LDNS_FREE(word);
					return NULL;
				}

				/* DOn't free, because we copy the pointer */
				ldns_resolver_set_domain(r, tmp);
				expect = LDNS_RESOLV_KEYWORD;
				break;
			case LDNS_RESOLV_NAMESERVER:
				/* NS aaaa or a record */
				tmp = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_AAAA, word);
				if (!tmp) {
					/* try ip4 */
					tmp = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, word);
				}
				/* could not parse it, exit */
				if (!tmp) {
					LDNS_FREE(word);
					return NULL;
				}
				(void)ldns_resolver_push_nameserver(r, tmp);
				ldns_rdf_deep_free(tmp);
				expect = LDNS_RESOLV_KEYWORD;
				break;
			case LDNS_RESOLV_SEARCH:
				/* search list domain dname, will only work with 1 name! */
				tmp = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, word);
				if (!tmp) {
					LDNS_FREE(word);
					return NULL;
				}

				ldns_resolver_push_searchlist(r, tmp); 
				ldns_rdf_deep_free(tmp);
				expect = LDNS_RESOLV_KEYWORD;
				break;
		}
		gtr = ldns_fget_token_l(fp, word, LDNS_PARSE_NORMAL, 0, line_nr);
	}
	
	LDNS_FREE(word);
	return r;
}

ldns_resolver *
ldns_resolver_new_frm_file(const char *filename)
{
	ldns_resolver *r;
	FILE *fp;

	if (!filename) {
		fp = fopen(LDNS_RESOLV_CONF, "r");

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
ldns_resolver_deep_free(ldns_resolver *res)
{
	size_t i;
	
	if (res) {
		if (res->_searchlist) {
			for (i = 0; i < ldns_resolver_searchlist_count(res); i++) {
				ldns_rdf_deep_free(res->_searchlist[i]);
			}
			LDNS_FREE(res->_searchlist);
		}
		if (res->_nameservers) {
			for (i = 0; i < res->_nameserver_count; i++) {
				ldns_rdf_deep_free(res->_nameservers[i]);
			}
			LDNS_FREE(res->_nameservers);
		}
		if (ldns_resolver_domain(res)) {
			ldns_rdf_deep_free(ldns_resolver_domain(res));
		}
		if (ldns_resolver_tsig_keyname(res)) {
			LDNS_FREE(res->_tsig_keyname);
		}
		
		if (res->_cur_axfr_pkt) {
			ldns_pkt_free(res->_cur_axfr_pkt);
		}
		
		if (res->_rtt) {
			LDNS_FREE(res->_rtt);
		}
		LDNS_FREE(res);
	}
}

ldns_pkt *
ldns_resolver_search(const ldns_resolver *r,const  ldns_rdf *name, ldns_rr_type type, 
                ldns_rr_class class, uint16_t flags)
{

	char *str_dname;
	ldns_rdf *new_name;
	ldns_rdf **search_list;
	size_t i;
	ldns_pkt *p;

	str_dname = ldns_rdf2str(name);

	if (ldns_dname_str_absolute(str_dname)) {
		/* query as-is */
		return ldns_resolver_query(r, name, type, class, flags);
	} else {
		search_list = ldns_resolver_searchlist(r);
		for (i = 0; i < ldns_resolver_searchlist_count(r); i++) {
			new_name = ldns_dname_cat_clone(name, search_list[i]);

			p = ldns_resolver_query(r, new_name, type, class, flags);
			ldns_rdf_free(new_name);
			if (p) {
				return p;
			}
		}
	}
	return NULL;
}

ldns_pkt *
ldns_resolver_query(const ldns_resolver *r, const ldns_rdf *name, ldns_rr_type type, 
		ldns_rr_class class, uint16_t flags)
{
	ldns_rdf *newname;
	ldns_pkt *pkt;
	ldns_status status;

	pkt = NULL;

	if (!ldns_resolver_defnames(r)) {
		status = ldns_resolver_send(&pkt, (ldns_resolver *)r, name, type, class, 
				flags);
		if (status == LDNS_STATUS_OK) {
			return pkt;
		} else {
			if (pkt) {
				ldns_pkt_free(pkt);
			}
			return NULL;
		}
	}

	if (!ldns_resolver_domain(r)) {
		/* _defnames is set, but the domain is not....?? */
		status = ldns_resolver_send(&pkt, (ldns_resolver *)r, name, type, class, 
				flags);
		if (status == LDNS_STATUS_OK) {
			return pkt;
		} else {
			if (pkt) {
				ldns_pkt_free(pkt);
			}
			return NULL;
		}
	}

	newname = ldns_dname_cat_clone((const ldns_rdf*)name, ldns_resolver_domain(r));
	if (!newname) {
		if (pkt) {
			ldns_pkt_free(pkt);
		}
		return NULL;
	}
	status = ldns_resolver_send(&pkt, (ldns_resolver *)r, newname, type, class, 
			flags);
	ldns_rdf_free(newname);
	return pkt;
}

ldns_status
ldns_resolver_send_pkt(ldns_pkt **answer,const ldns_resolver *r, 
		const ldns_pkt *query_pkt)
{
	ldns_pkt *answer_pkt = NULL;
	ldns_status stat = LDNS_STATUS_OK;

	stat = ldns_send(&answer_pkt, (ldns_resolver *)r, query_pkt);
	if (stat != LDNS_STATUS_OK) {
		if(answer_pkt) {
			ldns_pkt_free(answer_pkt);
			answer_pkt = NULL;
		}
	}
	
	if (answer) {
		*answer = answer_pkt;
	}

	return stat;
}

ldns_status
ldns_resolver_prepare_query_pkt(ldns_pkt **query_pkt, ldns_resolver *r,
                                const  ldns_rdf *name, ldns_rr_type type, 
                                ldns_rr_class class, uint16_t flags)
{
	/* prepare a question pkt from the parameters
	 * and then send this */
	*query_pkt = ldns_pkt_query_new(ldns_rdf_clone(name), type, class, flags);
	if (!*query_pkt) {
		return LDNS_STATUS_ERR;
	}

	/* set DO bit if necessary */
	if (ldns_resolver_dnssec(r)) {
		if (ldns_resolver_edns_udp_size(r) == 0) {
			ldns_resolver_set_edns_udp_size(r, 4096);
		}
		ldns_pkt_set_edns_do(*query_pkt, true);
		ldns_pkt_set_cd(*query_pkt, ldns_resolver_dnssec_cd(r));
	}

	/* transfer the udp_edns_size from the resolver to the packet */
	if (ldns_resolver_edns_udp_size(r) != 0) {
		ldns_pkt_set_edns_udp_size(*query_pkt, ldns_resolver_edns_udp_size(r));
	}

	if (ldns_resolver_debug(r)) {
		ldns_pkt_print(stdout, *query_pkt);
	}
	
	/* only set the id if it is not set yet */
	if (ldns_pkt_id(*query_pkt) == 0) {
		srandom((unsigned) time(NULL) ^ getpid());
		ldns_pkt_set_id(*query_pkt, (uint16_t) random());
	}

	return LDNS_STATUS_OK;
}


ldns_status
ldns_resolver_send(ldns_pkt **answer, ldns_resolver *r,const  ldns_rdf *name, 
		ldns_rr_type type, ldns_rr_class class, uint16_t flags)
{
	ldns_pkt *query_pkt;
	ldns_pkt *answer_pkt;
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
		return LDNS_STATUS_RES_NO_NS;
	}
	if (ldns_rdf_get_type(name) != LDNS_RDF_TYPE_DNAME) {
		return LDNS_STATUS_RES_QUERY;
	}

	status = ldns_resolver_prepare_query_pkt(&query_pkt,
	                                         r,
	                                         name,
	                                         type,
	                                         class,
	                                         flags);
	if (status != LDNS_STATUS_OK) {
		return status;
	}

	/* if tsig values are set, tsign it */
	/* TODO: make last 3 arguments optional too? maybe make complete
	         rr instead of seperate values in resolver (and packet)
	  Jelte
	  should this go in pkt_prepare?
	*/
#ifdef HAVE_SSL
	if (ldns_resolver_tsig_keyname(r) && ldns_resolver_tsig_keydata(r)) {
		status = ldns_pkt_tsig_sign(query_pkt,
		                            ldns_resolver_tsig_keyname(r),
		                            ldns_resolver_tsig_keydata(r),
		                            300, ldns_resolver_tsig_algorithm(r), NULL);
		if (status != LDNS_STATUS_OK) {
			return LDNS_STATUS_CRYPTO_TSIG_ERR;
		}
	}
#endif /* HAVE_SSL */
	status = ldns_resolver_send_pkt(&answer_pkt, r, query_pkt);
	ldns_pkt_free(query_pkt);
	
	/* allows answer to be NULL when not interested in return value */
	if (answer) {
		*answer = answer_pkt;
	}
	return status;
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
		cur_rr = ldns_rr_clone(ldns_rr_list_rr(
					ldns_pkt_answer(resolver->_cur_axfr_pkt), 
					resolver->_axfr_i));
		resolver->_axfr_i++;
		if (ldns_rr_get_type(cur_rr) == LDNS_RR_TYPE_SOA) {
			resolver->_axfr_soa_count++;
			if (resolver->_axfr_soa_count >= 2) {
				close(resolver->_socket);
				resolver->_socket = 0;
				ldns_pkt_free(resolver->_cur_axfr_pkt);
				resolver->_cur_axfr_pkt = NULL;
			}
		}
		return cur_rr;
	} else {
		packet_wire = ldns_tcp_read_wire(resolver->_socket, &packet_wire_size);
		
		(void) ldns_wire2pkt(&resolver->_cur_axfr_pkt, packet_wire, 
				     packet_wire_size);
		free(packet_wire);

		resolver->_axfr_i = 0;
		if (ldns_pkt_rcode(resolver->_cur_axfr_pkt) != 0) {
			/* error */
			return NULL;
		} else {
			return ldns_axfr_next(resolver);
		}
		
	}
	
}

bool
ldns_axfr_complete(const ldns_resolver *res) 
{
	/* complete when soa count is 2? */
	return res->_axfr_soa_count == 2;
}

ldns_pkt *
ldns_axfr_last_pkt(const ldns_resolver *res) 
{
	return res->_cur_axfr_pkt;
}

/* random isn't really that good */
void
ldns_resolver_nameservers_randomize(ldns_resolver *r)
{
	uint8_t i, j;
	ldns_rdf **ns, *tmp;

	/* should I check for ldns_resolver_random?? */
	assert(r != NULL);

	ns = ldns_resolver_nameservers(r);
	
	for (i = 0; i < ldns_resolver_nameserver_count(r); i++) {
		j = random() % ldns_resolver_nameserver_count(r);
		tmp = ns[i];
		ns[i] = ns[j];
		ns[j] = tmp;
	}
	ldns_resolver_set_nameservers(r, ns);
}

/* dynamic update stuff */
ldns_resolver *
ldns_update_resolver_new(const char *fqdn, const char *zone,
    ldns_rr_class class, ldns_tsig_credentials *tsig_cred, ldns_rdf **zone_rdf)
{
	ldns_resolver	*r1, *r2;
	ldns_pkt	*query = NULL, *resp;
	ldns_rr_list	*nslist, *iplist;
	ldns_rdf	*soa_zone, *soa_mname, *ns_name;
	size_t		i;

	if (class == 0)
		class = LDNS_RR_CLASS_IN;

	/* First, get data from /etc/resolv.conf */
	r1 = ldns_resolver_new_frm_file(NULL);
	if (!r1)
		return NULL;

	r2 = ldns_resolver_new();
	if (!r2)
		goto bad;

	/* TSIG key data available? Copy into the resolver. */
	if (tsig_cred) {
		ldns_resolver_set_tsig_algorithm(r2, ldns_tsig_algorithm(tsig_cred));
		ldns_resolver_set_tsig_keyname(r2, ldns_tsig_keyname_clone(tsig_cred));
		/*
		 * XXX Weird that ldns_resolver_deep_free() will free()
		 * keyname but not hmac key data?
		 */
		ldns_resolver_set_tsig_keydata(r2, ldns_tsig_keydata_clone(tsig_cred));
	}
	
	/* Now get SOA zone, mname, NS, and construct r2. [RFC2136 4.3] */

	/* Explicit 'zone' or no? */
	if (zone) {
		soa_zone = ldns_dname_new_frm_str(zone);
		if (ldns_update_soa_mname(soa_zone, r1, class, &soa_mname)
		    != LDNS_STATUS_OK)
			goto bad;
	} else {
		if (ldns_update_soa_zone_mname(fqdn, r1, class, &soa_zone,
			&soa_mname) != LDNS_STATUS_OK)
			goto bad;
	}
	
	/* Pass zone_rdf on upwards. */
	*zone_rdf = ldns_rdf_clone(soa_zone);
	
	/* NS */
	query = ldns_pkt_query_new(soa_zone, LDNS_RR_TYPE_NS, class, LDNS_RD);
	if (!query)
		goto bad;
	soa_zone = NULL;

	ldns_pkt_set_random_id(query);
	if (ldns_resolver_send_pkt(&resp, r1, query) != LDNS_STATUS_OK) {
		dprintf("%s", "NS query failed!\n");
		goto bad;
	}
	ldns_pkt_free(query);
	if (!resp)
		goto bad;

	/* Match SOA MNAME to NS list, adding it first */
	nslist = ldns_pkt_answer(resp);
	for (i = 0; i < ldns_rr_list_rr_count(nslist); i++) {
		ns_name = ldns_rr_rdf(ldns_rr_list_rr(nslist, i), 0);
		if (!ns_name)
			continue;
		if (ldns_rdf_compare(soa_mname, ns_name) == 0) {
			/* Match */
			iplist = ldns_get_rr_list_addr_by_name(r1, ns_name, class, 0);
			(void) ldns_resolver_push_nameserver_rr_list(r2, iplist);
			break;
		}
	}

	/* Then all the other NSs. XXX Randomize? */
	for (i = 0; i < ldns_rr_list_rr_count(nslist); i++) {
		ns_name = ldns_rr_rdf(ldns_rr_list_rr(nslist, i), 0);
		if (!ns_name)
			continue;
		if (ldns_rdf_compare(soa_mname, ns_name) != 0) {
			/* No match, add it now. */
			iplist = ldns_get_rr_list_addr_by_name(r1, ns_name, class, 0);
			(void) ldns_resolver_push_nameserver_rr_list(r2, iplist);
		}
	}

	/* Cleanup and return. */
	ldns_resolver_set_random(r2, false);
	ldns_pkt_free(resp);
	ldns_resolver_deep_free(r1);
	return r2;
	
  bad:
	if (r1)
		ldns_resolver_deep_free(r1);
	if (r2)
		ldns_resolver_deep_free(r2);
	if (query)
		ldns_pkt_free(query);
	if (resp)
		ldns_pkt_free(resp);
	return NULL;
}
