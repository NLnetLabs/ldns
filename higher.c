/*
 * higher.c
 *
 * Specify some higher level functions that would
 * be usefull to would be developers
 *
 * a Net::DNS like library for C
 *
 * (c) NLnet Labs, 2004
 *
 * See the file LICENSE for the license
 */

#include <ldns/config.h>

#include <ldns/dns.h>

#include <openssl/ssl.h>
#include <openssl/sha.h>

ldns_rr_list *
ldns_get_rr_list_addr_by_name(ldns_resolver *res, ldns_rdf *name, ldns_rr_class c, 
		uint16_t flags)
{
	ldns_pkt *pkt;
	ldns_rr_list *aaaa;
	ldns_rr_list *a;
	ldns_rr_list *result;

	a = NULL; aaaa = NULL;

	if (!res) {
		return NULL;
	}
	if (ldns_rdf_get_type(name) != LDNS_RDF_TYPE_DNAME) {
		return NULL;
	}

	/* add the RD flags, because we want an answer */
	pkt = ldns_resolver_query(res, name, LDNS_RR_TYPE_AAAA, c, flags | LDNS_RD);
	if (pkt) {
		/* extract the data we need */
		aaaa = ldns_pkt_rr_list_by_type(pkt, 
				LDNS_RR_TYPE_AAAA, LDNS_SECTION_ANSWER);

		ldns_pkt_free(pkt);
	}

	pkt = ldns_resolver_query(res, name, LDNS_RR_TYPE_A, c, flags | LDNS_RD);
	if (pkt) {
		/* extract the data we need */
		a = ldns_pkt_rr_list_by_type(pkt, 
				LDNS_RR_TYPE_A, LDNS_SECTION_ANSWER);

		ldns_pkt_free(pkt);
	}

	result = ldns_rr_list_cat_clone(aaaa, a);

	ldns_rr_list_free(aaaa);
	ldns_rr_list_free(a);

	return result;
}

ldns_rr_list *
ldns_get_rr_list_name_by_addr(ldns_resolver *res, ldns_rdf *addr, ldns_rr_class c, 
		uint16_t flags)
{
	ldns_pkt *pkt;
	ldns_rr_list *names;
	ldns_rdf *name;
	size_t i;

	i = 0; names = NULL;

	if (!res || !addr) {
		return NULL;
	}

	if (ldns_rdf_get_type(addr) != LDNS_RDF_TYPE_A &&
			ldns_rdf_get_type(addr) != LDNS_RDF_TYPE_AAAA) {
		return NULL;
	}

	name = ldns_rdf_address_reverse(addr);
	
	/* add the RD flags, because we want an answer */
	pkt = ldns_resolver_query(res, name, LDNS_RR_TYPE_PTR, c, flags | LDNS_RD);
	if (pkt) {
		/* extract the data we need */
		names = ldns_pkt_rr_list_by_type(pkt, 
				LDNS_RR_TYPE_PTR, LDNS_SECTION_ANSWER);
	}
	return names;
}

/* read a line, put it in a buffer, parse the buffer */
ldns_rr_list *
ldns_get_rr_list_hosts_frm_fp(FILE *fp)
{
	ssize_t i, j;
	size_t cnt;
	char *line;
	char *word;
	char *addr;
	char *rr_str;
	ldns_buffer *linebuf;
	ldns_rr *rr;
	ldns_rr_list *list;
	bool ip6;

	linebuf = ldns_buffer_new(LDNS_MAX_LINELEN);

	/* duh duh duh !!!!! */
	line = LDNS_XMALLOC(char, LDNS_MAX_LINELEN + 1);
	word = LDNS_XMALLOC(char, LDNS_MAX_LINELEN + 1);
	addr = LDNS_XMALLOC(char, LDNS_MAX_LINELEN + 1);
	rr_str = LDNS_XMALLOC(char, LDNS_MAX_LINELEN + 1);
	ip6 = false;
	list = ldns_rr_list_new();
	rr = NULL;

	for(i = ldns_fget_token(fp, line, "\n", 0);
			i > 0;
			i = ldns_fget_token(fp, line, "\n", 0)) 
	{
		/* # is comment */
		if (line[0] == '#') {
			continue;
		}
		/* put it in a buffer for further processing */
		ldns_buffer_new_frm_data(linebuf, line, (size_t) i);
		for(cnt = 0, j = ldns_bget_token(linebuf, word, LDNS_PARSE_NO_NL, 0);
				j > 0;
				j = ldns_bget_token(linebuf, word, LDNS_PARSE_NO_NL, 0),
				cnt++)
		{
			if (cnt == 0) {
				/* the address */
				if (ldns_rdf_new_frm_str(LDNS_RDF_TYPE_AAAA, word)) {
					/* ip6 */
					ip6 = true;
				} else {
					if (ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, word)) {
						/* ip4 */
						ip6 = false;
					} else {
						/* kaput */
						break;
					}
				}
				strncpy(addr, word, LDNS_IP6ADDRLEN);
			} else {
				/* la al la la */
				if (ip6) {
					snprintf(rr_str, LDNS_MAX_LINELEN, "%s IN AAAA %s", word, addr);
				} else {
					snprintf(rr_str, LDNS_MAX_LINELEN, "%s IN A %s", word, addr);
				}
				rr = ldns_rr_new_frm_str(rr_str);
			}
		}
		if (rr) {
				ldns_rr_list_push_rr(list, rr);
		}
	}
	LDNS_FREE(line);
	LDNS_FREE(word);
	LDNS_FREE(addr);
	LDNS_FREE(rr_str);
	return list;
}


ldns_rr_list *
ldns_get_rr_list_hosts_frm_file(char *filename)
{
	ldns_rr_list *names;
	FILE *fp;

	if (!filename) {
                fp = fopen(LDNS_RESOLV_HOSTS, "r");
        
        } else {
                fp = fopen(filename, "r");
        }
        if (!fp) {
                return NULL;
        }

	names = ldns_get_rr_list_hosts_frm_fp(fp);
	fclose(fp);
	return names;
}

uint16_t
ldns_getaddrinfo(ldns_resolver *res, ldns_rdf *node, ldns_rr_class c, ldns_rr_list **ret)
{
	ldns_rdf_type t;
	uint16_t names_found;
	ldns_resolver *r;

	t = ldns_rdf_get_type(node);
	names_found = 0;
	r = res;

	if (res == NULL) {
		/* prepare a new resolver, using /etc/resolv.conf is a guide  */
		r = ldns_resolver_new_frm_file(NULL);
		if (!r) {
			return 0;
		} 
	}

	if (t == LDNS_RDF_TYPE_DNAME) {
		/* we're asked to query for a name */
		*ret = ldns_get_rr_list_addr_by_name(
				r, node, c, 0);
		names_found = ldns_rr_list_rr_count(*ret);
	}

	if (t == LDNS_RDF_TYPE_A || t == LDNS_RDF_TYPE_AAAA) {
		/* an address */
		*ret = ldns_get_rr_list_name_by_addr(
				r, node, c, 0);
		names_found = ldns_rr_list_rr_count(*ret);
	}

	if (res == NULL) {
		ldns_resolver_free(r);
	}
	
	return names_found;
}

ldns_rr_list *
ldns_getaddrinfo_secure(void)
{
	return NULL;
}
