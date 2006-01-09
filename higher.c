/*
 * higher.c
 *
 * Specify some higher level functions that would
 * be usefull to would be developers
 *
 * a Net::DNS like library for C
 *
 * (c) NLnet Labs, 2004-2006
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
	ldns_rr_list *result = NULL;
	ldns_rr_list *hostsfilenames;
	size_t i;
	uint8_t ip6;

	a = NULL; aaaa = NULL; result = NULL;

	if (!res) {
		return NULL;
	}
	if (ldns_rdf_get_type(name) != LDNS_RDF_TYPE_DNAME) {
		return NULL;
	}

	ip6 = ldns_resolver_ip6(res); /* we use INET_ANY here, save
					 what was there */

	ldns_resolver_set_ip6(res, LDNS_RESOLV_INETANY);
	
	hostsfilenames = ldns_get_rr_list_hosts_frm_file(NULL);
	for (i = 0; i < ldns_rr_list_rr_count(hostsfilenames); i++) {
		if (ldns_rdf_compare(name, ldns_rr_owner(ldns_rr_list_rr(hostsfilenames, i))) == 0) {
			if (!result) {
				result = ldns_rr_list_new();
			}
			ldns_rr_list_push_rr(result, ldns_rr_clone(ldns_rr_list_rr(hostsfilenames, i)));
		}
	}

	ldns_rr_list_deep_free(hostsfilenames);

	if (result) {
		return result;
	}

	/* add the RD flags, because we want an answer */
	pkt = ldns_resolver_query(res, name, LDNS_RR_TYPE_AAAA, c, flags | LDNS_RD);
	if (pkt) {
		/* extract the data we need */
		aaaa = ldns_pkt_rr_list_by_type(pkt, 
				LDNS_RR_TYPE_AAAA, LDNS_SECTION_ANSWER);

		/* ldns_rr_list_print(stdout, aaaa); DEBUG */
		ldns_pkt_free(pkt);
	} 

	pkt = ldns_resolver_query(res, name, LDNS_RR_TYPE_A, c, flags | LDNS_RD);
	if (pkt) {
		/* extract the data we need */
		a = ldns_pkt_rr_list_by_type(pkt, 
				LDNS_RR_TYPE_A, LDNS_SECTION_ANSWER);
		ldns_pkt_free(pkt);
	} 

	ldns_resolver_set_ip6(res, ip6);

	if (aaaa && a) {
		result = ldns_rr_list_cat_clone(aaaa, a);
		ldns_rr_list_deep_free(aaaa);
		ldns_rr_list_deep_free(a);
		return result;
	}
	
	if (aaaa) {
		result = ldns_rr_list_clone(aaaa);
	}
	
	if (a) {
		result = ldns_rr_list_clone(a);
	}

	ldns_rr_list_deep_free(aaaa);
	ldns_rr_list_deep_free(a);

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
	return ldns_get_rr_list_hosts_frm_fp_l(fp, NULL);
}

ldns_rr_list *
ldns_get_rr_list_hosts_frm_fp_l(FILE *fp, int *line_nr)
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
	ldns_rdf *tmp;
	bool ip6;

	/* duh duh duh !!!!! */
	line = LDNS_XMALLOC(char, LDNS_MAX_LINELEN + 1);
	word = LDNS_XMALLOC(char, LDNS_MAX_LINELEN + 1);
	addr = LDNS_XMALLOC(char, LDNS_MAX_LINELEN + 1);
	rr_str = LDNS_XMALLOC(char, LDNS_MAX_LINELEN + 1);
	ip6 = false;
	list = ldns_rr_list_new();
	rr = NULL;

	for(i = ldns_fget_token_l(fp, line, "\n", 0, line_nr);
			i > 0;
			i = ldns_fget_token_l(fp, line, "\n", 0, line_nr)) 
	{
		/* # is comment */
		if (line[0] == '#') {
			continue;
		}
		/* put it in a buffer for further processing */
		linebuf = LDNS_MALLOC(ldns_buffer);

		ldns_buffer_new_frm_data(linebuf, line, (size_t) i);
		for(cnt = 0, j = ldns_bget_token(linebuf, word, LDNS_PARSE_NO_NL, 0);
				j > 0;
				j = ldns_bget_token(linebuf, word, LDNS_PARSE_NO_NL, 0),
				cnt++)
		{
			if (cnt == 0) {
				/* the address */
				if ((tmp = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_AAAA, word))) {
					/* ip6 */
					ldns_rdf_deep_free(tmp);
					ip6 = true;
				} else {
					if ((tmp = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, word))) {
						/* ip4 */
						ldns_rdf_deep_free(tmp);
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
				rr = ldns_rr_new_frm_str(rr_str, 0, NULL, NULL);
				if (rr) {
						ldns_rr_list_push_rr(list, ldns_rr_clone(rr));
				}
				ldns_rr_free(rr);
			}
		}
		ldns_buffer_free(linebuf);
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
		ldns_resolver_deep_free(r);
	}
	
	return names_found;
}

/*
 * Send a "simple" update for an A or an AAAA RR.
 * \param[in] fqdn the update RR owner
 * \param[in] zone the zone to update, if set to NULL, try to figure it out
 * \param[in] ipaddr the address to add, if set to NULL, remove any A/AAAA RRs
 * \param[in] ttl the update RR TTL
 * \param[in] tsig_cred credentials for TSIG-protected update messages
 */
ldns_status
ldns_update_send_simple_addr(const char *fqdn, const char *zone,
    const char *ipaddr, uint16_t ttl, ldns_tsig_credentials *tsig_cred)
{
	ldns_resolver	*res;
	ldns_pkt	*u_pkt = NULL, *r_pkt;
	ldns_rr_list	*up_rrlist;
	ldns_rr		*up_rr;
	ldns_rdf	*zone_rdf;
	char		*rrstr;
	uint32_t	rrstrlen, status = LDNS_STATUS_OK;

	if (!fqdn || strlen(fqdn) == 0)
		return LDNS_STATUS_ERR;

	/* Create resolver */
	res = ldns_update_resolver_new(fqdn, zone, LDNS_RR_CLASS_IN, tsig_cred,
	    &zone_rdf);
	if (!res || !zone_rdf)
		goto cleanup;

	/* Set up the update section. */
	up_rrlist = ldns_rr_list_new();
	if (!up_rrlist)
		goto cleanup;

	/* Create input for ldns_rr_new_frm_str() */
	if (ipaddr) {
		/* We're adding A or AAAA */
		rrstrlen = strlen(fqdn) + sizeof (" IN AAAA ") +
		    strlen(ipaddr) + 1;
		rrstr = (char *)malloc(rrstrlen);
		if (!rrstr) {
			ldns_rr_list_deep_free(up_rrlist);
			goto cleanup;
		}
		snprintf(rrstr, rrstrlen, "%s IN %s %s", fqdn,
		    strchr(ipaddr, ':') ? "AAAA" : "A", ipaddr);

		up_rr = ldns_rr_new_frm_str(rrstr, ttl, NULL, NULL);
		if (!up_rr) {
			ldns_rr_list_deep_free(up_rrlist);
			free(rrstr);
			goto cleanup;
		}
		free(rrstr);
		ldns_rr_list_push_rr(up_rrlist, up_rr);
	} else {
		/* We're removing A and/or AAAA from 'fqdn'. [RFC2136 2.5.2] */
		up_rr = ldns_rr_new();
		ldns_rr_set_owner(up_rr, ldns_dname_new_frm_str(fqdn));
		ldns_rr_set_ttl(up_rr, 0);
		ldns_rr_set_class(up_rr, LDNS_RR_CLASS_ANY);

		ldns_rr_set_type(up_rr, LDNS_RR_TYPE_A);
		ldns_rr_list_push_rr(up_rrlist, ldns_rr_clone(up_rr));

		ldns_rr_set_type(up_rr, LDNS_RR_TYPE_AAAA);
		ldns_rr_list_push_rr(up_rrlist, up_rr);
	}
	
	/* Create update packet. */
	u_pkt = ldns_update_pkt_new(zone_rdf, LDNS_RR_CLASS_IN, NULL,
	    up_rrlist, NULL);
	zone_rdf = NULL;
	if (!u_pkt) {
		ldns_rr_list_deep_free(up_rrlist);
		goto cleanup;
	}
	ldns_pkt_set_random_id(u_pkt);

	/* Add TSIG */
	if (tsig_cred)
		if (ldns_update_pkt_tsig_add(u_pkt, res) != LDNS_STATUS_OK)
			goto cleanup;

	if (ldns_resolver_send_pkt(&r_pkt, res, u_pkt) != LDNS_STATUS_OK)
		goto cleanup;
	ldns_pkt_free(u_pkt);
	if (!r_pkt)
		goto cleanup;

	if (ldns_pkt_rcode(r_pkt) != 0) {
		ldns_lookup_table *t = 
		    ldns_lookup_by_id(ldns_rcodes,
			(int)ldns_pkt_rcode(r_pkt));
		if (t)
			dprintf(";; UPDATE response was %s\n", t->name);
		else
			dprintf(";; UPDATE response was (%d)\n",
			    ldns_pkt_rcode(r_pkt));
		status = LDNS_STATUS_ERR;
	}
	ldns_pkt_free(r_pkt);
	ldns_resolver_deep_free(res);
	return status;
		
  cleanup:
	if (res)
		ldns_resolver_deep_free(res);
	if (u_pkt)
		ldns_pkt_free(u_pkt);
	return LDNS_STATUS_ERR;
}

bool
ldns_nsec_type_check(ldns_rr *nsec, ldns_rr_type t)
{
	/* does the nsec cover the t given? */
	/* copied from host2str.c line 465: ldns_rdf2buffer_str_nsec */
        uint8_t window_block_nr;
        uint8_t bitmap_length;
        uint16_t type;
        uint16_t pos = 0;
        uint16_t bit_pos;
	ldns_rdf *nsec_type_list = ldns_rr_rdf(nsec, 1); 
	uint8_t *data = ldns_rdf_data(nsec_type_list);

	while(pos < ldns_rdf_size(nsec_type_list)) {
		window_block_nr = data[pos];
		bitmap_length = data[pos+1];
		pos += 2;

		for (bit_pos = 0; bit_pos < (bitmap_length) * 8; bit_pos++) {
			if (ldns_get_bit(&data[pos], bit_pos)) {
				type = 256 * (uint16_t) window_block_nr + bit_pos;

				if ((ldns_rr_type)type == t) {
					/* we have a winner */
					return true;
				}
			}
		}
		pos += (uint16_t) bitmap_length;
	}
	return false;
}

void
ldns_print_rr_rdf(FILE *fp, ldns_rr *r, int rdfnum, ...)
{
	int16_t rdf;
	ldns_rdf *rd;
	va_list va_rdf;
	va_start(va_rdf, rdfnum);

	for(rdf = (int16_t)rdfnum; rdf != -1; rdf = (int16_t)va_arg(va_rdf, int)) {

		rd = ldns_rr_rdf(r, rdf);
		if (!rd) {
			continue;
		} else {
			ldns_rdf_print(fp, rd);
			fprintf(fp, " "); /* not sure if we want to do this */
		}
	}
	va_end(va_rdf);
}
