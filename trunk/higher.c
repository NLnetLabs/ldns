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

#include <config.h>
#include <openssl/ssl.h>
#include <openssl/sha.h>
#include <ldns/higher.h>
#include <ldns/parse.h>
#include <ldns/resolver.h>

#include "util.h"

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
	}

	pkt = ldns_resolver_query(res, name, LDNS_RR_TYPE_A, c, flags | LDNS_RD);
	if (pkt) {
		/* extract the data we need */
		a = ldns_pkt_rr_list_by_type(pkt, 
				LDNS_RR_TYPE_A, LDNS_SECTION_ANSWER);
	}
	result = ldns_rr_list_cat(aaaa, a);
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

ldns_rr_list *
ldns_get_rr_list_hosts_frm_fp(FILE *fp)
{
	ssize_t i;
	char *word;


	for(
			i = ldns_fget_token(fp, word, LDNS_PARSE_NORMAL, 0);
			i > 0;
			i = ldns_fget_token(fp, word, LDNS_PARSE_NORMAL, 0)
	) {
		/* # is comment */
		if (word[0] == '#') {
			printf("comment\n");
			continue;
		}
		
		fprintf(stderr, "%d [%s]\n",i ,word);
	}


}


ldns_rr_list *
ldns_get_rr_list_hosts_frm_file(char *filename)
{
	ldns_rr_list *names;
	FILE *fp;

	if (!filename) {
                fp = fopen(RESOLV_HOSTS, "r");
        
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
