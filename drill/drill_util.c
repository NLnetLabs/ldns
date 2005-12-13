/*
 * util.c
 * some handy function needed in drill and not implemented
 * in ldns
 * (c) 2005 NLnet Labs
 *
 * See the file LICENSE for the license
 *
 */

#include "drill.h"
#include <ldns/dns.h>

/* lnds_rr_new_frm_fp?? */
ldns_rr *
read_key_file(const char *filename)
{
	FILE *fp;
	char line[LDNS_MAX_PACKETLEN];
	int c;
	size_t i = 0;
	
	fp = fopen(filename, "r");
	if (!fp) {
		fprintf(stderr, "Unable to open %s: ", filename);
		perror("");
		return NULL;
	}
	
	while ((c = fgetc(fp)) && i < LDNS_MAX_PACKETLEN && c != EOF) {
		line[i] = c;
		i++;
	}
	line[i] = '\0';
	
	fclose(fp);
	
	if (i <= 0) {
		return NULL;
	} else {
		return ldns_rr_new_frm_str(line, 0, NULL, NULL);
	}
}

ldns_rdf *
ldns_rdf_new_addr_frm_str(char *str)
{
	ldns_rdf *a;

	a = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, str);
	if (!a) {
		/* maybe ip6 */
		a = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_AAAA, str);
		if (!a) {
			return NULL;
		}
	}
	return a;
}

/*
 * For all keys in a packet print the DS 
 */
void
print_ds_of_keys(ldns_pkt *p)
{
	ldns_rr_list *keys;
	uint16_t i;
	ldns_rr *ds;

	/* TODO fix the section stuff, here or in ldns */
	keys = ldns_pkt_rr_list_by_type(p, LDNS_RR_TYPE_DNSKEY, 
			LDNS_SECTION_ANSWER);

	/* this also returns the question section rr, which does not
	 * have any data.... and this inturn crashes everything */

	if (keys) {
		for (i = 0; i < ldns_rr_list_rr_count(keys); i++) {
			ds = ldns_key_rr2ds(ldns_rr_list_rr(keys, i));
			if (ds) {
				printf("; ");
				ldns_rr_print(stdout, ds);
				printf("\n");
			}
		}
	}
}

void *
xmalloc(size_t s)
{
	void *p;

	p = malloc(s);
	if (!p) {
		printf("Mem failure\n");
		exit(EXIT_FAILURE);
	}
	return p;
}

void *
xrealloc(void *p, size_t size)
{
	void *q;

	q = realloc(p, size);
	if (!q) {
		printf("Mem failure\n");
		exit(EXIT_FAILURE);
	}
	return q;
}

void
xfree(void *p)
{
	if (p) {
	        free(p);
	}
}
