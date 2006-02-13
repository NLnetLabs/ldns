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
			ds = ldns_key_rr2ds(ldns_rr_list_rr(keys, i), LDNS_SHA1);
			if (ds) {
				printf("; ");
				ldns_rr_print(stdout, ds);
				printf("\n");
			}
		}
	}
}

/* print some of the elements of a signature */
void
print_rrsig_abbr(FILE *fp, ldns_rr *sig) {
	ldns_lookup_table *lt;
	if (!sig) {
		return;
	}

	if (ldns_rr_get_type(sig) != LDNS_RR_TYPE_RRSIG) {
		return;
	}

	ldns_rdf_print(fp, ldns_rr_owner(sig));
	fprintf(fp, " %d", (int)ldns_rr_ttl(sig));

        lt = ldns_lookup_by_id(ldns_rr_classes, ldns_rr_get_class(sig));
        if (lt) {
               	fprintf(fp, " %s", lt->name);
        } else {
        	fprintf(fp, " CLASS%d", ldns_rr_get_class(sig));
        }
	fprintf(fp, " RRSIG ");

	/* print a number of rdf's */
	/* typecovered */
	ldns_rdf_print(fp, ldns_rr_rdf(sig, 0)); fprintf(fp, " ");
	/* algo */
	ldns_rdf_print(fp, ldns_rr_rdf(sig, 1)); fprintf(fp, " ");
	/* labels */
	ldns_rdf_print(fp, ldns_rr_rdf(sig, 2)); fprintf(fp, " ");
	/* expir */
	ldns_rdf_print(fp, ldns_rr_rdf(sig, 4)); fprintf(fp, " ");
	/* incep */	
	ldns_rdf_print(fp, ldns_rr_rdf(sig, 5)); fprintf(fp, " ");
	/* key-id */	
	ldns_rdf_print(fp, ldns_rr_rdf(sig, 6)); fprintf(fp, " ");
	/* key owner */
	ldns_rdf_print(fp, ldns_rr_rdf(sig, 7)); fprintf(fp, "\n");
}

void
print_rrsig_list_abbr(FILE *fp, ldns_rr_list *sig)
{
	size_t i;

	for(i = 0; i < ldns_rr_list_rr_count(sig); i++) {
		print_rrsig_abbr(fp, ldns_rr_list_rr(sig, i));
	}
}

void
print_dnskey_abbr(FILE *fp, ldns_rr *key)
{
	ldns_lookup_table *lt;
        if (!key) {
                return;
        }

        if (ldns_rr_get_type(key) != LDNS_RR_TYPE_DNSKEY) {
                return;
        }

        ldns_rdf_print(fp, ldns_rr_owner(key));
        fprintf(fp, " %d", (int)ldns_rr_ttl(key));

        lt = ldns_lookup_by_id(ldns_rr_classes, ldns_rr_get_class(key));
        if (lt) {
                fprintf(fp, " %s", lt->name);
        } else {
                fprintf(fp, " CLASS%d", ldns_rr_get_class(key));
        }
        fprintf(fp, " DNSKEY ");

        /* print a number of rdf's */
        /* flags */
        ldns_rdf_print(fp, ldns_rr_rdf(key, 0)); fprintf(fp, " ");
        /* proto */
        ldns_rdf_print(fp, ldns_rr_rdf(key, 1)); fprintf(fp, " ");
        /* algo */
        ldns_rdf_print(fp, ldns_rr_rdf(key, 2));

	if (ldns_rdf2native_int16(ldns_rr_rdf(key, 0)) == 256) {
		fprintf(fp, " ;{id = %d (zsk), size = %db}", (int)ldns_calc_keytag(key),
				(int)ldns_rr_dnskey_key_size(key));
		return;
	}
	if (ldns_rdf2native_int16(ldns_rr_rdf(key, 0)) == 257) {
		fprintf(fp, " ;{id = %d (ksk), size = %db}", (int)ldns_calc_keytag(key),
				(int)ldns_rr_dnskey_key_size(key));
		return;
	}
	fprintf(fp, " ;{id = %d, size = %db}", (int)ldns_calc_keytag(key),
			(int)ldns_rr_dnskey_key_size(key));
}

void
print_dnskey_list_abbr(FILE *fp, ldns_rr_list *key)
{
	size_t i;

	for(i = 0; i < ldns_rr_list_rr_count(key); i++) {
		print_dnskey_abbr(fp, ldns_rr_list_rr(key, i));
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
