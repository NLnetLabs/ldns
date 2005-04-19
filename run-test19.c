/*
 * mx is a small programs that prints out the mx records
 * for a particulary domain
 */

#include <stdio.h>
#include <config.h>
#include <ldns/ldns.h>

int
usage(FILE *fp, char *prog) {
	fprintf(fp, "%s keygen\n", prog);
	fprintf(fp, "  generate a DNSKEY RR \n");
	return 0;
}

int
main()
{
	ldns_resolver *r;
	ldns_rdf *aaaa;

	r = ldns_resolver_new_frm_file(NULL);
	if (!r) {
		printf("something wrong?\n");
	}

	aaaa = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_AAAA, "::0");
	ldns_rdf_print(stdout, aaaa);
	printf("\n\n");

	ldns_resolver_print(stdout, r);
	return 0;
}
