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

	r = ldns_resolver_new_frm_file(NULL);
	if (!r) {
		printf("something wrong?\n");
	}

	ldns_resolver_print(stdout, r);
	return 0;
}
