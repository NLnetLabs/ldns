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
	FILE *f;
	char *tok;
	size_t b;

  	if (!(f = fopen("blaat", "r"))) {
		exit(1);
	}

	tok = XMALLOC(char, 1024);

	while ((b = ldns_get_str(f, tok, true)) != 0) {
		fprintf(stdout, "%d: %s\n", (int)b, tok);
	}
	

	fclose(f);
	return 0;
}
