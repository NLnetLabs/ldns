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

	while ((b = ldns_get_token(f, tok, LDNS_PARSE_SKIP_SPACE)) != 0) {
		fprintf(stdout, "%d: %s\n", (int)b, tok);
	}
	fclose(f);

  	if (!(f = fopen("Kdnssec.nl.+005+32820.private", "r"))) {
		exit(1);
	}
	
	/* ldns_get_keyword_data(f, "Algorithm", ": \t", tok, LDNS_STR);*/
	if (ldns_get_keyword_data(f, "Private-key-format", 
				":", tok, LDNS_PARSE_SKIP_SPACE) != -1) {
		printf("found it, found it\n");
		printf("%s\n", tok);
	}

	fclose(f);
	return 0;
}
