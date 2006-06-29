/*
 * ldns-resolver tries to create a resolver structure from /dev/urandom
 * this is only useful to test the library for robusteness with input data
 *
 * (c) NLnet Labs 2006
 * See the file LICENSE for the license
 */

#include "config.h"

#include <ldns/dns.h>

int
main(int argc, char **argv) {

	ldns_resolver *r;
	int line;
	FILE *rand;
	ldns_status s;

	if (argc < 2) {
		printf("Usage: ldns-resolver <file>\n");
		exit(EXIT_FAILURE);
	}
	
	if (!(rand = fopen(argv[1], "r"))) {
		exit(EXIT_FAILURE);
	}

	printf("Trying to read from %s\n", argv[1]);
	s = ldns_resolver_new_frm_fp_l(&r, rand, &line);
	if (s != LDNS_STATUS_OK) {
		printf("Failure\n");
	} else {
		printf("Succes\n");
		ldns_resolver_print(stdout, r);
		ldns_resolver_deep_free(r);
	}

	fclose(rand);

	return EXIT_SUCCESS;
}
