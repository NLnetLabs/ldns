#include "config.h"

#include <ldns/dns.h>

int
main(int argc, char **argv) {

	ldns_resolver *r;
	int line;
	FILE *rand;
	ldns_status s;

	if (!(rand = fopen(argv[1], "r"))) {
		exit(EXIT_FAILURE);
	}

	printf("Trying to read from /dev/urandom\n");
	s = ldns_resolver_new_frm_fp_l(&r, rand, &line);
	if (s != LDNS_STATUS_OK) {
		printf("Failure\n");
	} else {
		printf("Succes\n");
		ldns_resolver_print(stdout, r);
	}

	fclose(rand);

	return EXIT_SUCCESS;
}
