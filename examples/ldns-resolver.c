#include "config.h"

#include <ldns/dns.h>

int
main(int argc, char **argv) {

	ldns_resolver *r = NULL;
	int line;
	FILE *rand;

	if (!(rand = fopen(argv[1], "r"))) {
		exit(EXIT_FAILURE);
	}

	printf("Trying to read from /dev/urandom\n");
	r = ldns_resolver_new_frm_fp_l(rand, &line);
	if (!r) {
		printf("Failure\n");
	} else {
		printf("Succes\n");
		ldns_resolver_print(stdout, r);
	}

	fclose(rand);

}
