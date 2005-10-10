/*
 * read a zone file from disk and print it
 *
 * See the file LICENSE for the license
 */

#include "config.h"

#include <errno.h>

#include <ldns/dns.h>


int
main(int argc, char **argv)
{
	ldns_rr *rr;
	char *filename = "";
	FILE *fp;
	ldns_zone *z;
	int line_nr = 0;
	
	if (argc < 2) {
		printf("Usage: %s <zonefile>\n", argv[0]);
		printf("\tReads the zonefile and prints it.\n");
		exit(0);
	}
	
	filename = argv[1];

	fp = fopen(filename, "r");
	if (!fp) {
		fprintf(stderr, "Unable to open %s: %s\n", filename, strerror(errno));
		exit(EXIT_FAILURE);
	}
	
	z = ldns_zone_new_frm_fp_l(fp, NULL, 0, LDNS_RR_CLASS_IN, &line_nr);

	if (z) {
		ldns_zone_print(stdout, z);
		ldns_zone_deep_free(z);
	}
	fclose(fp);
	
        exit(EXIT_SUCCESS);
}
