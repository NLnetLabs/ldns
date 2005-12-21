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
	char *filename;
	FILE *fp;
	ldns_zone *z = NULL;
	int line_nr = 0;
	int c;
	bool sort = false;
	char *progname;

	progname = strdup(argv[0]);

        while ((c = getopt(argc, argv, "z")) != -1) {
                switch(c) {
                        case 'z':
                                sort = true;
                                break;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 1) {
		printf("Usage: %s [-z] <zonefile>\n", progname);
		printf("\tReads the zonefile and prints it.\n");
		printf("\tThe RR count of the zone is printed to stderr.\n");
		printf("\tIf -z is given the zone is sorted.\n");
		exit(EXIT_FAILURE);
	}
	
	filename = argv[0];

	fp = fopen(filename, "r");
	if (!fp) {
		fprintf(stderr, "Unable to open %s: %s\n", filename, strerror(errno));
		exit(EXIT_FAILURE);
	}
	
	z = ldns_zone_new_frm_fp_l(fp, NULL, 0, LDNS_RR_CLASS_IN, &line_nr);

	if (z) {
		if (sort) {
			ldns_zone_sort(z);
		}
		fprintf(stderr, "%d\n", ldns_rr_list_rr_count(ldns_zone_rrs(z)) + 1);
		ldns_zone_print(stdout, z);
		ldns_zone_deep_free(z);
	} else {
		fprintf(stderr, "Syntax error at %d\n", line_nr);
	}
	fclose(fp);
	
        exit(EXIT_SUCCESS);
}
