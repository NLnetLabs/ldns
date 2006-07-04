/*
 * read a zone file from disk and prints it, one RR per line
 *
 * See the file LICENSE for the license
 */

#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>

#include <ldns/ldns.h>

#include <errno.h>

int
main(int argc, char **argv)
{
	char *filename;
	FILE *fp;
	ldns_zone *z;
	int line_nr = 0;
	int c;
	bool sort = false;
	ldns_status s;

        while ((c = getopt(argc, argv, "hzv")) != -1) {
                switch(c) {
                        case 'z':
                                sort = true;
                                break;
			case 'v':
				printf("read zone version %s (ldns version %s)\n", LDNS_VERSION, ldns_version());
				exit(EXIT_SUCCESS);
				break;
			case 'h':
				printf("Usage: %s [-z] [-v] <zonefile>\n", argv[0]);
				printf("\tReads the zonefile and prints it.\n");
				printf("\tThe RR count of the zone is printed to stderr.\n");
				printf("\tIf -z is given the zone is sorted.\n");
				printf("\t-v shows the version and exits\n");
				printf("\nif now file is given standard input is read\n");
				exit(EXIT_SUCCESS);
		}
	}

	argc -= optind;
	argv += optind;

	if (argc == 0) {
		fp = stdin;
	} else {
		filename = argv[0];

		fp = fopen(filename, "r");
		if (!fp) {
			fprintf(stderr, "Unable to open %s: %s\n", filename, strerror(errno));
			exit(EXIT_FAILURE);
		}
	}
	
	s = ldns_zone_new_frm_fp_l(&z, fp, NULL, 0, LDNS_RR_CLASS_IN, &line_nr);
	if (s == LDNS_STATUS_OK) {
		if (sort) {
			ldns_zone_sort(z);
		}
		ldns_zone_print(stdout, z);
		ldns_zone_deep_free(z);
	} else {
		fprintf(stderr, "%s at %d\n", 
				ldns_get_errorstr_by_id(s),
				line_nr);
	}
	fclose(fp);

        exit(EXIT_SUCCESS);
}
