/*
 * read a zone from disk and split it up:
 *
 * zone: SOA a b c d e f g h i j k l 
 * becomes:
 * zone1: SOA a b c d e f
 * zone2: SOA f g h i k l
 *
 * ldns-catzone removes the last name and put
 * the zone back together.
 *
 * This way you can incremental sign a zone
 *
 * See the file LICENSE for the license
 */

#include "config.h"
#include <errno.h>
#include <ldns/dns.h>

#define FIRST_ZONE 	0
#define MIDDLE_ZONE 	1
#define LAST_ZONE 	2

void
usage(FILE *f, char *progname)
{
		fprintf(f, "Usage: %s [OPTIONS] <zonefile>\n", progname);
		fprintf(f, "\tThe generate zone file is printed to stdout\n");
		fprintf(f, "\tDNSKEYs found in subsequent zones are removed.\n");
		fprintf(f, "-o ORIGIN\tUse this as initial origin. For zones starting with @\n");
}

int
main(int argc, char **argv)
{
	char *progname;
	FILE *fp;
	int c;
	ldns_rdf *origin;
	size_t i, j;
	int where;
	ldns_zone *z;
	ldns_rr_list *zrr;
	ldns_rr *current_rr;
	ldns_rr_list *lastname;

	progname = strdup(argv[0]);
	origin = NULL;
	
	while ((c = getopt(argc, argv, "n:o:")) != -1) {
		switch(c) {
			case 'o':
				origin = ldns_dname_new_frm_str(strdup(optarg));
				if (!origin) {
					printf("cannot convert to dname\n");
					exit(EXIT_FAILURE);
				}
				break;
			default:
				printf("Unrecognized option\n");
				usage(stdout, progname);
				exit(EXIT_FAILURE);
		}
	}
	
	argc -= optind;
	argv += optind;

	if (argc < 1) {
		usage(stdout, progname);
		exit(EXIT_SUCCESS);
	}
	
	for (i = 0; i < argc; i++) {
		
		if (0 == i) {
			where = FIRST_ZONE;
		} else if ((argc - 1) == i) {
			where = LAST_ZONE;
		} else {
			where = MIDDLE_ZONE;
		}
		if (!(fp = fopen(argv[i], "r"))) {
			printf("Cannot open file\n");
			exit(EXIT_FAILURE);
		}
		
		if (!(z = ldns_zone_new_frm_fp(fp, origin, 0, 0))) {
			printf("cannot parse the zone\n");
			exit(EXIT_FAILURE);
		}

		zrr = ldns_zone_rrs(z);

		printf("** READING %s\n", argv[i]);

		for (j = 0; j < ldns_rr_list_rr_count(zrr); j++) {

			current_rr = ldns_rr_list_rr(zrr, j);
		
			switch(where) {
				case FIRST_ZONE:
					/* remove the last RRs with the same name */
					break;
				case MIDDLE_ZONE:
					if (ldns_rr_get_type(current_rr) ==
							LDNS_RR_TYPE_SOA) {
						/* skip this */
						continue;
					}
					
					/* remove 
					 * SOA + SOA sig
					 * KEY + sig KEYs
					 * remove the last RRs with the same name */
					break;
				case LAST_ZONE:
					if (ldns_rr_get_type(current_rr) ==
							LDNS_RR_TYPE_SOA) {
						/* skip this */
						continue;
					}
					/* remove
					 * SOA + SOA sig
					 * KEY + sig KEYS
					 * DONT remove the last record */
					break;
			}
			ldns_rr_print(stdout, current_rr);
		}
	}
        exit(EXIT_SUCCESS);
}
