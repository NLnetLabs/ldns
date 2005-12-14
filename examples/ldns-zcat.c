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
	char *progname;

	progname = strdup(argv[0]);
	
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

        exit(EXIT_SUCCESS);
}
