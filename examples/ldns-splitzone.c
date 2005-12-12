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

#define DEFAULT_SPLIT 	1000
#define FILE_SIZE 	255

void
usage(FILE *f, char *progname)
{
		fprintf(f, "Usage: %s [OPTIONS] <zonefile>\n", progname);
		fprintf(f, "\tSplit a zone file up.\n");
		fprintf(f, "\nOPTIONS:\n");
		fprintf(f, "-n = NUMBER\tSplit after this many names\n");
}

int
main(int argc, char **argv)
{
	char *progname;
	FILE *fp;
	ldns_zone *z;
	ldns_rr_list *zrrs;
	ldns_rdf *lastname;
	int c; 
	int line_nr;
	size_t split;
	size_t i;
	bool splitting;
	size_t file_counter;
	char filename[255];

	progname = strdup(argv[0]);
	split = 0;
	splitting = false; /* when true we are about to split */
	file_counter = 1;

	while ((c = getopt(argc, argv, "n:")) != -1) {
		switch(c) {
			case 'n':
				split = (size_t)atoi(optarg);
				if (split == 0) {
					printf("Need a number\n");
					exit(EXIT_FAILURE);
				}
				break;
			default:
				printf("Unrecognized option\n");
				usage(stdout, progname);
				exit(EXIT_FAILURE);
		}
	}
	if (split == 0) {
		split = DEFAULT_SPLIT;
	}
	
	argc -= optind;
	argv += optind;

	if (argc < 1) {
		usage(stdout, progname);
		exit(EXIT_SUCCESS);
	}

	fp = fopen(argv[0], "r");
	if (!fp) {
		fprintf(stderr, "Unable to open %s: %s\n", argv[0], strerror(errno));
		exit(EXIT_FAILURE);
	}
	
	/* suck in the entire zone ... is this wise... */
	z = ldns_zone_new_frm_fp_l(fp, NULL, 0, LDNS_RR_CLASS_IN, &line_nr);
	fclose(fp);

	if (!z) {
		printf("Zone could not be parsed\n");
		exit(EXIT_FAILURE);
	}

	/* no RRsets may be truncated */
	zrrs = ldns_zone_rrs(z);
	
	/* Setup */
#if 0
	snprintf(filename, FILE_SIZE, "%s.%d", argv[0], file_counter);
	fp = fopen(filename, "w");
	if (!fp) {
		printf("whaahah\n");
		exit(EXIT_FAILURE);
	}
	ldns_rr_print(fp, ldns_zone_soa(z));
#endif

	for(i = 0; i < ldns_rr_list_rr_count(zrrs); i++) {
	
		ldns_rr_print(stdout, 
				ldns_rr_list_rr(zrrs, i));

		lastname = ldns_rr_owner(ldns_rr_list_rr(zrrs, i));

	}
/*	fclose(fp); */

	
        exit(EXIT_SUCCESS);
}
