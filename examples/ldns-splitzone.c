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
		fprintf(f, "-n NUMBER\tSplit after this many names\n");
		fprintf(f, "-o ORIGIN\tUse this as initial origin. For zones starting with @\n");
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
	int splitting;
	size_t file_counter;
	char filename[255];
	ldns_rdf *origin = NULL;

	progname = strdup(argv[0]);
	split = 0;
	splitting = 0; /* when true we are about to split */
	file_counter = 1;
	lastname = NULL;

	while ((c = getopt(argc, argv, "n:o:")) != -1) {
		switch(c) {
			case 'n':
				split = (size_t)atoi(optarg);
				if (split == 0) {
					printf("Need a number\n");
					exit(EXIT_FAILURE);
				}
				break;
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
	if (split == 0) {
		split = DEFAULT_SPLIT;
	}
	
	argc -= optind;
	argv += optind;

	if (argc < 1) {
		usage(stdout, progname);
		exit(EXIT_SUCCESS);
	}

	if (!(fp = fopen(argv[0], "r"))) {
		fprintf(stderr, "Unable to open %s: %s\n", argv[0], strerror(errno));
		exit(EXIT_FAILURE);
	}
	/* suck in the entire zone ... */
	if (!origin) {
		printf("Warning no origin is given I'm using . now\n");
		origin = ldns_dname_new_frm_str(".");
	}
	
	z = ldns_zone_new_frm_fp_l(fp, origin, 0, LDNS_RR_CLASS_IN, &line_nr);
	fclose(fp);

	if (!z) {
		printf("Zone could not be parsed\n");
		exit(EXIT_FAILURE);
	}
	ldns_zone_sort(z);

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

#if 0
		if (i > 0 && (i % split) == 0) {
			printf("%d %d\n", i, (i & split));
			splitting = 1;
		}

		if (splitting == 1 && 
				ldns_dname_compare(ldns_rr_owner(ldns_rr_list_rr(zrrs, i)), lastname) == 0) {
			/* equal names, don't split yet */
		} else {
			/* now we are ready to split */
			splitting = 2;
		}
		if (splitting == 2) {
			/* SPLIT */
			printf("LDNS INTENT TO SPLIT !!!! \n");
			lastname = NULL;
			continue;
		}
		
		lastname = ldns_rr_owner(ldns_rr_list_rr(zrrs, i));
#endif
	}
/*	fclose(fp); */

	
        exit(EXIT_SUCCESS);
}
