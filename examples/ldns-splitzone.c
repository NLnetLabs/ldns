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

#define DEFAULT_SPLIT 	500
#define FILE_SIZE 	255
#define SPLIT_MAX 	999 
#define NO_SPLIT 	0
#define INTENT_TO_SPLIT 1
#define SPLIT_NOW	2

void
usage(FILE *f, char *progname)
{
		fprintf(f, "Usage: %s [OPTIONS] <zonefile>\n", progname);
		fprintf(f, "\tSplit a zone file up.\n");
		fprintf(f, "\nOPTIONS:\n");
		fprintf(f, "-n NUMBER\tSplit after this many names\n");
		fprintf(f, "-o ORIGIN\tUse this as initial origin. For zones starting with @\n");
}


FILE *
open_newfile(char *basename, ldns_zone *z, size_t counter)
{
	char filename[FILE_SIZE];
	FILE *fp;

	if (counter > SPLIT_MAX)  {
		printf("maximum splits reached %d\n", counter);
		return NULL;
	}

	snprintf(filename, FILE_SIZE, "%s.%03d", basename, counter);

	if (!(fp = fopen(filename, "w"))) {
		printf("cannot open %s\n", filename);
		return NULL;
	} else {
		printf("Opening %s\n", filename);
	}
	ldns_rr_print(fp, ldns_zone_soa(z));
	return fp;
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
	ldns_rdf *origin = NULL;
	ldns_rdf *current_rdf;
	ldns_rr *current_rr;

	progname = strdup(argv[0]);
	split = 0;
	splitting = NO_SPLIT; 
	file_counter = 0;
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
	/* ldns_zone_sort(z); ASSUME SORTED ZONE */ 

	/* no RRsets may be truncated */
	zrrs = ldns_zone_rrs(z);
	
	/* Setup */
	if (!(fp = open_newfile(argv[0], z, file_counter))) {
			exit(EXIT_FAILURE);
	}

	for(i = 0; i < ldns_rr_list_rr_count(zrrs); i++) {
	
		current_rr = ldns_rr_list_rr(zrrs, i);
		current_rdf = ldns_rr_owner(current_rr);

		if (i > 0 && (i % split) == 0) {
			splitting = INTENT_TO_SPLIT;
		}

		if (splitting == INTENT_TO_SPLIT) { 
			if (ldns_dname_compare(current_rdf, lastname) != 0) {
				splitting = SPLIT_NOW;
			} 
			/* else: do nothing */
		}

		if (splitting == SPLIT_NOW) {
			fclose(fp);

			/* SPLIT */
			lastname = NULL;
			splitting = NO_SPLIT;
			file_counter++;
			if (!(fp = open_newfile(argv[0], z, file_counter))) {
				exit(EXIT_FAILURE);
			}
			ldns_rr_print(fp, current_rr); 
		}

		if (splitting == NO_SPLIT || splitting == INTENT_TO_SPLIT) {
			ldns_rr_print(fp, current_rr);
		}
		lastname = current_rdf;
	}
	fclose(fp); 

        exit(EXIT_SUCCESS);
}
