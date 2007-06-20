/*
 * read a zone file from disk and prints it, one RR per line
 *
 * See the file LICENSE for the license
 */

#include "config.h"
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
	bool canonicalize = false;
	bool sort = false;
	bool strip = false;
	ldns_status s;
	size_t i;
	ldns_rr_list *stripped_list;
	ldns_rr *cur_rr;

        while ((c = getopt(argc, argv, "chsvz")) != -1) {
                switch(c) {
                	case 'c':
                		canonicalize = true;
                		break;
			case 'h':
				printf("Usage: %s [-c] [-v] [-z] <zonefile>\n", argv[0]);
				printf("\tReads the zonefile and prints it.\n");
				printf("\tThe RR count of the zone is printed to stderr.\n");
				printf("\t-c canonicalize all rrs in the zone.\n");
				printf("\t-h show this text\n");
				printf("\t-s strip DNSSEC data from the zone\n");
				printf("\t-v shows the version and exits\n");
				printf("\t-z sort the zone (implies -c).\n");
				printf("\nif no file is given standard input is read\n");
				exit(EXIT_SUCCESS);
				break;
                        case 's':
                        	strip = true;
                        	break;
			case 'v':
				printf("read zone version %s (ldns version %s)\n", LDNS_VERSION, ldns_version());
				exit(EXIT_SUCCESS);
				break;
                        case 'z':
                		canonicalize = true;
                                sort = true;
                                break;
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

	if (strip) {
		stripped_list = ldns_rr_list_new();
		while ((cur_rr = ldns_rr_list_pop_rr(ldns_zone_rrs(z)))) {
			if (ldns_rr_get_type(cur_rr) == LDNS_RR_TYPE_RRSIG ||
			    ldns_rr_get_type(cur_rr) == LDNS_RR_TYPE_NSEC
			   ) {
			   	
			   	printf("remove:\n");
			   	ldns_rr_print(stdout, cur_rr);
				
				ldns_rr_free(cur_rr);
			} else {
				ldns_rr_list_push_rr(stripped_list, cur_rr);
			}
		}
		ldns_rr_list_free(ldns_zone_rrs(z));
		ldns_zone_set_rrs(z, stripped_list);
	}

	if (s == LDNS_STATUS_OK) {
		if (canonicalize) {
			ldns_rr2canonical(ldns_zone_soa(z));
			for (i = 0; i < ldns_rr_list_rr_count(ldns_zone_rrs(z)); i++) {
				ldns_rr2canonical(ldns_rr_list_rr(ldns_zone_rrs(z), i));
			}
		}
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
