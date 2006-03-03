/*
 * signzone signs a zone file
 * for a particulary domain
 * (c) NLnet Labs, 2005
 * See the file LICENSE for the license
 */

#include "config.h"
#include <errno.h>

#include <time.h>

#include <ldns/dns.h>

#define MAX_FILENAME_LEN 250

void
usage(FILE *fp, const char *prog) {
	fprintf(fp, "%s [OPTIONS] zonefile key [key [key]]\n", prog);
	fprintf(fp, "  signs the zone with the given key(s)\n");
	fprintf(fp, "  -e <date>\texpiration date\n");
	fprintf(fp, "  -f <file>\toutput zone to file (default <name>.signed)\n");
	fprintf(fp, "  -i <date>\tinception date\n");
	fprintf(fp, "  -o <domain>\torigin for the zone\n");
	fprintf(fp, "  -v\t\tprint version and exit\n");
	fprintf(fp, "  -n\t\tuse NSEC3 instead of NSEC.\n");
	fprintf(fp, "\t\tIf you use NSEC3, you can specify the following extra options:\n");
	fprintf(fp, "\t\t-a [algorithm] hashing algorithm\n");
	fprintf(fp, "\t\t-t [number] number of hash iterations\n");
	fprintf(fp, "\t\t-s [string] salt\n");
	fprintf(fp, "\n");
	fprintf(fp, "  keys must be specified by their base name: K<name>+<alg>+<id>\n");
	fprintf(fp, "  both a .key and .private file must present\n");
	fprintf(fp, "  A date can be a timestamp (seconds since the epoch), or of\n  the form <YYYYMMdd[hhmmss]>\n");
}

void check_tm(struct tm tm)
{
	if (tm.tm_year < 70) {
		fprintf(stderr, "You cannot specify dates before 1970\n");
		exit(EXIT_FAILURE);
	}
	if (tm.tm_mon < 0 || tm.tm_mon > 11) {
		fprintf(stderr, "The month must be in the range 1 to 12\n");
		exit(EXIT_FAILURE);
	}
	if (tm.tm_mday < 1 || tm.tm_mday > 31) {
		fprintf(stderr, "The day must be in the range 1 to 31\n");
		exit(EXIT_FAILURE);
	}
	
	if (tm.tm_hour < 0 || tm.tm_hour > 23) {
		fprintf(stderr, "The hour must be in the range 0-23\n");
		exit(EXIT_FAILURE);
	}

	if (tm.tm_min < 0 || tm.tm_min > 59) {
		fprintf(stderr, "The minute must be in the range 0-59\n");
		exit(EXIT_FAILURE);
	}

	if (tm.tm_sec < 0 || tm.tm_sec > 59) {
		fprintf(stderr, "The second must be in the range 0-59\n");
		exit(EXIT_FAILURE);
	}

}

int
main(int argc, char *argv[])
{
	const char *zonefile_name;
	FILE *zonefile = NULL;
	int argi;

	ldns_zone *orig_zone = NULL;
	ldns_rr_list *orig_rrs = NULL;
	ldns_rr *orig_soa = NULL;

	const char *keyfile_name_base;
	char *keyfile_name;
	FILE *keyfile = NULL;
	ldns_key *key = NULL;
	ldns_rr *pubkey = NULL;
	ldns_key_list *keys;

	uint16_t default_ttl = LDNS_DEFAULT_TTL;

	char *outputfile_name = NULL;
	FILE *outputfile;
	
	bool use_nsec3 = false;
	
	uint8_t nsec3_algorithm = 1;
	uint32_t nsec3_iterations = 1;
	uint8_t nsec3_salt_length = 0;
	char *nsec3_salt = NULL;
	
	/* we need to know the origin before reading ksk's,
	 * so keep an array of filenames until we know it
	 */
	struct tm tm;
	uint32_t inception;
	uint32_t expiration;

	ldns_rdf *origin = NULL;

	uint16_t ttl = 0;
	ldns_rr_class class = LDNS_RR_CLASS_IN;	

	ldns_zone *signed_zone = NULL;
	
	int line_nr = 0;
	int c;
	
	const char *prog = strdup(argv[0]);
	
	inception = 0;
	expiration = 0;
	
	while ((c = getopt(argc, argv, "a:e:f:i:no:v:s:t:")) != -1) {
		switch (c) {
		case 'a':
			nsec3_algorithm = (uint8_t) atoi(optarg);
			break;
		case 'e':
			/* try to parse YYYYMMDD first,
			 * if that doesn't work, it
			 * should be a timestamp (seconds since epoch)
			 */
			memset(&tm, 0, sizeof(tm));

			if (strlen(optarg) == 8 &&
			    sscanf(optarg, "%4d%2d%2d", &tm.tm_year, &tm.tm_mon, &tm.tm_mday)
			   ) {
			   	tm.tm_year -= 1900;
			   	tm.tm_mon--;
			   	check_tm(tm);
				expiration = (uint32_t) mktime_from_utc(&tm);
			} else if (strlen(optarg) == 14 &&
			    sscanf(optarg, "%4d%2d%2d%2d%2d%2d", &tm.tm_year, &tm.tm_mon, &tm.tm_mday, &tm.tm_hour, &tm.tm_min, &tm.tm_sec)
			   ) {
			   	tm.tm_year -= 1900;
			   	tm.tm_mon--;
			   	check_tm(tm);
				expiration = (uint32_t) mktime_from_utc(&tm);
			} else {
				expiration = (uint32_t) atol(optarg);
			}
			break;
		case 'f':
			outputfile_name = LDNS_XMALLOC(char, MAX_FILENAME_LEN);
			strncpy(outputfile_name, optarg, MAX_FILENAME_LEN);
			break;
		case 'i':
			memset(&tm, 0, sizeof(tm));

			if (strlen(optarg) == 8 &&
			    sscanf(optarg, "%4d%2d%2d", &tm.tm_year, &tm.tm_mon, &tm.tm_mday)
			   ) {
			   	tm.tm_year -= 1900;
			   	tm.tm_mon--;
			   	check_tm(tm);
				inception = (uint32_t) mktime_from_utc(&tm);
			} else if (strlen(optarg) == 14 &&
			    sscanf(optarg, "%4d%2d%2d%2d%2d%2d", &tm.tm_year, &tm.tm_mon, &tm.tm_mday, &tm.tm_hour, &tm.tm_min, &tm.tm_sec)
			   ) {
			   	tm.tm_year -= 1900;
			   	tm.tm_mon--;
			   	check_tm(tm);
				inception = (uint32_t) mktime_from_utc(&tm);
			} else {
				inception = (uint32_t) atol(optarg);
			}
			break;
		case 'n':
			use_nsec3 = true;
			break;
		case 'o':
			if (ldns_str2rdf_dname(&origin, optarg) != LDNS_STATUS_OK) {
				fprintf(stderr, "Bad origin, not a correct domain name\n");
				usage(stderr, prog);
				exit(EXIT_FAILURE);
			}
			
			break;
		case 'v':
			printf("zone signer version %s (ldns version %s)\n", LDNS_VERSION, ldns_version());
			exit(EXIT_SUCCESS);
			break;
		case 's':
			nsec3_salt_length = (uint8_t) strlen(optarg);
			nsec3_salt = LDNS_XMALLOC(char, nsec3_salt_length);
			memcpy(nsec3_salt, optarg, nsec3_salt_length);
			break;
		case 't':
			nsec3_iterations = (uint32_t) atoi(optarg);
			break;
		default:
			usage(stderr, prog);
			exit(EXIT_SUCCESS);
		}
	}
	
	argc -= optind;
	argv += optind;

	if (argc < 2) {
		usage(stdout, prog);
		exit(EXIT_FAILURE);
	} else {
		zonefile_name = argv[0];
	}

	/* read zonefile first to find origin if not specified */
	
	zonefile = fopen(zonefile_name, "r");
	
	if (!zonefile) {
		fprintf(stderr, "Error: unable to read %s (%s)\n", zonefile_name, strerror(errno));
		exit(EXIT_FAILURE);
	} else {
		orig_zone = ldns_zone_new_frm_fp_l(zonefile, origin, ttl, class, &line_nr);
		if (!orig_zone) {
			fprintf(stderr, "Zone not read, parse error at %s line %d\n", zonefile_name, line_nr);
			exit(EXIT_FAILURE);
		} else {
			orig_soa = ldns_zone_soa(orig_zone);
			if (!orig_soa) {
				fprintf(stderr, "Error reading zonefile: missing SOA record\n");
				exit(EXIT_FAILURE);
			}
			orig_rrs = ldns_zone_rrs(orig_zone);
			if (!orig_rrs) {
				fprintf(stderr, "Error reading zonefile: no resource records\n");
				exit(EXIT_FAILURE);
			}
		}
		fclose(zonefile);
	}

	if (!origin) {
		/* default to root origin */
		/*origin = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, ".");*/
		origin = ldns_rr_owner(orig_soa);
	}

	keys = ldns_key_list_new();

	/* read the ZSKs */
	argi = 1;
	while (argi < argc) {
		keyfile_name_base = argv[argi];
		keyfile_name = LDNS_XMALLOC(char, strlen(keyfile_name_base) + 9);
		snprintf(keyfile_name, strlen(keyfile_name_base) + 9, "%s.private", keyfile_name_base);
		keyfile = fopen(keyfile_name, "r");
		line_nr = 0;
		if (!keyfile) {
			fprintf(stderr, "Error: unable to read %s: %s\n", keyfile_name, strerror(errno));
		} else {
			key = ldns_key_new_frm_fp_l(keyfile, &line_nr);
			fclose(keyfile);
			if (key) {
				/* set times in key? they will end up
				   in the rrsigs
				*/
				if (expiration != 0) {
					ldns_key_set_expiration(key, expiration);
				}
				if (inception != 0) {
					ldns_key_set_inception(key, inception);
				}

				LDNS_FREE(keyfile_name);
				keyfile_name = LDNS_XMALLOC(char, strlen(keyfile_name_base) + 5);
				snprintf(keyfile_name, strlen(keyfile_name_base) + 5, "%s.key", keyfile_name_base);
				keyfile = fopen(keyfile_name, "r");
				line_nr = 0;
				if (!keyfile) {
					fprintf(stderr, "Error: unable to read %s: %s\n", keyfile_name, strerror(errno));
				} else {
					pubkey = ldns_rr_new_frm_fp_l(keyfile, &default_ttl, NULL, NULL, &line_nr);
					if (pubkey) {
						ldns_key_set_pubkey_owner(key, ldns_rdf_clone(ldns_rr_owner(pubkey)));
						ldns_key_set_flags(key, ldns_rdf2native_int16(ldns_rr_rdf(pubkey, 0)));
					}
					/*ldns_key_set_flags(key, ldns_key_flags(key) | LDNS_KEY_ZONE_KEY);*/
					ldns_key_list_push_key(keys, key);
					ldns_zone_push_rr(orig_zone, ldns_rr_clone(pubkey));
					ldns_rr_free(pubkey);
				}

				
			} else {
				fprintf(stderr, "Error reading key from %s at line %d\n", argv[argi], line_nr);
			}
		}

		argi++;
	}
	
	if (ldns_key_list_key_count(keys) < 1) {
		fprintf(stderr, "Error: no keys to sign with. Aborting.\n\n");
		usage(stderr, prog);
		exit(EXIT_FAILURE);
	}
			
	if (use_nsec3) {
		signed_zone = ldns_zone_sign_nsec3(orig_zone,
		                                   keys,
		                                   nsec3_algorithm,
		                                   nsec3_iterations,
		                                   nsec3_salt_length,
		                                   nsec3_salt);
	} else {
		signed_zone = ldns_zone_sign(orig_zone, keys);
	}
	
	if (!outputfile_name) {
		outputfile_name = LDNS_XMALLOC(char, MAX_FILENAME_LEN);
		snprintf(outputfile_name, MAX_FILENAME_LEN, "%s.signed", zonefile_name);
	}
	
	if (signed_zone) {
		outputfile = fopen(outputfile_name, "w");
		if (!outputfile) {
			fprintf(stderr, "Unable to open %s for writing: %s\n", outputfile_name, strerror(errno));
		} else {
			ldns_zone_print(outputfile, signed_zone);
			fclose(outputfile);
		}
		ldns_zone_deep_free(signed_zone); 
	} else {
		fprintf(stderr, "Error signing zone.");
		exit(EXIT_FAILURE);
	}
	
	ldns_key_list_free(keys);
	ldns_zone_deep_free(orig_zone);
	
	LDNS_FREE(outputfile_name);
        exit(EXIT_SUCCESS);
}
