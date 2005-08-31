/*
 * mx is a small programs that prints out the mx records
 * for a particulary domain
 * (c) NLnet Labs, 2005
 * Licensed under the GPL version 2
 */

#include <ldns/config.h>
#include <errno.h>

#include <time.h>

#include <ldns/dns.h>

#define DATE_FORMAT "%Y%m%d%H%M%S"
#define SHORT_DATE_FORMAT "%Y%m%d"

void
usage(FILE *fp, const char *prog) {
	fprintf(fp, "%s [OPTIONS] <zonefile> <keyfile(s)>\n", prog);
	fprintf(fp, "  signs the zone with the given private key\n");
	fprintf(fp, "  -e <date>\t\texpiration date\n");
	fprintf(fp, "  -i <date>\t\tinception date\n");
	fprintf(fp, "  -k <keyfile>\t\tkey signing key\n");
	fprintf(fp, "\t\t\tdates can be in YYYYMMDD[HHmmSS] format or timestamps\n");
	fprintf(fp, "  -o <domain>\t\torigin for the zone\n");
	fprintf(fp, "keys and keysigning keys (-k option) can be given multiple times\n");
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

	FILE *keyfile = NULL;
	ldns_key *key = NULL;
	ldns_key_list *keys;


	/* we need to know the origin before reading ksk's,
	 * so keep an array of filenames until we know it
	 */
	int key_signing_key_nr = 0;
	char **key_signing_key_filenames = NULL;
	ldns_key_list *key_signing_keys;
	
	struct tm tm;
	uint32_t inception;
	uint32_t expiration;

	ldns_rdf *origin = NULL;

	uint16_t ttl = 0;
	ldns_rr_class class = LDNS_RR_CLASS_IN;	

	ldns_zone *signed_zone = NULL;
	
	int line_nr = 0;
	char c;
	
	const char *prog = argv[0];
	
	inception = 0;
	expiration = 0;
	
	while ((c = getopt(argc, argv, "e:i:k:o:")) != -1) {
		switch (c) {
		case 'e':
			/* try to parse YYYYMMDD first,
			 * if that doesn't work, it
			 * should be a timestamp (seconds since epoch)
			 */
			memset(&tm, 0, sizeof(tm));

			if ((char *)strptime(optarg, DATE_FORMAT, &tm) != NULL) {
				expiration = (uint32_t) timegm(&tm);
			} else if ((char *)strptime(optarg, SHORT_DATE_FORMAT, &tm) != NULL) {
				expiration = (uint32_t) timegm(&tm);
			} else {
				expiration = atol(optarg);
			}
			break;
		case 'i':
			memset(&tm, 0, sizeof(tm));

			if ((char *)strptime(optarg, DATE_FORMAT, &tm) != NULL) {
				inception = (uint32_t) timegm(&tm);
			} else if ((char *)strptime(optarg, SHORT_DATE_FORMAT, &tm) != NULL) {
				inception = (uint32_t) timegm(&tm);
			} else {
				inception = atol(optarg);
			}
			break;
		case 'k':
			key_signing_key_filenames = LDNS_XREALLOC(key_signing_key_filenames, char *, key_signing_key_nr + 1);
			if (!key_signing_key_filenames) {
				fprintf(stderr, "Out of memory\n");
			}
			key_signing_key_filenames[key_signing_key_nr] = optarg;
			key_signing_key_nr++;
			break;
		case 'o':
			if (ldns_str2rdf_dname(&origin, optarg) != LDNS_STATUS_OK) {
				fprintf(stderr, "Bad origin, not a correct domain name\n");
				usage(stderr, prog);
				exit(EXIT_FAILURE);
			}
			
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
			fprintf(stderr, "Zone not read, parse error at %s line %u\n", zonefile_name, line_nr);
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
		keyfile = fopen(argv[argi], "r");
		if (!keyfile) {
			fprintf(stderr, "Error: unable to read k%s (%s)\n", argv[argi], strerror(errno));
		} else {
			key = ldns_key_new_frm_fp(keyfile);
			if (key) {
				/* TODO: should this be in frm_fp? */
				ldns_key_set_pubkey_owner(key, ldns_rdf_clone(origin));

				/* set times in key? they will end up
				   in the rrsigs
				*/
				if (expiration != 0) {
					ldns_key_set_expiration(key, expiration);
				}
				if (inception != 0) {
					ldns_key_set_inception(key, inception);
				}

				ldns_key_list_push_key(keys, key);
				
			} else {
				fprintf(stderr, "Error reading key from %s\n", argv[argi]);
			}
			fclose(keyfile);
		}
		argi++;
	}
	
	if (ldns_key_list_key_count(keys) < 1) {
		fprintf(stderr, "Error: no keys to sign with. Aborting.\n\n");
		usage(stderr, prog);
		exit(EXIT_FAILURE);
	}
			
	/* read the KSKs */
	key_signing_keys = ldns_key_list_new();

	for (argi = 0; argi < key_signing_key_nr; argi++) {
		keyfile = fopen(key_signing_key_filenames[argi], "r");
		if (!keyfile) {
			fprintf(stderr, "Error: unable to read KSK %s (%s)\n", argv[argi], strerror(errno));
		} else {
			key = ldns_key_new_frm_fp(keyfile);
			if (key) {
				/* TODO: should this be in frm_fp? */
				ldns_key_set_pubkey_owner(key, ldns_rdf_clone(origin));

				/* set times in key? they will end up
				   in the rrsigs
				*/
				if (expiration != 0) {
					ldns_key_set_expiration(key, expiration);
				}
				if (inception != 0) {
					ldns_key_set_inception(key, inception);
				}

				ldns_key_list_push_key(key_signing_keys, key);
			} else {
				fprintf(stderr, "Error reading KSK from %s\n", argv[argi]);
			}
			fclose(keyfile);
		}
	}

	signed_zone = ldns_zone_sign(orig_zone, keys, key_signing_keys);
	
	if (signed_zone) {
		ldns_zone_print(stdout, signed_zone);
		ldns_zone_deep_free(signed_zone); 
	} else {
		fprintf(stderr, "Error signing zone.");
		exit(EXIT_FAILURE);
	}
	
	ldns_key_list_free(keys);
	ldns_key_list_free(key_signing_keys);
	ldns_zone_deep_free(orig_zone);
	
	LDNS_FREE(key_signing_key_filenames);
        exit(EXIT_SUCCESS);
}
