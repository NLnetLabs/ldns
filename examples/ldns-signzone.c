/*
 * ldns-signzone signs a zone file
 * 
 * (c) NLnet Labs, 2005
 * See the file LICENSE for the license
 */

#include "config.h"
#include <stdlib.h>
#include <unistd.h>

#include <errno.h>

#include <time.h>

#include <ldns/ldns.h>
#include <ldns/keys.h>

#include <openssl/conf.h>
#include <openssl/engine.h>


#define MAX_FILENAME_LEN 250
int verbosity = 0;

void
usage(FILE *fp, const char *prog) {
	fprintf(fp, "%s [OPTIONS] zonefile key [key [key]]\n", prog);
	fprintf(fp, "  signs the zone with the given key(s)\n");
	fprintf(fp, "  -e <date>\texpiration date\n");
	fprintf(fp, "  -f <file>\toutput zone to file (default <name>.signed)\n");
	fprintf(fp, "  -i <date>\tinception date\n");
	fprintf(fp, "  -l\t\tLeave old DNSSEC RRSIGS and NSEC records intact\n");
	fprintf(fp, "  -o <domain>\torigin for the zone\n");
	fprintf(fp, "  -v\t\tprint version and exit\n");
	fprintf(fp, "  -E <name>\tuse <name> as the crypto engine for signing\n");
	fprintf(fp, "           \tThis can have a lot of extra options, see -E help for more info\n");
	fprintf(fp, "  -k <id>,<int>\tuse key id with algorithm int from engine\n");
	fprintf(fp, "  -K <id>,<int>\tuse key id with algorithm int from engine as KSK\n");
	fprintf(fp, "\t\tif no key is given (but an external one is used through the engine support, it might be necessary to provide the right algorithm number.\n");
	fprintf(fp, "  keys must be specified by their base name: K<name>+<alg>+<id>\n");
	fprintf(fp, "  if the public part of the key is not present in the zone, \n");
	fprintf(fp, "  both a .key and .private file must be present\n");
	fprintf(fp, "  A date can be a timestamp (seconds since the epoch), or of\n  the form <YYYYMMdd[hhmmss]>\n");
}

void
usage_openssl(FILE *fp, const char *prog) {
	fprintf(fp, "Special commands for openssl engines:\n");
	fprintf(fp, "-c <file>\tOpenSSL config file\n");
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

void
strip_dnssec_records(ldns_zone *zone)
{
	ldns_rr_list *new_list;
	ldns_rr *cur_rr;
	
	new_list = ldns_rr_list_new();
	
	new_list = ldns_rr_list_new();
	while ((cur_rr = ldns_rr_list_pop_rr(ldns_zone_rrs(zone)))) {
		if (ldns_rr_get_type(cur_rr) == LDNS_RR_TYPE_RRSIG ||
		    ldns_rr_get_type(cur_rr) == LDNS_RR_TYPE_NSEC
		   ) {
			
			ldns_rr_free(cur_rr);
		} else {
			ldns_rr_list_push_rr(new_list, cur_rr);
		}
	}
	ldns_rr_list_free(ldns_zone_rrs(zone));
	ldns_zone_set_rrs(zone, new_list);
}

int
main(int argc, char *argv[])
{
	const char *zonefile_name;
	FILE *zonefile = NULL;
	uint32_t default_ttl = LDNS_DEFAULT_TTL;
	int line_nr = 0;
	int c;
	int argi;
	ENGINE *engine = NULL;

	ldns_zone *orig_zone;
	ldns_rr_list *orig_rrs = NULL;
	ldns_rr *orig_soa = NULL;
	ldns_zone *signed_zone;

	const char *keyfile_name_base;
	char *keyfile_name;
	FILE *keyfile = NULL;
	ldns_key *key = NULL;
	ldns_rr *pubkey, *pubkey_gen;
	ldns_key_list *keys;
	size_t key_i;
	ldns_status s;

	bool leave_old_dnssec_data = false;

	char *outputfile_name = NULL;
	FILE *outputfile;
	
	/* tmp vars for engine keys */
	char *eng_key_l;
	size_t eng_key_id_len;
	char *eng_key_id;
	int eng_key_algo;
	
	/* we need to know the origin before reading ksk's,
	 * so keep an array of filenames until we know it
	 */
	struct tm tm;
	uint32_t inception;
	uint32_t expiration;
	ldns_rdf *origin = NULL;
	uint32_t ttl = 0;
	ldns_rr_class class = LDNS_RR_CLASS_IN;	
	
	char *prog = strdup(argv[0]);
	
	inception = 0;
	expiration = 0;
	
	keys = ldns_key_list_new();

/*	OPENSSL_config(NULL);*/

	while ((c = getopt(argc, argv, "e:f:i:lo:vE:ak:K:")) != -1) {
		switch (c) {
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
		case 'l':
			leave_old_dnssec_data = true;
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
		case 'E':
			if (strncmp("help", optarg, 5) == 0) {
				printf("help\n");
				exit(EXIT_SUCCESS);
			}
			ENGINE_load_openssl();
			ENGINE_load_builtin_engines();
			ENGINE_load_dynamic();
			ENGINE_load_cryptodev();
			engine = ENGINE_by_id(optarg);
			if (!engine) {
				printf("No such engine: %s\n", optarg);
				engine = ENGINE_get_first();
				printf("Available engines:\n");
				while (engine) {
					printf("%s\n", ENGINE_get_id(engine));
					engine = ENGINE_get_next(engine);
				}
				exit(EXIT_FAILURE);
			} else {
				if (!ENGINE_init(engine)) {
					printf("The engine couldn't initialize\n");
					exit(EXIT_FAILURE);
				}
				ENGINE_set_default_RSA(engine);
				ENGINE_set_default_DSA(engine);
				ENGINE_set_default(engine, 0);
			}
			break;
		case 'k':
			eng_key_l = index(optarg, ',');
			if (eng_key_l && strlen(eng_key_l) > 1) {
				if (eng_key_l > optarg) {
					eng_key_id_len = (size_t) (eng_key_l - optarg);
					eng_key_id = malloc(eng_key_id_len + 1);
					memcpy(eng_key_id, optarg, eng_key_id_len);
					eng_key_id[eng_key_id_len] = '\0';
				} else {
					/* no id given, use default from engine */
					eng_key_id = NULL;
				}
				
				eng_key_algo = atoi(eng_key_l + 1);

				printf("Engine key id: %s, algo %d\n", eng_key_id, eng_key_algo);
				
				if (expiration != 0) {
					ldns_key_set_expiration(key, expiration);
				}
				if (inception != 0) {
					ldns_key_set_inception(key, inception);
				}

				s = ldns_key_new_frm_engine(&key, engine, eng_key_id, eng_key_algo);
				if (s == LDNS_STATUS_OK) {
					ldns_key_list_push_key(keys, key);
					/*printf("Added key at %p:\n", key);*/
					/*ldns_key_print(stdout, key);*/
				} else {
					printf("Error reading key '%s' from engine: %s\n", eng_key_id, ldns_get_errorstr_by_id(s));
					printf("The available key id's are:\n");
					printf("TODO\n");
					exit(EXIT_FAILURE);
				}
				
				if (eng_key_id) {
					free(eng_key_id);
				}
			} else {
				printf("Error: bad engine key specification (should be: -k <id>,<algorithm>)).\n");
				exit(EXIT_FAILURE);
			}
			
			break;
		case 'K':
			printf("Not implemented yet\n");
			exit(EXIT_FAILURE);
			break;
		default:
			usage(stderr, prog);
			exit(EXIT_SUCCESS);
		}
	}
	
	argc -= optind;
	argv += optind;

	if (argc < 1) {
		printf("Error: not enough arguments\n");
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
		s = ldns_zone_new_frm_fp_l(&orig_zone, zonefile, origin, ttl, class, &line_nr);
		if (s != LDNS_STATUS_OK) {
			fprintf(stderr, "Zone not read, error: %s at %s line %d\n", 
					ldns_get_errorstr_by_id(s), 
					zonefile_name, line_nr);
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
		origin = ldns_rr_owner(orig_soa);
	}
	
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
			s = ldns_key_new_frm_fp_l(&key, keyfile, &line_nr);
			fclose(keyfile);
			if (s == LDNS_STATUS_OK) {
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
				
				/* find the public key in the zone, or in a
				 * seperate file
				 * we 'generate' one anyway, then match that to any present in the zone,
				 *  if it matches, we drop our own. If not, we try to see if there
				 * is a .key file present. If not, we use our own generated one, with
				 * some default values */
				
				pubkey_gen = ldns_key2rr(key);
				if (verbosity >= 2) {
					fprintf(stderr, "Looking for key with keytag %u or %u\n", (unsigned int) ldns_calc_keytag(pubkey_gen), (unsigned int)  ldns_calc_keytag(pubkey_gen) + 1);
				}
				for (key_i = 0; key_i < ldns_rr_list_rr_count(orig_rrs); key_i++) {
					pubkey = ldns_rr_list_rr(orig_rrs, key_i);
					if (ldns_rr_get_type(pubkey) == LDNS_RR_TYPE_DNSKEY &&
					    (ldns_calc_keytag(pubkey) == ldns_calc_keytag(pubkey_gen) ||
					     /* KSK has gen-keytag + 1 */
					     ldns_calc_keytag(pubkey) == ldns_calc_keytag(pubkey_gen) + 1) 
					    ) {
						/* found it, drop our own */
						if (verbosity >= 2) {
							fprintf(stderr, "Found it in the zone!\n");
						}
						goto found;
					}
				}
				/* it was not in the zone, try to read a .key file */
				keyfile_name = LDNS_XMALLOC(char, strlen(keyfile_name_base) + 5);
				snprintf(keyfile_name, strlen(keyfile_name_base) + 5, "%s.key", keyfile_name_base);
				if (verbosity >= 2) {
					fprintf(stderr, "Trying to read %s\n", keyfile_name);
				}
				keyfile = fopen(keyfile_name, "r");
				line_nr = 0;
				if (keyfile) {
					if (ldns_rr_new_frm_fp_l(&pubkey, keyfile, &default_ttl, NULL, NULL, &line_nr) ==
							LDNS_STATUS_OK) {
						ldns_key_set_pubkey_owner(key, ldns_rdf_clone(ldns_rr_owner(pubkey)));
						ldns_key_set_flags(key, ldns_rdf2native_int16(ldns_rr_rdf(pubkey, 0)));
						ldns_key_set_keytag(key, ldns_calc_keytag(pubkey));
					}
					ldns_zone_push_rr(orig_zone, ldns_rr_clone(pubkey));
					ldns_rr_free(pubkey);
					fclose(keyfile);
					goto found;
				}
				LDNS_FREE(keyfile_name);
				
				/* okay, so reading .key didn't work either, just use our generated one */
				if (verbosity >= 2) {
					fprintf(stderr, "Not in zone, no .key file, generating DNSKEY from .private\n");
				}
				ldns_zone_push_rr(orig_zone, pubkey_gen);
				
				
				found:
				ldns_rr_free(pubkey_gen);
				ldns_key_list_push_key(keys, key);
				exit(0);
#if 0
 else {
					/* apparently the public key is not in the zone
					   so we try to read the .key file
					 */
					keyfile_name = LDNS_XMALLOC(char, strlen(keyfile_name_base) + 5);
					snprintf(keyfile_name, strlen(keyfile_name_base) + 5, "%s.key", keyfile_name_base);
					fprintf(stderr, "trying to read %s\n", keyfile_name);
					keyfile = fopen(keyfile_name, "r");
					line_nr = 0;
					if (!keyfile) {
						fprintf(stderr, "Error: unable to read %s: %s\n", keyfile_name, strerror(errno));
					} else {
						if (ldns_rr_new_frm_fp_l(&pubkey, keyfile, &default_ttl, NULL, NULL, &line_nr) ==
								LDNS_STATUS_OK) {
							ldns_key_set_pubkey_owner(key, ldns_rdf_clone(ldns_rr_owner(pubkey)));
							ldns_key_set_flags(key, ldns_rdf2native_int16(ldns_rr_rdf(pubkey, 0)));
							ldns_key_set_keytag(key, ldns_calc_keytag(pubkey));
						}
						ldns_key_list_push_key(keys, key);
						ldns_zone_push_rr(orig_zone, ldns_rr_clone(pubkey));
						ldns_rr_free(pubkey);
						fclose(keyfile);
					}
					LDNS_FREE(keyfile_name);
				}
#endif
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

	/* remove old RRSIGS and NSECS */
	if (!leave_old_dnssec_data) {
		strip_dnssec_records(orig_zone);
	}

	/* walk through the keys, and add pubkeys to the orig zone */
	for (key_i = 0; key_i < ldns_key_list_key_count(keys); key_i++) {
		key = ldns_key_list_key(keys, key_i);
		if (!ldns_key_pubkey_owner(key)) {
			ldns_key_set_pubkey_owner(key, ldns_rdf_clone(origin));
			pubkey = ldns_key2rr(key);
			ldns_key_set_flags(key, ldns_rdf2native_int16(ldns_rr_rdf(pubkey, 0)));
			ldns_key_set_keytag(key, ldns_calc_keytag(pubkey));
			ldns_zone_push_rr(orig_zone, pubkey);
			printf("Derived DNSKEY RR:\n");
			ldns_rr_print(stdout, pubkey);
		}
	}
			
	signed_zone = ldns_zone_sign(orig_zone, keys);

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
	
	CRYPTO_cleanup_all_ex_data();

	free(prog);
	exit(EXIT_SUCCESS);
}
