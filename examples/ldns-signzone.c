/*
 * ldns-signzone signs a zone file
 * 
 * (c) NLnet Labs, 2005 - 2008
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

#ifdef HAVE_SSL
#include <openssl/err.h>
#endif

void
usage(FILE *fp, const char *prog) {
	fprintf(fp, "%s [OPTIONS] zonefile key [key [key]]\n", prog);
	fprintf(fp, "  signs the zone with the given key(s)\n");
	fprintf(fp, "  -d\t\tused keys are not added to the zone\n");
	fprintf(fp, "  -e <date>\texpiration date\n");
	fprintf(fp, "  -f <file>\toutput zone to file (default <name>.signed)\n");
	fprintf(fp, "  -i <date>\tinception date\n");
	fprintf(fp, "  -l\t\tLeave old DNSSEC RRSIGS and NSEC records intact\n");
	fprintf(fp, "  -o <domain>\torigin for the zone\n");
	fprintf(fp, "  -v\t\tprint version and exit\n");
	fprintf(fp, "  -E <name>\tuse <name> as the crypto engine for signing\n");
	fprintf(fp, "           \tThis can have a lot of extra options, see the manual page for more info\n");
	fprintf(fp, "  -k <id>,<int>\tuse key id with algorithm int from engine\n");
	fprintf(fp, "  -K <id>,<int>\tuse key id with algorithm int from engine as KSK\n");
	fprintf(fp, "\t\tif no key is given (but an external one is used through the engine support, it might be necessary to provide the right algorithm number.\n");
	fprintf(fp, "  -n\t\tuse NSEC3 instead of NSEC.\n");
	fprintf(fp, "\t\tIf you use NSEC3, you can specify the following extra options:\n");
	fprintf(fp, "\t\t-a [algorithm] hashing algorithm\n");
	fprintf(fp, "\t\t-t [number] number of hash iterations\n");
	fprintf(fp, "\t\t-s [string] salt\n");
	fprintf(fp, "\t\t-p set the opt-out flag on all nsec3 rrs\n");
	fprintf(fp, "\n");
	fprintf(fp, "  keys must be specified by their base name (usually K<name>+<alg>+<id>),\n");
	fprintf(fp, "  i.e. WITHOUT the .private extension.\n");
	fprintf(fp, "  If the public part of the key is not present in the zone, the DNSKEY RR\n");
	fprintf(fp, "  will be read from the file called <base name>.key. If that does not exist,\n");
	fprintf(fp, "  a default DNSKEY will be generated from the private key and added to the zone.\n");
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
	ldns_dnssec_zone *signed_zone;

	const char *keyfile_name_base;
	char *keyfile_name;
	FILE *keyfile = NULL;
	ldns_key *key = NULL;
	ldns_rr *pubkey, *pubkey_gen;
	ldns_key_list *keys;
	size_t key_i;
	ldns_status s;
	size_t i;
	ldns_rr_list *added_rrs;

	bool leave_old_dnssec_data = false;

	char *outputfile_name = NULL;
	FILE *outputfile;
	
	/* tmp vars for engine keys */
	char *eng_key_l;
	size_t eng_key_id_len;
	char *eng_key_id;
	int eng_key_algo;
	
	bool use_nsec3 = false;

	/* Add the given keys to the zone if they are not yet present */
	bool add_keys = true;
	uint8_t nsec3_algorithm = 1;
	uint8_t nsec3_flags = 0;
	size_t nsec3_iterations_cmd = 1;
	uint16_t nsec3_iterations = 1;
	uint8_t nsec3_salt_length = 0;
	uint8_t *nsec3_salt = NULL;
	
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
	ldns_status result;
	
	inception = 0;
	expiration = 0;
	
	keys = ldns_key_list_new();

	OPENSSL_config(NULL);

	while ((c = getopt(argc, argv, "a:de:f:i:k:lno:ps:t:v:E:K:")) != -1) {
		switch (c) {
		case 'a':
			nsec3_algorithm = (uint8_t) atoi(optarg);
			break;
		case 'd':
			add_keys = false;
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
		case 'l':
			leave_old_dnssec_data = true;
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
		case 'p':
			nsec3_flags = nsec3_flags | LDNS_NSEC3_VARS_OPTOUT_MASK;
			break;
		case 'v':
			printf("zone signer version %s (ldns version %s)\n", LDNS_VERSION, ldns_version());
			exit(EXIT_SUCCESS);
			break;
		case 'E':
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
			eng_key_l = strchr(optarg, ',');
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
					/* must be dnssec key */
					switch (ldns_key_algorithm(key)) {
					case LDNS_SIGN_RSAMD5:
					case LDNS_SIGN_RSASHA1:
					case LDNS_SIGN_RSASHA1_NSEC3:
					case LDNS_SIGN_RSASHA256:
					case LDNS_SIGN_RSASHA512:
					case LDNS_SIGN_DSA:
					case LDNS_SIGN_DSA_NSEC3:
						ldns_key_list_push_key(keys, key);
						/*printf("Added key at %p:\n", key);*/
						/*ldns_key_print(stdout, key);*/
						break;
					default:
						fprintf(stderr, "Warning, key not suitable for signing, ignoring key with algorithm %u\n", ldns_key_algorithm(key));
						break;
					}
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
		case 's':
			if (strlen(optarg) % 2 != 0) {
				fprintf(stderr, "Salt value is not valid hex data, not a multiple of 2 characters\n");
				exit(EXIT_FAILURE);
			}
			nsec3_salt_length = (uint8_t) strlen(optarg) / 2;
			nsec3_salt = LDNS_XMALLOC(uint8_t, nsec3_salt_length);
			for (c = 0; c < (int) strlen(optarg); c += 2) {
				if (isxdigit(optarg[c]) && isxdigit(optarg[c+1])) {
					nsec3_salt[c/2] = (uint8_t) ldns_hexdigit_to_int(optarg[c]) * 16 +
						ldns_hexdigit_to_int(optarg[c+1]);
				} else {
					fprintf(stderr, "Salt value is not valid hex data.\n");
					exit(EXIT_FAILURE);
				}
			}

			break;
		case 't':
			nsec3_iterations_cmd = (size_t) atol(optarg);
			if (nsec3_iterations_cmd > LDNS_NSEC3_MAX_ITERATIONS) {
				fprintf(stderr, "Iterations count can not exceed %u, quitting\n", LDNS_NSEC3_MAX_ITERATIONS);
				exit(EXIT_FAILURE);
			}
			nsec3_iterations = (uint16_t) nsec3_iterations_cmd;
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
	
	printf("[XX] Reading zone file\n");
	if (!zonefile) {
		fprintf(stderr,
			   "Error: unable to read %s (%s)\n",
			   zonefile_name,
			   strerror(errno));
		exit(EXIT_FAILURE);
	} else {
		s = ldns_zone_new_frm_fp_l(&orig_zone,
							  zonefile,
							  origin,
							  ttl,
							  class,
							  &line_nr);
		if (s != LDNS_STATUS_OK) {
			fprintf(stderr, "Zone not read, error: %s at %s line %d\n", 
				   ldns_get_errorstr_by_id(s), 
				   zonefile_name, line_nr);
			exit(EXIT_FAILURE);
		} else {
			orig_soa = ldns_zone_soa(orig_zone);
			if (!orig_soa) {
				fprintf(stderr,
					   "Error reading zonefile: missing SOA record\n");
				exit(EXIT_FAILURE);
			}
			orig_rrs = ldns_zone_rrs(orig_zone);
			if (!orig_rrs) {
				fprintf(stderr,
					   "Error reading zonefile: no resource records\n");
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
		snprintf(keyfile_name,
			    strlen(keyfile_name_base) + 9,
			    "%s.private",
			    keyfile_name_base);
		keyfile = fopen(keyfile_name, "r");
		line_nr = 0;
		if (!keyfile) {
			fprintf(stderr,
				   "Error: unable to read %s: %s\n",
				   keyfile_name,
				   strerror(errno));
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
				 * we 'generate' one anyway, 
				 * then match that to any present in the zone,
				 * if it matches, we drop our own. If not,
				 * we try to see if there is a .key file present.
				 * If not, we use our own generated one, with
				 * some default values 
				 *
				 * Even if -d (do-not-add-keys) is specified, 
				 * we still need to do this, because we need
				 * to have any key flags that are set this way
				 */
				pubkey_gen = ldns_key2rr(key);

				if (verbosity >= 2) {
					fprintf(stderr,
						   "Looking for key with keytag %u or %u\n",
						   (unsigned int) ldns_calc_keytag(pubkey_gen),
						   (unsigned int) ldns_calc_keytag(pubkey_gen)+1
						   );
				}
				for (key_i = 0;
					key_i < ldns_rr_list_rr_count(orig_rrs);
					key_i++) {
					pubkey = ldns_rr_list_rr(orig_rrs, key_i);
					if (ldns_rr_get_type(pubkey) == LDNS_RR_TYPE_DNSKEY &&
					    (ldns_calc_keytag(pubkey)
						==
						ldns_calc_keytag(pubkey_gen) ||
					     /* KSK has gen-keytag + 1 */
					     ldns_calc_keytag(pubkey)
						==
						ldns_calc_keytag(pubkey_gen) + 1) 
					    ) {
						/* found it, drop our own */
						if (verbosity >= 2) {
							fprintf(stderr, "Found it in the zone!\n");
						}
						goto found;
					}
				}
				/* it was not in the zone, try to read a .key file */
				keyfile_name = LDNS_XMALLOC(char,
									   strlen(keyfile_name_base) + 5);
				snprintf(keyfile_name,
					    strlen(keyfile_name_base) + 5,
					    "%s.key",
					    keyfile_name_base);
				if (verbosity >= 2) {
					fprintf(stderr, "Trying to read %s\n", keyfile_name);
				}
				keyfile = fopen(keyfile_name, "r");
				line_nr = 0;
				if (keyfile) {
					if (ldns_rr_new_frm_fp_l(&pubkey,
										keyfile,
										&default_ttl,
										NULL,
										NULL,
										&line_nr) ==
					    LDNS_STATUS_OK) {
						ldns_key_set_pubkey_owner(key, ldns_rdf_clone(ldns_rr_owner(pubkey)));
						ldns_key_set_flags(key, ldns_rdf2native_int16(ldns_rr_rdf(pubkey, 0)));
						ldns_key_set_keytag(key, ldns_calc_keytag(pubkey));
					}
					if (add_keys) {
						ldns_zone_push_rr(orig_zone,
									   ldns_rr_clone(pubkey));
					}
					ldns_rr_free(pubkey);
					fclose(keyfile);
					goto found;
				}
				
				/* okay, so reading .key didn't work either,
				   just use our generated one */
				if (verbosity >= 2) {
					fprintf(stderr, "Not in zone, no .key file, generating DNSKEY from .private\n");
				}
				if (add_keys) {
					ldns_zone_push_rr(orig_zone, pubkey_gen);
				}
				
			found:
				ldns_rr_free(pubkey_gen);
				switch (ldns_key_algorithm(key)) {
				case LDNS_SIGN_RSAMD5:
				case LDNS_SIGN_RSASHA1:
				case LDNS_SIGN_RSASHA1_NSEC3:
				case LDNS_SIGN_RSASHA256:
				case LDNS_SIGN_RSASHA512:
				case LDNS_SIGN_DSA:
				case LDNS_SIGN_DSA_NSEC3:
					ldns_key_list_push_key(keys, key);
					/*printf("Added key at %p:\n", key);*/
					/*ldns_key_print(stdout, key);*/
					break;
				default:
					fprintf(stderr, "Warning, key not suitable for signing, ignoring key from %s with algorithm %u\n", keyfile_name, ldns_key_algorithm(key));
					break;
				}
				LDNS_FREE(keyfile_name);
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

	/* walk through the keys, and add pubkeys to the orig zone */
	for (key_i = 0; key_i < ldns_key_list_key_count(keys); key_i++) {
		key = ldns_key_list_key(keys, key_i);
		if (!ldns_key_pubkey_owner(key)) {
			ldns_key_set_pubkey_owner(key, ldns_rdf_clone(origin));
			pubkey = ldns_key2rr(key);
			if (!key || !pubkey) {
				fprintf(stderr, "Unknown key type; can't create public key RR. Aborting.\n");
				exit(1);
			}
			ldns_key_set_flags(key, ldns_rdf2native_int16(ldns_rr_rdf(pubkey, 0)));
			ldns_key_set_keytag(key, ldns_calc_keytag(pubkey));
			/*ldns_zone_push_rr(orig_zone, pubkey);*/
			printf("Derived DNSKEY RR:\n");
			ldns_rr_print(stdout, pubkey);
		}
	}

	signed_zone = ldns_dnssec_zone_new();
    	if (ldns_dnssec_zone_add_rr(signed_zone, ldns_zone_soa(orig_zone)) !=
	    LDNS_STATUS_OK) {
		fprintf(stderr, "Error adding SOA to dnssec zone, skipping record\n");
	}

	for (i = 0; i < ldns_rr_list_rr_count(ldns_zone_rrs(orig_zone)); i++) {
		if (ldns_dnssec_zone_add_rr(signed_zone, 
							   ldns_rr_list_rr(ldns_zone_rrs(orig_zone), 
										    i)) !=
		    LDNS_STATUS_OK) {
			fprintf(stderr, "Error adding RR to dnssec zone");
			fprintf(stderr, ", skipping record:\n");
			ldns_rr_print(stderr, 
					    ldns_rr_list_rr(ldns_zone_rrs(orig_zone), i));
		}
	}

	/* list to store newly created rrs, so we can free them later */
	added_rrs = ldns_rr_list_new();

	if (use_nsec3) {
		result = ldns_dnssec_zone_sign_nsec3(signed_zone,
			added_rrs,
			keys,
			ldns_dnssec_default_replace_signatures,
			NULL,
			nsec3_algorithm,
			nsec3_flags,
			nsec3_iterations,
			nsec3_salt_length,
			nsec3_salt);
	} else {
		result = ldns_dnssec_zone_sign(signed_zone,
				added_rrs,
				keys,
				ldns_dnssec_default_replace_signatures,
				NULL);
	}
	if (result != LDNS_STATUS_OK) {
		fprintf(stderr, "Error signing zone: %s\n",
			   ldns_get_errorstr_by_id(result));
	}
	
	if (!outputfile_name) {
		outputfile_name = LDNS_XMALLOC(char, MAX_FILENAME_LEN);
		snprintf(outputfile_name, MAX_FILENAME_LEN, "%s.signed", zonefile_name);
	}

	if (signed_zone) {
		outputfile = fopen(outputfile_name, "w");
		if (!outputfile) {
			fprintf(stderr, "Unable to open %s for writing: %s\n",
				   outputfile_name, strerror(errno));
		} else {
			ldns_dnssec_zone_print(outputfile, signed_zone);
			fclose(outputfile);
		}
/*
		ldns_zone_deep_free(signed_zone); 
*/
	} else {
		fprintf(stderr, "Error signing zone.\n");

#ifdef HAVE_SSL
		if (ERR_peek_error()) {
			ERR_load_crypto_strings();
			ERR_print_errors_fp(stderr);
			ERR_free_strings();
		}
#endif
		exit(EXIT_FAILURE);
	}
	
	ldns_dnssec_zone_free(signed_zone);
	ldns_key_list_free(keys);
	ldns_zone_deep_free(orig_zone);
	ldns_rr_list_deep_free(added_rrs);
	
	LDNS_FREE(outputfile_name);
	
	CRYPTO_cleanup_all_ex_data();

	free(prog);
	exit(EXIT_SUCCESS);
}
