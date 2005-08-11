/*
 * mx is a small programs that prints out the mx records
 * for a particulary domain
 * (c) NLnet Labs, 2005
 * Licensed under the GPL version 2
 */

#include <ldns/config.h>
#include <errno.h>

#include <ldns/dns.h>

int
usage(FILE *fp, char *prog) {
	fprintf(fp, "%s [OPTIONS] <zone name> <zonefile> <keyfile(s)>\n", prog);
	fprintf(fp, "  signs the zone with the given private key\n");
fprintf(fp, "currently only reads zonefile and prints it\n");
fprintf(fp, "todo: settable ttl, class?");
fprintf(fp, "you can specify multiple keyfiles");
	return 0;
}

int
main(int argc, char *argv[])
{
	const char *zonefile_name;
	FILE *zonefile = NULL;
	const char *zone_name = NULL;
	int argi;

	ldns_zone *orig_zone = NULL;
	ldns_rr_list *orig_rrs = NULL;
	ldns_rr *orig_soa = NULL;

	FILE *keyfile = NULL;
	ldns_key *key = NULL;
	ldns_key_list *keys;
	
	ldns_rdf *origin = NULL;
	uint16_t ttl = 0;
	ldns_rr_class class = LDNS_RR_CLASS_IN;	

	ldns_rr_list *rrs;
	
	if (argc < 3) {
		usage(stdout, argv[0]);
		exit(1);
	} else {
		zone_name = argv[1];
		zonefile_name = argv[2];
	}

	keys = ldns_key_list_new();

	argi = 3;
	while (argi < argc) {
		keyfile = fopen(argv[argi], "r");
		if (!keyfile) {
			fprintf(stderr, "Error: unable to read k%s (%s)\n", argv[argi], strerror(errno));
		} else {
			key = ldns_key_new_frm_fp(keyfile);
			if (key) {
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
		usage(stderr, argv[0]);
		return 1;
	}

	if (!origin) {
		/* default to root origin */
		/*origin = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, ".");*/
		origin = ldns_dname_new_frm_str(zone_name);
	}
	
	printf("Reading zonefile: %s\n", zonefile_name);

	zonefile = fopen(zonefile_name, "r");
	
	if (!zonefile) {
		fprintf(stderr, "Error: unable to read %s (%s)\n", zonefile_name, strerror(errno));
	} else {
		orig_zone = ldns_zone_new_frm_fp(zonefile, origin, ttl, class);
		
		if (!orig_zone) {
			fprintf(stderr, "Zone not read\n");
		} else {
			printf("Zone read.\nSOA:\n");
			orig_soa = ldns_zone_soa(orig_zone);
			orig_rrs = ldns_zone_rrs(orig_zone);

			ldns_rr_print(stdout, orig_soa);
			printf("\n");

			rrs = ldns_rr_list_new();
			ldns_rr_list_push_rr(rrs, orig_soa);
			ldns_rr_list_cat(rrs, orig_rrs);

			ldns_rr_list_free(rrs);
			ldns_zone_deep_free(orig_zone);
		}

		fclose(zonefile);
	}
	
	ldns_rdf_deep_free(origin);
	
        return 0;
}
