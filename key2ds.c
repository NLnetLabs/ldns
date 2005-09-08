/*
 * key2ds transforms a public key into its DS
 * for a particulary domain. It (currently) prints out the public key
 * (c) NLnet Labs, 2005
 * Licensed under the GPL version 2
 */

#include <ldns/config.h>

#include <ldns/dns.h>

#include <errno.h>

void
usage(FILE *fp, char *prog) {
	fprintf(fp, "%s keyfile\n", prog);
	fprintf(fp, "  generate a ds record\n");
	fprintf(fp, "  The following file will be created: ");
	fprintf(fp, "K<name>+<alg>+<id>.ds\n");
	fprintf(fp, "  The base name (K<name>+<alg>+<id> will be printed to stdout\n");
}

int
main(int argc, char *argv[])
{
	char *prog;
	FILE *keyfp, *dsfp;
	char *keyname;
	char *dsname;
	char *owner;
	ldns_rr *k, *ds;
	ldns_signing_algorithm alg;
	
	alg = 0;
	prog = strdup(argv[0]);
	if (argc != 2) {
		usage(stderr, prog);
		exit(EXIT_FAILURE);
	}
	keyname = strdup(argv[1]);

	keyfp = fopen(keyname, "r");
	if (!keyfp) {
		fprintf(stderr, "Failed to open public key file %s: %s\n", keyname,
				strerror(errno));
		exit(EXIT_FAILURE);
	}

	k = ldns_rr_new_frm_fp(keyfp, 0, NULL);
	if (!k) {
		fprintf(stderr, "Could not read public key from file %s\n", keyname);
		exit(EXIT_FAILURE);
	}
	fclose(keyfp);
	
	owner = ldns_rdf2str(ldns_rr_owner(k));
	alg = ldns_rdf2native_int8(ldns_rr_dnskey_algorithm(k));

	ds = ldns_key_rr2ds(k);
	if (!ds) {
		fprintf(stderr, "Conversion to a DS RR failed\n");
		exit(EXIT_FAILURE);
	}

	/* print the public key RR to .key */
	dsname = LDNS_XMALLOC(char, strlen(owner) + 16);
	snprintf(dsname, strlen(owner) + 15, "K%s+%03u+%05u.ds", owner, alg, ldns_calc_keytag(k));

	dsfp = fopen(dsname, "w");
	if (!dsfp) {
		fprintf(stderr, "Unable to open %s: %s\n", dsname, strerror(errno));
		exit(EXIT_FAILURE);
	} else {
		ldns_rr_print(dsfp, ds);
		fclose(dsfp);
		LDNS_FREE(dsname);
	}
	
	fprintf(stdout, "K%s+%03u+%05u\n", owner, alg, ldns_calc_keytag(k)); 
        exit(EXIT_SUCCESS);
}
