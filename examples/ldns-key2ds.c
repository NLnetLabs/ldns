/*
 * key2ds transforms a public key into its DS
 * It (currently) prints out the public key
 *
 * (c) NLnet Labs, 2005
 * See the file LICENSE for the license
 */

#include "config.h"

#include <ldns/ldns.h>

#include <errno.h>

void
usage(FILE *fp, char *prog) {
	fprintf(fp, "%s [-1|-2] keyfile\n", prog);
	fprintf(fp, "  Generate a DS RR from the key\n");
	fprintf(fp, "  The following file will be created: ");
	fprintf(fp, "K<name>+<alg>+<id>.ds\n");
	fprintf(fp, "  The base name (K<name>+<alg>+<id> will be printed to stdout\n");
	fprintf(fp, "Options:\n");
	fprintf(fp, "  -1 (default): use SHA1 for the DS hash\n");
	fprintf(fp, "  -2: use SHA256 for the DS hash\n");
}

int
main(int argc, char *argv[])
{
	FILE *keyfp, *dsfp;
	char *keyname;
	char *dsname;
	char *owner;
	ldns_rr *k, *ds;
	ldns_signing_algorithm alg;
	ldns_hash h;
	
	alg = 0;
	h = LDNS_SHA1;

	argv++, argc--;
	while (argc && argv[0][0] == '-') {
		if (strcmp(argv[0], "-1") == 0) {
			h = LDNS_SHA1;
		} 
		if (strcmp(argv[0], "-2") == 0) {
			h = LDNS_SHA256;
		} 
		argv++, argc--;
	}

	if (argc != 1) {
		usage(stderr, argv[0]);
		exit(EXIT_FAILURE);
	}
	keyname = strdup(argv[0]);

	keyfp = fopen(keyname, "r");
	if (!keyfp) {
		fprintf(stderr, "Failed to open public key file %s: %s\n", keyname,
				strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (ldns_rr_new_frm_fp(&k, keyfp, 0, NULL, NULL) != LDNS_STATUS_OK) {
		fprintf(stderr, "Could not read public key from file %s\n", keyname);
		exit(EXIT_FAILURE);
	}
	fclose(keyfp);
	free(keyname);
	
	owner = ldns_rdf2str(ldns_rr_owner(k));
	alg = ldns_rdf2native_int8(ldns_rr_dnskey_algorithm(k));

	ds = ldns_key_rr2ds(k, LDNS_SHA1);
	if (!ds) {
		fprintf(stderr, "Conversion to a DS RR failed\n");
		ldns_rr_free(k);
		free(owner);
		exit(EXIT_FAILURE);
	}

	/* print the public key RR to .key */
	dsname = LDNS_XMALLOC(char, strlen(owner) + 16);
	snprintf(dsname, strlen(owner) + 15, "K%s+%03u+%05u.ds", owner, alg, (unsigned int) ldns_calc_keytag(k));

	dsfp = fopen(dsname, "w");
	if (!dsfp) {
		fprintf(stderr, "Unable to open %s: %s\n", dsname, strerror(errno));
		exit(EXIT_FAILURE);
	} else {
		ldns_rr_print(dsfp, ds);
		fclose(dsfp);
	}
	
	ldns_rr_free(ds);
	fprintf(stdout, "K%s+%03u+%05u\n", owner, alg, (unsigned int) ldns_calc_keytag(k)); 

	ldns_rr_free(k);
	free(owner);
	LDNS_FREE(dsname);
        exit(EXIT_SUCCESS);
}
