/*
 * keygen is a small programs that generate a dnskey and private key
 * for a particulary domain. It (currently) prints out the public key
 * (c) NLnet Labs, 2005
 * Licensed under the GPL version 2
 */

#include <ldns/config.h>

#include <ldns/dns.h>

#include <errno.h>

void
usage(FILE *fp, char *prog) {
	fprintf(fp, "%s keygen [-D|-R] -b bits domain\n", prog);
	fprintf(fp, "  generate a new key pair for domain\n");
	fprintf(fp, "  -D\tgenerate a DSA key\n");
	fprintf(fp, "  -R\tgenerate a RSA key\n");
	fprintf(fp, "  -k\tset the flags to 257; key signing key\n");
	fprintf(fp, "  -b <bits>\tspecify the keylength\n");
	fprintf(fp, "  The following files will be created:\n");
	fprintf(fp, "    K<name>+<alg>+<id>.key\tPublic key in RR format\n");
	fprintf(fp, "    K<name>+<alg>+<id>.private\tPrivate key in key format\n");
	fprintf(fp, "    K<name>+<alg>+<id>.ds\tDS in RR format\n");
	fprintf(fp, "  The base name (K<name>+<alg>+<id> will be printed to stdout\n");
/*
	fprintf(fp, "  The public key is printed to stdout\n");
	fprintf(fp, "  The private key is printed to stderr\n");
*/
	fprintf(fp, "\nWARNING, WARNING, this program does NOT use a good random source for the key generation.\nUse at your OWN RISK\n\n");
}

int
main(int argc, char *argv[])
{
	int c;
	char *prog;

	/* default key size */
	uint16_t def_bits = 1024;
	uint16_t bits = def_bits;
	bool ksk;

	FILE *file;
	char *filename;
	char *owner;

	ldns_signing_algorithm algorithm;
	ldns_rdf *domain;
	ldns_rr *pubkey;
	ldns_key *key;
	ldns_rr *ds;

	prog = strdup(argv[0]);
	algorithm = 0;
	ksk = false; /* don't create a ksk per default */
	
	while ((c = getopt(argc, argv, "DRkb:")) != -1) {
		switch (c) {
		case 'D':
			if (algorithm != 0) {
				fprintf(stderr, "%s: %s", prog, "Only one -D or -A is allowed\n");
				exit(EXIT_FAILURE);
			}
			algorithm = LDNS_SIGN_DSA;
			break;
		case 'R':
			if (algorithm != 0) {
				fprintf(stderr, "%s: %s", prog, "Only one -D or -A is allowed\n");
				exit(EXIT_FAILURE);
			}
			algorithm = LDNS_SIGN_RSASHA1;
			break;
		case 'b':
			bits = atoi(optarg);
			if (bits == 0) {
				fprintf(stderr, "%s: %s %d", prog, "Can not parse the -b argument, setting it to the default\n", def_bits);
			}
			bits = def_bits;
			break;
		case 'k':
			ksk = true;
			break;
		default:
			usage(stderr, prog);
			exit(EXIT_FAILURE);
		}
	}
	argc -= optind;
	argv += optind;

	if (algorithm == 0) {
		algorithm = LDNS_SIGN_RSASHA1; /* default to RSA SHA1 */
	}

	if (argc != 1) {
		usage(stderr, prog);
		exit(EXIT_FAILURE);
	} 

	/* create an rdf from the domain name */
	domain = ldns_dname_new_frm_str(argv[0]);

	/* generate a new key */
	key = ldns_key_new_frm_algorithm(algorithm, bits);
	
	/* set the owner name in the key - this is a /seperate/ step */
	ldns_key_set_pubkey_owner(key, domain);

	/* ksk flag */
	if (ksk) {
		ldns_key_set_flags(key, ldns_key_flags(key) + 1);
	}

	/* create the public from the ldns_key */
	pubkey = ldns_key2rr(key);
	owner = ldns_rdf2str(ldns_rr_owner(pubkey));
	
	/* calculate and set the keytag */
	ldns_key_set_keytag(key, ldns_calc_keytag(pubkey));

	/* build the DS record */
	ds = ldns_key_rr2ds(pubkey);

	/* print the public key RR to .key */
	filename = LDNS_XMALLOC(char, strlen(owner) + 17);
	snprintf(filename, strlen(owner) + 16, "K%s+%03u+%05u.key", owner, algorithm, ldns_key_keytag(key));
	file = fopen(filename, "w");
	if (!file) {
		fprintf(stderr, "Unable to open %s: %s\n", filename, strerror(errno));
		fprintf(stderr, "Aborting\n");
		exit(EXIT_FAILURE);
	} else {
		ldns_rr_print(file, pubkey);
		fclose(file);
		LDNS_FREE(filename);
	}
	
	/* print the priv key to stderr */
	filename = LDNS_XMALLOC(char, strlen(owner) + 21);
	snprintf(filename, strlen(owner) + 20, "K%s+%03u+%05u.private", owner, algorithm, ldns_key_keytag(key));
	file = fopen(filename, "w");
	if (!file) {
		fprintf(stderr, "Unable to open %s: %s\n", filename, strerror(errno));
		fprintf(stderr, "Aborting\n");
		exit(EXIT_FAILURE);
	} else {
		ldns_key_print(file, key);
		fclose(file);
		LDNS_FREE(filename);
	}
	
	/* print the DS to .ds */
	filename = LDNS_XMALLOC(char, strlen(owner) + 16);
	snprintf(filename, strlen(owner) + 15, "K%s+%03u+%05u.ds", owner, algorithm, ldns_key_keytag(key));
	file = fopen(filename, "w");
	if (!file) {
		fprintf(stderr, "Unable to open %s: %s\n", filename, strerror(errno));
		fprintf(stderr, "Aborting\n");
		exit(EXIT_FAILURE);
	} else {
		ldns_rr_print(file, ds);
		fclose(file);
		LDNS_FREE(filename);
	}
	
	fprintf(stdout, "K%s+%03u+%05u\n", owner, algorithm, ldns_key_keytag(key));
        exit(EXIT_SUCCESS);
}
