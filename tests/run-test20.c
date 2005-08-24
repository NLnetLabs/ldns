/*
 * mx is a small programs that prints out the mx records
 * for a particulary domain
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <stdbool.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif /* HAVE_STDINT_H */

#include <ldns/dns.h>

int
usage(FILE *fp, char *prog) {
	fprintf(fp, "%s keygen\n", prog);
	fprintf(fp, "  generate a DNSKEY RR \n");
	return 0;
}

int
main(void)
{
	ldns_rr *dnskey;
	ldns_key *privkey;
	ldns_rr *dnskey_dsa;
	ldns_key *privkey_dsa;
	ldns_rdf *owner;
	ldns_rr *rr;
	ldns_key_list *keys;
	ldns_rr_list  *rrs;
	ldns_rr_list  *signatures;
	ldns_rr_list  *dnskeys;
	/* ----- */
	FILE *f;
	char *d;

	d = LDNS_XMALLOC(char, 1000);

	keys = ldns_key_list_new();
	rrs  = ldns_rr_list_new();
	dnskeys = ldns_rr_list_new();

	privkey = ldns_key_new_frm_algorithm(LDNS_SIGN_RSASHA1, 512);
	if (!privkey) {
		printf("Ah, keygen failed");
		exit(1);
	}

	owner = ldns_dname_new_frm_str("miek.nl");
	ldns_key_set_pubkey_owner(privkey, owner);

	ldns_key_set_origttl(privkey, 1800);
	SSL_load_error_strings();

	ldns_key_list_push_key(keys, privkey);

	rr = ldns_rr_new_frm_str("www.miek.nl IN A 127.0.0.1", 0, NULL);
	ldns_rr_print(stdout, rr);
	
	ldns_rr_list_push_rr(rrs, rr);
	
	dnskey = ldns_key2rr(privkey);
	if (dnskey) {
		ldns_rr_print(stdout, dnskey);
		printf("; {%d}\n", 
				(int) ldns_calc_keytag(dnskey));
		printf("\n");
		ldns_key_set_keytag(privkey, ldns_calc_keytag(dnskey));
	} else {
		exit(1);
	}
	ldns_rr_list_push_rr(dnskeys, dnskey);

	ldns_rr_list_print(stdout, dnskeys);
	printf("\n Trying to sign\n");

	f = fopen("Kmiek.nl.+001+63054.private", "r");
	printf("Opening %s\n", "Kmiek.nl.+001+63054.private");
	if (!f) {
		return 0;
	}
	privkey = ldns_key_new_frm_fp(f);
	fclose(f);

	if (!privkey) { 
		printf("arrg no key could be found!\n");
		exit(1);
	} else {
		printf("Checking\n\n");
		ldns_key_print(stdout, privkey);
	}

	dnskey = ldns_key2rr(privkey);
	if (dnskey) {
		ldns_rr_print(stdout, dnskey);
		printf("; {%d}\n", 
				(int) ldns_calc_keytag(dnskey));
		printf("\n");
		ldns_key_set_keytag(privkey, ldns_calc_keytag(dnskey));
	} else {
		exit(1);
	}

	f = fopen("Kmiek.nl.+001+05920.private", "r");
	printf("Opening %s\n", "Kmiek.nl.+001+05920.private ");
	if (!f) {
		return 0;
	}

	privkey = ldns_key_new_frm_fp(f);
	fclose(f);

	if (!privkey) { 
		printf("arrg no key could be found!\n");
		exit(1);
	}

	dnskey = ldns_key2rr(privkey);
	if (dnskey) {
		ldns_rr_print(stdout, dnskey);
		printf("; {%d}\n", 
				(int) ldns_calc_keytag(dnskey));
		printf("\n");
		ldns_key_set_keytag(privkey, ldns_calc_keytag(dnskey));
	} else {
		exit(1);
	}


	signatures = ldns_sign_public(rrs, keys);

	ldns_rr_list_print(stdout, signatures);

	printf("Now we are going to verify\n");

	if (ldns_verify(rrs, signatures, dnskeys)) {
		printf("SUCCESS\n\n");
	} else {
		printf("FAILURE\n\n");
	}
	
        return 0;
}
