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

	rr = ldns_rr_new_frm_str("www.miek.nl IN A 127.0.0.1");
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
	if (!f) {
		return 0;
	}

	/*
	ldns_fget_keyword_data(f, "Private-key-format", ": ", d, "\n");
	printf("read from file [%s]\n", d);
	ldns_fget_keyword_data(f, "Algorithm", ": ", d, "\n");
	printf("read from file [%s]\n", d);
	
	ldns_fget_keyword_data(f, "Modulus", ": ", d, "\n");
	printf("read from file [%s]\n", d);
	ldns_fget_keyword_data(f, "PublicExponent", ": ", d, "\n");
	printf("read from file [%s]\n", d);
	ldns_fget_keyword_data(f, "PrivateExponent", ": ", d, "\n");
	printf("read from file [%s]\n", d);
	ldns_fget_keyword_data(f, "Prime1", ": ", d, "\n");
	printf("read from file [%s]\n", d);
	ldns_fget_keyword_data(f, "Prime2", ": ", d, "\n");
	printf("read from file [%s]\n", d);
	ldns_fget_keyword_data(f, "Exponent1", ": ", d, "\n");
	printf("read from file [%s]\n", d);
	ldns_fget_keyword_data(f, "Exponent2", ": ", d, "\n");
	printf("read from file [%s]\n", d);
	ldns_fget_keyword_data(f, "Coefficient", ": ", d, "\n");
	printf("read from file [%s]\n", d);
	*/


	privkey = ldns_key_new_frm_fp(f);
	printf("Kom ik hier nog wel ofzo?\n");

	fclose(f);




	return 0;


	/* this is all kaput... :-( */

	
	signatures = ldns_sign_public(rrs, keys);

	ldns_rr_list_print(stdout, signatures);

	printf("Now we are going to verify\n");

	if (ldns_verify(rrs, signatures, dnskeys)) {
		printf("SUCESS\n\n");
	} else {
		printf("FAILURE\n\n");
	}
	
        return 0;
}
