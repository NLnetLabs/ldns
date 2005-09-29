/*
 * mx is a small programs that prints out the mx records
 * for a particulary domain
 */

#include "config.h"

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
	ldns_rr_list  *result_keys;
	ldns_status result;

	/* ----- */
	FILE *f;
	char *d;
	char *keyfilename;

	d = LDNS_XMALLOC(char, 1000);

	keys = ldns_key_list_new();
	rrs  = ldns_rr_list_new();
	dnskeys = ldns_rr_list_new();

	privkey = ldns_key_new_frm_algorithm(LDNS_SIGN_RSASHA1, 512);
	if (!privkey) {
		printf("Ah, keygen failed");
		exit(1);
	}

	owner = ldns_dname_new_frm_str("jelte.nlnetlabs.nl");
	ldns_key_set_pubkey_owner(privkey, owner);

	ldns_key_set_origttl(privkey, 1800);
	SSL_load_error_strings();

	ldns_key_list_push_key(keys, privkey);

	rr = ldns_rr_new_frm_str("www.jelte.nlnetlabs.nl. IN A 127.0.0.1", 0, NULL);
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

	signatures = ldns_sign_public(rrs, keys);

	printf("DATA:\n");
	ldns_rr_list_print(stdout, rrs);

	printf("SIGS:\n");

	ldns_rr_list_print(stdout, signatures);

	printf("KEYS:\n");
	ldns_rr_list_print(stdout, dnskeys);

	printf("Now we are going to verify\n");

	result_keys = ldns_rr_list_new();
	result = ldns_verify(rrs, signatures, dnskeys, result_keys);

	printf("RESULT:\n");
	ldns_rr_list_print(stdout, result_keys);

	if (result == LDNS_STATUS_OK) {
		printf("SUCCESS\n\n");
	} else {
		printf("FAILURE\n\n");
	}
	
        return 0;
}
