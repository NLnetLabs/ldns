/*
 * mx is a small programs that prints out the mx records
 * for a particulary domain
 */

#include <stdio.h>
#include <config.h>
#include <ldns/ldns.h>

int
usage(FILE *fp, char *prog) {
	fprintf(fp, "%s keygen\n", prog);
	fprintf(fp, "  generate a DNSKEY RR \n");
	return 0;
}

int
main(int argc, char *argv[])
{
	ldns_rr *dnskey;
	ldns_key *privkey;
	ldns_rdf *owner;
	ldns_rr *rr;
	ldns_key_list *keys;
	ldns_rr_list  *rrs;
	ldns_rr_list  *signatures;

	keys = ldns_key_list_new();
	rrs  = ldns_rr_list_new();

	rr = ldns_rr_new_frm_str("a.miek.nl. 1800 IN A 195.169.222.38");
	ldns_rr_print(stdout, rr);
	printf("\n");

	privkey = ldns_key_new_frm_algorithm(LDNS_SIGN_RSASHA1, 1024);
	if (!privkey) {
		printf("Ah, keygen failed");
		exit(1);
	}

	owner = ldns_dname_new_frm_str("miek.nl");
	ldns_key_set_pubkey_owner(privkey, owner);
	ldns_key_set_flags(privkey, 256);

	ldns_key_list_push_key(keys, privkey);
	ldns_rr_list_push_rr(rrs, rr);
	
	dnskey = ldns_key2rr(privkey);
	if (dnskey) {
		ldns_rr_print(stdout, dnskey);
		printf("\n");
	}

	signatures = ldns_sign_public(rrs, keys);

	ldns_rr_list_print(stdout, signatures);

        return 0;
}
