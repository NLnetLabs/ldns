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

	privkey = ldns_key_new_frm_algorithm(LDNS_SIGN_RSASHA1, 1024);
	if (!privkey) {
		printf("Ah, keygen failed");
		exit(1);
	}
	RSA_print_fp(stdout, ldns_key_rsa_key(privkey), 0);
	printf("did it print\n");

	dnskey = ldns_key2rr(privkey);
	if (dnskey) {
		ldns_rr_print(stdout, dnskey);
	}
	printf("\n");
	
	if (argc != 2) {
		usage(stdout, argv[0]);
		exit(1);
	} 

        
        return 0;
}
