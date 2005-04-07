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
main()
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
	const char *soa_string1;
	const char *soa_string2;
	const char *soa_string3;

	keys = ldns_key_list_new();
	rrs  = ldns_rr_list_new();
	dnskeys = ldns_rr_list_new();

	/* well formed */
	rr = ldns_rr_new_frm_str("a.miek.nl.   1800   IN   A    195.169.222.38");
	ldns_rr_print(stdout, rr);
	printf("\n");

	
	soa_string1 = "miek.nl. 3600 IN SOA elektron.atoom.net. miekg.atoom.net. ( \
2002120700 ; serial\n\
21600      ; refresh (6 hours)\n\
7200       ; retry (2 hours)\n\
604800     ; expire (1 week)\n\
3600       ; minimum (1 hour)\n\
)";
	soa_string3 = "miek.nl. 3600 IN SOA elektron.atoom.net. miekg.atoom.net. ( \
2002120700 \n\
21600      \n\
7200       \n\
604800     \n\
3600       \n\
)";
	soa_string2 = "miek.nl. 3600 IN SOA elektron.atoom.net. miekg.atoom.net. \
2002120700 \n\
21600 \n\
7200 \n\
604800 \n\
3600"; 

	printf("string as typed:\n%s\n", soa_string1);
	printf("string as typed:\n%s\n", soa_string2);
	printf("string as typed:\n%s\n", soa_string3);
	rr = ldns_rr_new_frm_str(soa_string1);
	ldns_rr_print(stdout, rr);
	printf("\n");
	rr = ldns_rr_new_frm_str(soa_string2);
	ldns_rr_print(stdout, rr);
	printf("\n");
	rr = ldns_rr_new_frm_str(soa_string3);
	ldns_rr_print(stdout, rr);
	printf("\n");
	exit(0);

	rr = ldns_rr_new_frm_str("a.miek.nl. 1800    IN     MX     10    www.atoom.net");
	ldns_rr_print(stdout, rr);
	printf("\n");

	rr = ldns_rr_new_frm_str("a.miek.nl. 1800    IN     MX     10    w\\065.atoom.net");
	ldns_rr_print(stdout, rr);
	printf("\n");

	rr = ldns_rr_new_frm_str("a.miek.nl. 1800    IN     MX     10    w\\65.atoom.net");
	ldns_rr_print(stdout, rr);
	printf("\n");

	rr = ldns_rr_new_frm_str("a.miek.nl. 1800    IN     MX     10    www\\.www.atoom.net");
	ldns_rr_print(stdout, rr);
	printf("\n");

	rr = ldns_rr_new_frm_str("a.miek.nl. 1800    IN     MX     10    \\.");
	ldns_rr_print(stdout, rr);
	printf("\n");

	printf("rr sig with inception as epoch number\n");
	rr = ldns_rr_new_frm_str("nlnetlabs.nl.       86400  IN  RRSIG    DNSKEY RSASHA1 2 86400 1114695776 1112103776 43791 nlnetlabs.nl.  FE//RZ0Z1sMzea0ioOLFpUIcM3wnxLGndtKUXJSM3SQ3BlYok2fUTiI+zegNoB1YdylWsfohZJfjkODrOJO9PSbN7hMHmzFEsDFAbCU75TySBuxv2UQlQVuTznxtRdvLGIRGxRhPmjlc/gtJPMB4XJKUWmtkzlTVKqZU7oNCsLA=");
	ldns_rr_print(stdout, rr);
	printf("\n");

	printf("rr sig with inception as date\n");
	rr = ldns_rr_new_frm_str("nlnetlabs.nl.       86400  IN  RRSIG    DNSKEY RSASHA1 2 86400 20050105121300 1112103776 43791 nlnetlabs.nl.  FE//RZ0Z1sMzea0ioOLFpUIcM3wnxLGndtKUXJSM3SQ3BlYok2fUTiI+zegNoB1YdylWsfohZJfjkODrOJO9PSbN7hMHmzFEsDFAbCU75TySBuxv2UQlQVuTznxtRdvLGIRGxRhPmjlc/gtJPMB4XJKUWmtkzlTVKqZU7oNCsLA=");

	ldns_rr_print(stdout, rr);
	printf("\n");
	
	/* miss formed */
	rr = ldns_rr_new_frm_str("a.miek.nl. 1800 IN MX 10");
	ldns_rr_print(stdout, rr);
	printf("\n");

	rr = ldns_rr_new_frm_str("a.miek.nl. 1800 IN A 267.271.122.1t");
	ldns_rr_print(stdout, rr);
	printf("\n");

	printf("this must work again\n");
	rr = ldns_rr_new_frm_str("a.miek.nl.   IN     A    127.0.0.1");
	ldns_rr_print(stdout, rr);
	printf("\n");
	rr = ldns_rr_new_frm_str("a.miek.nl.   1D IN     A    127.0.0.1");
	ldns_rr_print(stdout, rr);
	printf("\n");

	rr = ldns_rr_new_frm_str("a.miek.nl.   1800   IN   A    195.169.222.38");
	ldns_rr_print(stdout, rr);
	printf("\n");


	privkey = ldns_key_new_frm_algorithm(LDNS_SIGN_RSASHA1, 512);
	if (!privkey) {
		printf("Ah, keygen failed");
		exit(1);
	}

	owner = ldns_dname_new_frm_str("miek.nl");
	ldns_key_set_pubkey_owner(privkey, owner);

	ldns_key_set_origttl(privkey, 1800);
	/*	SSL_load_error_strings();*/

	ldns_key_list_push_key(keys, privkey);

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

	signatures = ldns_sign_public(rrs, keys);

	ldns_rr_list_print(stdout, signatures);

	printf("Now we are going to verify\n");

	printf("\n[%d]\n", ldns_verify(rrs, signatures, dnskeys));
	
        return 0;
}
