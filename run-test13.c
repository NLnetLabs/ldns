/**
 * An example ldns program
 *
 * Setup a resolver
 * Query a nameserver
 * Print the result
 */

#include <config.h>
#include <ldns/dns.h>

int
main(int argc, char **argv)
{       
	ldns_rr *RR;
        const char *nameserver_address = "127.0.0.1";
	ldns_rr_list *keys_rrset;
	ldns_rr *sig;
	ldns_rr_list *rrset;


	keys_rrset = ldns_rr_list_new();
	rrset = ldns_rr_list_new();

	if (argc >= 2) {
		nameserver_address = argv[1];
	}
	
	RR = ldns_rr_new_frm_str("miek.nl. 3600 IN MX 10 elektron.atoom.net.");
	if (RR) {
		ldns_rr_print(stdout, RR);
		printf("\n");
	}
	RR = ldns_rr_new_frm_str("miek.nl.   3600   IN   MX  (\n\t10\n\telektron.atoom.net.\n\t)");
	if (RR) {
		ldns_rr_print(stdout, RR);
		printf("\n");
	}
	RR = ldns_rr_new_frm_str(" nlnetlabs.nl.           84236   IN      DNSKEY  257 3 5 AQPzzTWMz8qSWIQlfRnPckx2BiVmkVN6LPupO3mbz7FhLSnm26n6iG9NLby97Ji453aWZY3M5/xJBSOS2vWtco2t8C0+xeO1bc/d6ZTy32DHchpW6rDH1vp86Ll+ha0tmwyy9QP7y2bVw5zSbFCrefk8qCUBgfHm9bHzMG1UBYtEIQ==");

	if (RR) {
		ldns_rr_print(stdout, RR);
		printf("\n");
	}

	printf("\n*** Okay, now the real dnssec testing ***\n\n");

	ldns_rr_set_push_rr(keys_rrset,ldns_rr_new_frm_str("nlnetlabs.nl.       81310  IN  DNSKEY   257 3 RSASHA1 AQPzzTWMz8qSWIQlfRnPckx2BiVmkVN6LPupO3mbz7FhLSnm26n6iG9NLby97Ji453aWZY3M5/xJBSOS2vWtco2t8C0+xeO1bc/d6ZTy32DHchpW6rDH1vp86Ll+ha0tmwyy9QP7y2bVw5zSbFCrefk8qCUBgfHm9bHzMG1UBYtEIQ== ) ; {id = 43791} {sep}"));

	if (keys_rrset) {
		ldns_rr_list_print(stdout,keys_rrset);
		printf("\n");
	}
	
	ldns_rr_set_push_rr(rrset, ldns_rr_new_frm_str("www.nlnetlabs.nl.   86354  IN  A        213.154.224.1"));
	if (rrset) {
		ldns_rr_list_print(stdout,rrset);
		printf("\n");
	}

	sig = ldns_rr_new_frm_str("www.nlnetlabs.nl.   86400  IN  RRSIG    A RSASHA1 3 86400 1111020602 1108428602 ( 43791 nlnetlabs.nl.  Q/uyU1R/mLWsCONp5yu8F67Rm62yH/ts7PO3tFbZ72XONGlwliztUgHF5Cr0Jei/GsRb2TPpyHZjr5lkeFQU/PnFeUmiKT1tTw24OcYXaiFWbEsZ+ormYGtq+2t5cwvYEbZsMMsMikv+VRmG1y6b8sNObAeIjtRZhrXogQolCm4= )");

	/* try to verify some things */
	

        return 0;
}
