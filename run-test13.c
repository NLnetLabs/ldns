/**
 * An example ldns program
 *
 * Setup a resolver
 * Query a nameserver
 * Print the result
 */

#include <config.h>
#include <ldns/resolver.h>
#include <ldns/dname.h>        
#include <ldns/host2str.h>

int
main(int argc, char **argv)
{       
	ldns_rr *RR;
        const char *nameserver_address = "127.0.0.1";

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

        return 0;
}
