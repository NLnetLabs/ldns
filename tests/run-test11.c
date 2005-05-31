/**
 * An example ldns program
 *
 * Setup a resolver
 * Query a nameserver
 * Print the result
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <stdbool.h>

#include <stdint.h>

#include <ldns/dns.h>


void
print_usage(char *file)
{
	printf("AXFR example\n");
	printf("Usage: %s <domain> <server ip>\n", file);
	printf("ipv4 only atm\n");
	exit(0);
}

int
main(int argc, char **argv)
{       
        ldns_rdf *nameserver;
        ldns_rdf *domain;
        
        ldns_resolver *resolver;
        ldns_rr *rr = NULL;

        char *server_ip = NULL;
        char *name = NULL;
        char *rr_str;
        
	/* Get the domain and the nameserver from the command line */
        if (argc < 3) {
        	print_usage(argv[0]);
	} else {
		name = argv[1];
		server_ip = argv[2];
	}

        nameserver  = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, server_ip);
	if (!nameserver) {
		printf("Bad server ip\n");
		return -1;
	}
	
	resolver = ldns_resolver_new();
	ldns_resolver_set_usevc(resolver, true);
	(void) ldns_resolver_push_nameserver(resolver, nameserver);
	
	domain = ldns_dname_new_frm_str(name);
	if (!domain) {
		printf("Bad domain\n");
	}
	
	(void) ldns_axfr_start(resolver, domain, LDNS_RR_CLASS_IN);
	
	while ((rr = ldns_axfr_next(resolver))) {
		rr_str = ldns_rr2str(rr);
		printf("%s\n", rr_str);
		ldns_rr_free(rr);
		LDNS_FREE(rr_str);
	}

	
        ldns_rdf_free(nameserver);
        ldns_rdf_free(domain);
        ldns_resolver_free(resolver);
        
        return 0;
}
