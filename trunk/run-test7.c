/**
 * An example ldns program
 *
 * Setup a resolver
 * Query a nameserver
 * Print the result
 */

#include <config.h>
#include <ldns/dns.h>

void
print_usage(char *file)
{
	printf("Usage: %s <type> <name> <server ip>\n", file);
	printf("ipv4 only atm\n");
	exit(0);
}

int     
main(int argc, char **argv)
{       
        ldns_resolver *res;
        ldns_rdf *qname;
        ldns_rdf *nameserver;
	ldns_rdf *default_dom;
        ldns_pkt *pkt;
        char *server_ip = NULL;
        char *name = NULL;
        char *type = NULL;
        
        if (argc < 4) {
        	print_usage(argv[0]);
	} else {
		type = argv[1];
		name = argv[2];
		server_ip = argv[3];
	}
                
        /* init */
        res = ldns_resolver_new(); 
        if (!res)
                return 1;

        /* create a default domain and add it */

        default_dom = ldns_dname_new_frm_str("miek.nl.");
#if 0
        ldns_resolver_set_domain(res, default_dom);
	ldns_resolver_set_defnames(res, true); /* use the suffix */
#endif

        nameserver  = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, server_ip);
	if (!nameserver) {
		printf("Bad server ip\n");
		return 1;
	}



        if (ldns_resolver_push_nameserver(res, nameserver) != LDNS_STATUS_OK) {
		printf("error push nameserver\n");
                return 1;
	}
        /* setup the question */
        qname = ldns_dname_new_frm_str(name);
	if (!qname) {
		printf("error making qname\n");
                return 1;
	}
        
        pkt = ldns_resolver_query(res, qname, ldns_get_rr_type_by_name(type), 0, LDNS_RD);

	if (!pkt)  {
		printf("error pkt sending\n");
		return 1;
	}
                
        /* print the resulting pkt to stdout */
        ldns_pkt_print(stdout, pkt);

        ldns_rdf_free(nameserver);
        ldns_rdf_free(qname);
        ldns_pkt_free(pkt);
        ldns_resolver_free(res);
        return 0;
}
