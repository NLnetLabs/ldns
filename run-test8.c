/**
 * An example ldns program
 *
 * Setup a resolver
 * Query a nameserver
 * Print the result
 */

#include <config.h>
#include <ldns/resolver.h>
        

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
	ldns_rdf *defdomain;
        ldns_pkt *pkt;
        char *server_ip;
        char *name;
        char *type;
        
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
                return -1;

        nameserver  = ldns_rdf_new_frm_str(server_ip, LDNS_RDF_TYPE_A);
	if (!nameserver) {
		printf("Bad server ip\n");
		return -1;
	}
	defdomain = ldns_dname_new_frm_str("miek.nl");
	ldns_resolver_set_domain(res, defdomain);
	ldns_resolver_set_defnames(res, true);

        if (ldns_resolver_push_nameserver(res, nameserver) != LDNS_STATUS_OK) {
		printf("error push nameserver\n");
		return -1;
	}
	/* HACK */
	ldns_resolver_set_configured(res, 1);
	/* UDP query */
	ldns_resolver_set_usevc(res, false);
        qname = ldns_rdf_new_frm_str(name, LDNS_RDF_TYPE_DNAME);
	if (!qname) {
		printf("error making qname\n");
		return -1;
	}
        
        pkt = ldns_resolver_send(res, qname, ldns_rr_get_type_by_name(type), 0, LDNS_RD);
	if (!pkt)  {
		printf("error pkt sending\n");
	} else {
	}
        pkt = ldns_resolver_send(res, qname, ldns_rr_get_type_by_name(type), 0, LDNS_RD);
	if (!pkt)  {
		printf("error pkt sending\n");
	} else {
	}

        pkt = ldns_resolver_query(res, qname, ldns_rr_get_type_by_name(type), 0, LDNS_RD);
	if (!pkt)  {
		printf("error pkt sending\n");
	} else {
	}
        
        return 0;
}
