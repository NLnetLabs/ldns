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

void
print_usage(char *file)
{
	printf("Usage: %s <type> <name>\n", file);
	exit(0);
}

int
main(int argc, char **argv)
{       
        ldns_resolver *res;
        ldns_rdf *qname;
	ldns_rdf *defdomain;
        ldns_pkt *pkt;
        char *name = NULL;
        char *type = NULL;
        
        if (argc < 3) {
        	print_usage(argv[0]);
	} else {
		type = argv[1];
		name = argv[2];
	}
                
        /* init */
        res = ldns_resolver_new_frm_file(NULL); 
        if (!res) {
		printf("resolver creation failed\n");
                return -1;
	}

	/* UDP query */
	ldns_resolver_set_usevc(res, false);
        qname = ldns_dname_new_frm_str(name);
	if (!qname) {
		printf("error making qname\n");
		return -1;
	}

        pkt = ldns_resolver_query(res, qname, ldns_get_rr_type_by_name(type), 0, LDNS_RD);
	if (!pkt)  {
		printf("error pkt sending\n");
	} else {
		ldns_pkt_print(stdout, pkt);
	}
        
        return 0;
}
