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
        ldns_pkt *pkt, *answer;
	ldns_rdf *qname;

        ldns_resolver *res;
        ldns_rdf *nameserver;
        ldns_rdf *mac;

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
                
	qname = ldns_dname_new_frm_str(name);

	pkt = ldns_pkt_query_new(qname, ldns_get_rr_type_by_name(type), 0, LDNS_RD);

	ldns_pkt_set_id(pkt, 46789);

	ldns_pkt_tsig_sign(pkt, "jelte.", "vBUWJnkgDw4YTobXtbUD6XED5Qg74tnghYX3tzKzfsI=", 300, "hmac-md5.sig-alg.reg.int", NULL);

	mac = ldns_rr_rdf(ldns_pkt_tsig(pkt), 3);
	/* test our own sign */
	if (!ldns_pkt_tsig_verify(pkt, "jelte.", "vBUWJnkgDw4YTobXtbUD6XED5Qg74tnghYX3tzKzfsI=", NULL)) {
		printf("Can't verify my own sig :(\n");
		exit(-1);
	}

        /* print the resulting pkt to stdout */
        printf("QUERY:\n");
        ldns_pkt_print(stdout, pkt);
        
        /* Send to resolver */
        
        /* init */
        res = ldns_resolver_new(); 
        if (!res)
                return -1;
        nameserver  = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, server_ip);
        if (ldns_resolver_push_nameserver(res, nameserver) != LDNS_STATUS_OK) {
                printf("error push nameserver\n");
                return -1;
        }

        answer = ldns_send(res, pkt);
        
        printf("\n\nANSWER:\n");
        ldns_pkt_print(stdout, answer);

        printf("\nVerifying...\n");
        
        if (ldns_pkt_tsig_verify(answer, "jelte.", "vBUWJnkgDw4YTobXtbUD6XED5Qg74tnghYX3tzKzfsI=", mac)) {
        	printf("Success!\n");
	} else {
		printf("Failed.\n");
	}
/*
        ldns_rdf_free(nameserver);
        ldns_rdf_free(qname);
        ldns_pkt_free(pkt);
        ldns_resolver_free(res);
*/
        return 0;
}
