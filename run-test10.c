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
main(void)
{       
        ldns_pkt *pkt;
	ldns_rdf *name;
	ldns_rdf *qname;

        ldns_resolver *res;
        ldns_rdf *nameserver;
        
        /* init */
        res = ldns_resolver_new(); 
        if (!res)
                return -1;
        nameserver  = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, "127.0.0.1");
        if (ldns_resolver_push_nameserver(res, nameserver) != LDNS_STATUS_OK) {
                printf("error push nameserver\n");
                return -1;
        }

        qname = ldns_dname_new_frm_str("www.miek.nl.");

        pkt = ldns_resolver_send(res, qname, LDNS_RR_TYPE_A, 0, LDNS_RD);
        if (pkt) {
                ldns_pkt_print(stdout, pkt);
        }
        ldns_pkt_free(pkt);

        pkt = ldns_resolver_send(res, qname, LDNS_RR_TYPE_A, 0, LDNS_RD);
        if (pkt) {
                ldns_pkt_print(stdout, pkt);
        }
        ldns_pkt_free(pkt);

	name = ldns_dname_new_frm_str("www.miek.nl");
	
	pkt = ldns_pkt_query_new(name, LDNS_RR_TYPE_AAAA, 0, LDNS_RD);
	ldns_pkt_print(stdout, pkt);
	/* this free also frees the ldns_rdf variable 'name' */
        ldns_pkt_free(pkt);

	ldns_rdf_free(qname);
        ldns_rdf_free(nameserver);
        ldns_resolver_free(res);

        return 0;
}
