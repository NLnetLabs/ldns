/**
 * An example ldns program
 *
 * Setup a resolver
 * Query a nameserver
 * Print the result
 */

#include <config.h>
#include <ldns/resolver.h>
#include <ldns/ldns.h>
        
int     
main(void)
{       
        ldns_resolver *res;
        ldns_rdf *default_dom;
        ldns_rdf *qname;
        ldns_rdf *nameserver;
        ldns_pkt *pkt;
                
        /* init */
        res = ldns_resolver_new(); 
        if (!res)
                return 1;

        /* create a default domain and add it */
        default_dom = ldns_rdf_new_frm_str("miek.nl.", LDNS_RDF_TYPE_DNAME);
	if (!default_dom) {
		printf("error default dom\n");
		return 1;
	}
        nameserver  = ldns_rdf_new_frm_str("127.0.0.1", LDNS_RDF_TYPE_A);
	if (!nameserver) {
		printf("error default dom\n");
		return 1;
	}

                
        ldns_resolver_set_domain(res, default_dom);

        if (ldns_resolver_push_nameserver(res, nameserver) != LDNS_STATUS_OK) {
		printf("error push nameserver\n");
                return 1;
	}
        if (ldns_resolver_push_nameserver(res, nameserver) != LDNS_STATUS_OK) {
		printf("error push nameserver\n");
                return 1;
	}

        /* setup the question */
        qname = ldns_rdf_new_frm_str("miekwww", LDNS_RDF_TYPE_DNAME);
	if (!qname) {
		printf("error making qname\n");
                return 1;
	}
        
        /* fire it off. "miek.nl." will be added */
        pkt = ldns_resolver_send(res, qname, LDNS_RR_TYPE_MX, 0, 0);

	if (!pkt)  {
		printf("error pkt sending\n");
	} else {
        
        /* print the resulting pkt to stdout */
/*
	        ldns_pkt_print(stdout, pkt);
*/
	        ldns_pkt_free(pkt);
	}

        ldns_rdf_free(qname);
        ldns_rdf_free(default_dom);
        ldns_rdf_free(nameserver);
        ldns_resolver_free(res);

        return 0;
}
