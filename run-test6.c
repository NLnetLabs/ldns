/**
 * An example ldns program
 *
 * Setup a resolver
 * Query a nameserver
 * Print the result
 */

#include <config.h>
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
        nameserver  = ldns_rdf_new_frm_str("2001:7b8:206:1:211:2fff:fed7:7378", 
			LDNS_RDF_TYPE_AAAA);
	if (!nameserver) {
		printf("error in making NS\n");
		return 1;
	}

        ldns_resolver_set_domain(res, default_dom);

        if (ldns_resolver_push_nameserver(res, nameserver) != LDNS_STATUS_OK) {
		printf("error push nameserver\n");
                return 1;
	}

	/* hack to make the resolver appear to
	 * be configued - don't know if we need this
	 */
	ldns_resolver_set_configured(res, 1);
        
        /* setup the question */
        qname = ldns_rdf_new_frm_str("www.miek.nl", LDNS_RDF_TYPE_DNAME);
	if (!qname) {
		printf("error making qname\n");
                return 1;
	}
        
        /* fire it off. "miek.nl." will be added */
        pkt = ldns_resolver_send(res, qname, LDNS_RR_TYPE_MX, 0, LDNS_RD);

	if (!pkt)  {
		printf("error pkt sending\n");
		return 1;
	}
        
        /* print the resulting pkt to stdout */
        ldns_pkt_print(stdout, pkt);

        return 0;
}
