/**
 * An example ldns program
 *
 * Setup a resolver
 * Query a nameserver
 * Print the result
 */

#include <config.h>
#include <ldns/resolver.h>
        
int
main(void)
{       
        ldns_pkt *pkt;
	ldns_rdf *name;

	name = ldns_dname_new_frm_str("www.miek.nl");
	
	pkt = ldns_pkt_query_new(name, LDNS_RR_TYPE_AAAA, 0, LDNS_RD);
	ldns_pkt_set_answerfrom(pkt, name);
	ldns_pkt_print(stdout, pkt);

	pkt = ldns_pkt_query_new(name, LDNS_RR_TYPE_AAAA, 0, LDNS_RD);
	ldns_pkt_set_answerfrom(pkt, name);
	ldns_pkt_print(stdout, pkt);
	
	pkt = ldns_pkt_query_new(name, LDNS_RR_TYPE_AAAA, 0, LDNS_RD);
	ldns_pkt_set_answerfrom(pkt, name);
	ldns_pkt_print(stdout, pkt);
	
        return 0;
}
