/**
 * An example ldns program
 * In semi-C code
 *
 * Setup a resolver
 * Query a nameserver
 * Print the result
 */

#include <ldns.h>

int 
main(void)
{
	ldns_resolver *Res;
	ldns_rdf *default_dom;
	ldns_rdf *qname;
	ldns_rr_type *qtype;
	ldns_pkt *pkt;

	/* init */
	Res = ldns_resolver_new();
	if (!Res)
		return 1;
	
	/* create a default domain and add it */
	default_dom = rdf_new_frm_str("miek.nl", LDNS_RDF_TYPE_DNAME);
	if (ldns_resolver_nameserver_push(Res, default_dom) !=
			LDNS_STATUS_OK)
		return 1;

	/* setup the question */
	qname = ldns_rdf_new_frm_str("www", LDNS_RDF_TYPE_DNAME);
	qtype = ldns_rr_type_new_frm_str("MX");

	/* fire it off */
	pkt = ldns_resolver_query(Res, qname, qtype, NULL);

	/* print the resulting pkt to stdout */
	ldns_pkt_print(Res, stdout);

	return 0;
}
