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
doit(void)
{       
        ldns_rdf *a_rec;
        ldns_rdf *aaaa_rec;
        ldns_rdf *rev;

	rev = a_rec = NULL;
	
        a_rec = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, "192.168.10.1");
        rev = ldns_rdf_address_reverse(a_rec);

        printf("printing the reverse of\n");
	if (a_rec)
	        ldns_rdf_print(stdout, a_rec);
        printf("\n");

        /* this should be someones reverse.. */
	if (rev)
	        ldns_rdf_print(stdout, rev);
        printf("\n");

	aaaa_rec = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_AAAA, "2001:7b8:206:1::53");
        printf("printing the reverse of\n");
	if (aaaa_rec)
	        ldns_rdf_print(stdout, aaaa_rec);
        printf("\n");

        rev = ldns_rdf_address_reverse(aaaa_rec);
        /* this should be someones reverse.. */
	if (rev)
	        ldns_rdf_print(stdout, rev);
        printf("\n");
}       

int
main(void)
{
	ldns_rr *ns;
	ldns_rr_list *list;
	ldns_resolver *res;
	ldns_rdf **nss;
	size_t i;

#if 0
	printf("Test some simple ipvX reverse functions\n");
	doit();
	doit();
	doit();
	doit();
#endif
	
	res = ldns_resolver_new();
	list = ldns_rr_list_new();

	ns = ldns_rr_new_frm_str("a.root-servers.net. 3600 IN A  198.41.0.1");
	ldns_rr_list_push_rr(list, ns);
	ns = ldns_rr_new_frm_str("a.root-servers.net. 3600 IN A  198.41.0.2");
	ldns_rr_list_push_rr(list, ns);
	ns = ldns_rr_new_frm_str("a.root-servers.net. 3600 IN A  198.41.0.3");
	ldns_rr_list_push_rr(list, ns);
	printf("\nrr:\n");
	ldns_rr_print(stdout, ns);
	printf("\nlist:\n");
	ldns_rr_list_print(stdout, list);
	printf("------\n");

	/*ldns_resolver_push_nameserver_rr(res, ns);*/
	if (ldns_resolver_push_nameserver(res, ldns_rr_rdf(ns,0)) != LDNS_STATUS_OK) {
		printf("err\n");
	}
	if (ldns_resolver_push_nameserver(res, ldns_rr_rdf(ns,0)) != LDNS_STATUS_OK) {
		printf("err\n");
	}
	printf("the whole shebang\n");
	ldns_resolver_push_nameserver_rr_list(res, list);
	ldns_resolver_push_nameserver_rr_list(res, list);
	ldns_resolver_push_nameserver_rr_list(res, list);
	ldns_resolver_push_nameserver_rr_list(res, list);
	ldns_resolver_push_nameserver_rr_list(res, list);
	ldns_resolver_push_nameserver_rr_list(res, list);
	ldns_resolver_push_nameserver_rr_list(res, list);
	
	nss = ldns_resolver_nameservers(res);
	if (!nss) {
		printf("ook hier gaat wat fout!\n");
	}
	for (i = 0; i < ldns_resolver_nameserver_count(res); i++) {
		ldns_rdf_print(stdout, nss[i]);
		printf("\n");
	}
	printf("removing whole shebang\n");

	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_push_nameserver_rr_list(res, list);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_push_nameserver_rr_list(res, list);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);
	ldns_resolver_pop_nameserver(res);

	printf("printing what is left\n");
	nss = ldns_resolver_nameservers(res);

	for (i = 0; i < ldns_resolver_nameserver_count(res); i++) {
		ldns_rdf_print(stdout, nss[i]);
		printf("\n");
	}

	return 0;
}
