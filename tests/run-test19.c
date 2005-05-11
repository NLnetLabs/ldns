/*
 * mx is a small programs that prints out the mx records
 * for a particulary domain
 */

#include <ldns/dns.h>
#include <stdio.h>

int
usage(FILE *fp, char *prog) {
	fprintf(fp, "%s keygen\n", prog);
	fprintf(fp, "  generate a DNSKEY RR \n");
	return 0;
}

int
main()
{
	ldns_resolver *r;
	ldns_rdf *aaaa;
	ldns_rr_list *hosts;

	r = ldns_resolver_new_frm_file(NULL);
	if (!r) {
		printf("something wrong?\n");
	}

	printf("::0\n");
	aaaa = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_AAAA, "::0");
	ldns_rdf_print(stdout, aaaa);
	printf("\n\n");
	printf("0::1\n");
	aaaa = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_AAAA, "0::1");
	ldns_rdf_print(stdout, aaaa);
	printf("\n\n");
	printf("0::0\n");
	aaaa = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_AAAA, "0::0");
	ldns_rdf_print(stdout, aaaa);
	printf("\n\n");
	printf("ff:192.168.1.1\n");
	aaaa = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_AAAA, "ff:192.168.1.1");
	ldns_rdf_print(stdout, aaaa);
	printf("\n\n");
	printf("::A0\n");
	aaaa = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_AAAA, "::A0");
	ldns_rdf_print(stdout, aaaa);
	printf("\n\n");
	printf("FF:0:0:0:0::1\n");
	aaaa = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_AAAA, "FF:0:0:0:0::1");
	ldns_rdf_print(stdout, aaaa);
	printf("\n\n");
	printf("FF:0:0:0:1::0\n");
	aaaa = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_AAAA, "FF:0:0:0:1::0");
	ldns_rdf_print(stdout, aaaa);
	printf("\n\n");
	printf("FF:0:0:0:1::0:1\n");
	aaaa = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_AAAA, "FF:0:0:0:1::0:1");
	ldns_rdf_print(stdout, aaaa);
	printf("\n\n");

	/*
	hosts = ldns_get_rr_list_hosts_frm_file(NULL);
	ldns_rr_list_print(stdout, hosts);
	*/
	
	return 0;
}
