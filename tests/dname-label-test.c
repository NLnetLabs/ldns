
/* lowlevel test functions */
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <stdbool.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif /* HAVE_STDINT_H */

#include <ldns/dns.h>

int
main(int argc, char **argv)
{
	ldns_rdf *test;
	ldns_rdf *test2;
	ldns_rdf *newlabel;

	test = ldns_dname_new_frm_str("bla.miek.nl");
	test2 = ldns_dname_new_frm_str("www.bla.miek.nl");

	ldns_rdf_print(stdout, test);
	printf("\n");

	newlabel = ldns_dname_label(test, -1);
	ldns_rdf_print(stdout, newlabel);
	printf("\n");
	ldns_rdf_deep_free(newlabel);

	newlabel = ldns_dname_label(test, 0);
	ldns_rdf_print(stdout, newlabel);
	printf("\n");
	ldns_rdf_deep_free(newlabel);

	newlabel = ldns_dname_label(test, 1);
	ldns_rdf_print(stdout, newlabel);
	printf("\n");
	ldns_rdf_deep_free(newlabel);

	newlabel = ldns_dname_label(test, 2);
	ldns_rdf_print(stdout, newlabel);
	printf("\n");
	ldns_rdf_deep_free(newlabel);

	newlabel = ldns_dname_label(test, 3);
	ldns_rdf_print(stdout, newlabel);
	printf("\n");
	ldns_rdf_deep_free(newlabel);

	newlabel = ldns_dname_label(test, 4);
	ldns_rdf_print(stdout, newlabel);
	printf("\n");
	ldns_rdf_deep_free(newlabel);

	newlabel = ldns_dname_label(test, 5);
	ldns_rdf_print(stdout, newlabel);
	printf("\n");
	ldns_rdf_deep_free(newlabel);

	(void)ldns_dname_is_subdomain(test2, test);
	
	return 0;
}
