/* 
 * test3, test functions in str2host
 *
 */

#include <config.h>
#include <ldns/ldns.h>
#include <ldns/str2host.h>

#include "util.h"

#define MAX_PACKET 10000

int
main(void)
{
	ldns_rdf *rd;

	fprintf(stdout, "www.\n");
	(void) ldns_str2rdf_dname(&rd, "www.");
	fprintf(stdout, "www.miek.nl\n");
	(void) ldns_str2rdf_dname(&rd, "www.miek.nl");
	fprintf(stdout, "www\n");
	(void) ldns_str2rdf_dname(&rd, "www");
	fprintf(stdout, "www.miek.nl..\n");
	(void) ldns_str2rdf_dname(&rd, "www.miek.nl..");

	return 0;
}
