/*
 * Test CGA-TSIG, send query, verify CGA-TSIG in response.
 * (c) NLnet Labs, 2013
 * See the file LICENSE for the license
 *
 */

#include "config.h"
#include <ldns/ldns.h>

static int
usage(FILE *fp, char *prog) {
	fprintf(fp, "%s qname qtype \n", prog);
	fprintf(fp, "  query for <qname, qtype, IN>\n");
	return 0;
}

int
main(int argc, char *argv[])
{
	ldns_resolver *res;
	ldns_rdf *qname;
	ldns_rr_type qtype = LDNS_RR_TYPE_A;
	ldns_pkt *p;
	ldns_rr_list *rrs;
	ldns_status s;
	p = NULL;
	rrs = NULL;
	qname = NULL;
	res = NULL;
	/* get commandline arguments */
	if (argc != 2) {
		usage(stdout, argv[0]);
		exit(EXIT_FAILURE);
	} else {
		/* QNAME */
		qname = ldns_dname_new_frm_str(argv[1]);
		if (!qname) {
			usage(stdout, argv[0]);
			exit(EXIT_FAILURE);
		}
		/* QTYPE */
	}
	/* create a new resolver from /etc/resolv.conf */

	/* adjust so that either resolv.conf contains address of ldnsd,
	   or set resolver with:
	   -ldns_resolver_set_source()
	   -ldns_resolver_set_port()
	 */
	s = ldns_resolver_new_frm_file(&res, NULL);
	if (s != LDNS_STATUS_OK) {
		exit(EXIT_FAILURE);
	}
	/* use the resolver to send a query */
	p = ldns_resolver_query(res, qname, qtype, LDNS_RR_CLASS_IN, LDNS_RD);
	ldns_rdf_deep_free(qname);
        if (!p)  {
		exit(EXIT_FAILURE);
        } else {
		/* Get CGA-TSIG from packet */

		/* Do CGA-TSIG verification */

		/* retrieve the resource records from the answer section */
		rrs = ldns_pkt_rr_list_by_type(p, qtype, LDNS_SECTION_ANSWER);
		if (!rrs) {
			fprintf(stderr,
				" *** invalid answer name %s after query for %s\n",
				argv[1], argv[1]);
                        ldns_pkt_free(p);
                        ldns_resolver_deep_free(res);
			exit(EXIT_FAILURE);
		} else {
			ldns_rr_list_sort(rrs);
			ldns_rr_list_print(stdout, rrs);
			ldns_rr_list_deep_free(rrs);
		}
        }
        ldns_pkt_free(p);
        ldns_resolver_deep_free(res);
        return 0;
}
