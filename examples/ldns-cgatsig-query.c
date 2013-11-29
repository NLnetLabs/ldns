/*
 * Test CGA-TSIG, send query, verify CGA-TSIG in response.
 * (c) NLnet Labs, 2013
 * See the file LICENSE for the license
 *
 */

#include "config.h"
#include <ldns/ldns.h>

static int
usage(FILE *output) {
	fprintf(output, "Usage: ldns-cgatsig-query <qname> [<port>] [<no tsig>] [<resolver file>]\n");
	fprintf(output, "  query for <qname, A, IN>\n");
	return 0;
}

int
main(int argc, char *argv[])
{
	ldns_resolver *res = NULL;
	ldns_rdf *qname = NULL;
	ldns_rr_type qtype = LDNS_RR_TYPE_A;
	char *rin = NULL;
	uint16_t port = LDNS_PORT;
	int no_tsig = 0;
	ldns_pkt *p = NULL;
	ldns_rr_list *rrs = NULL;
	ldns_status s;

	/* get commandline arguments */
	if (argc < 2) {
		usage(stderr);
		exit(EXIT_FAILURE);
	} else {
		/* QNAME */
		qname = ldns_dname_new_frm_str(argv[1]);
		if (!qname) {
			usage(stderr);
			exit(EXIT_FAILURE);
		}
		if (argc > 2) {
			port = (uint16_t)atoi(argv[2]);
		}
		if (argc > 3) {
			no_tsig = atoi(argv[3]);
		}
		if (argc > 4) {
			rin = argv[4];
		}
	}
	/* create a new resolver from input file (or default /etc/resolv.conf) */

	/* adjust so that either resolv.conf contains address of ldnsd,
	   or set resolver with:
	   -ldns_resolver_set_source()
	   -ldns_resolver_set_port()
	 */
	s = ldns_resolver_new_frm_file(&res, rin);
	if (s != LDNS_STATUS_OK) {
		exit(EXIT_FAILURE);
	}

	if (!no_tsig) {
		ldns_resolver_set_tsig_keyname(res, "test.");
		ldns_resolver_set_tsig_algorithm(res, "cga-tsig.");
	}
	ldns_resolver_set_port(res, port);

	/* use the resolver to send a query */
	s = ldns_resolver_query_ws(&p, res, qname, qtype, LDNS_RR_CLASS_IN, LDNS_RD);
	ldns_rdf_deep_free(qname);

	if (!no_tsig) {
		printf("Status after TSIG verification: %s\n", ldns_get_errorstr_by_id(s));
	}

	if (s != LDNS_STATUS_OK && s != LDNS_STATUS_CRYPTO_TSIG_BOGUS) {
		exit(EXIT_FAILURE);
	}

//status = ldns_pkt_tsig_verify_2(ldns_pkt *pkt, uint8_t *wire, size_t wirelen, const char *key_name,
//	const char *key_data, ldns_rdf *orig_mac_rdf, const struct sockaddr_storage *ns_out, size_t ns_out_len)

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

	ldns_pkt_free(p);
	ldns_resolver_deep_free(res);
	return 0;
}
