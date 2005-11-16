/*
 * mx is a small programs that prints out the mx records
 * for a particulary domain
 * (c) NLnet Labs, 2005
 * See the file LICENSE for the license
 */

#include "config.h"

#include <ldns/dns.h>

int
usage(FILE *fp, char *prog) {
	fprintf(fp, "%s domain\n", prog);
	fprintf(fp, "  print out the inception and expiration dates\n");
	fprintf(fp, "  in a more human readable form\n");
	fprintf(fp, "  -t <type>\tquery for RRSIG(<type>)\n");
	return 0;
}

int
main(int argc, char *argv[])
{
	ldns_resolver *res;
	ldns_resolver *localres;
	ldns_rdf *domain;
	ldns_pkt *p;
	ldns_rr_list *rrsig;
	ldns_rr_list *rrsig_type;
	ldns_rr_list *ns;
	ldns_rr_list *ns_ip;
	uint8_t i, j;
	ldns_rr_type t;
	time_t incep, expir;
	char incep_buf[26];
	char expir_buf[26];
	
	p = NULL;
	rrsig = NULL;
	rrsig_type = NULL;
	domain = NULL;
	res = NULL;
	localres = NULL;
	t = LDNS_RR_TYPE_SOA; /* can be overruled on the cmd line, -t switch */

	/* option parsing */
	
	if (argc != 2) {
		usage(stdout, argv[0]);
		exit(EXIT_FAILURE);
	} else {
		/* create a rdf from the command line arg */
		domain = ldns_dname_new_frm_str(argv[1]);
		if (!domain) {
			usage(stdout, argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	/* create a new resolver from /etc/resolv.conf */
	localres = ldns_resolver_new_frm_file(NULL);

	if (!localres) {
		exit(EXIT_FAILURE);
	}
	/* first get the nameserver of the domain in question */
	p = ldns_resolver_query(localres, domain, LDNS_RR_TYPE_NS,
				LDNS_RR_CLASS_IN, LDNS_RD);
	if (!p) {
		fprintf(stderr," *** Could not find any nameserver for %s", argv[1]);
		exit(EXIT_FAILURE);
	}
	ns = ldns_pkt_rr_list_by_type(p, LDNS_RR_TYPE_NS, LDNS_SECTION_ANSWER);

	if (!ns) {
		fprintf(stderr," *** Could not find any nameserver for %s", argv[1]);
		exit(EXIT_FAILURE);
	}

	/* use our local resolver to resolv the names in the for usage in our
	 * new resolver */
	res = ldns_resolver_new();
	if (!res) {
		exit(EXIT_FAILURE);
	}
	for(i = 0; i < ldns_rr_list_rr_count(ns); i++) {
		ns_ip = ldns_get_rr_list_addr_by_name(localres,
			ldns_rr_ns_nsdname(ldns_rr_list_rr(ns, i)),
			LDNS_RR_CLASS_IN, LDNS_RD);
		/* add these to new resolver */
		for(j = 0; j < ldns_rr_list_rr_count(ns_ip); j++) {
			ldns_resolver_push_nameserver(res,
				ldns_rr_a_address(ldns_rr_list_rr(ns_ip, j)));
		}

	}

	/* enable DNSSEC */
	ldns_resolver_set_dnssec(res, true);
	/* also set CD, we want EVERYTHING! */
	ldns_resolver_set_dnssec_cd(res, true);

	/* use the resolver to send it a query for the mx 
	 * records of the domain given on the command line
	 */
	p = ldns_resolver_query(res, domain, LDNS_RR_TYPE_RRSIG, LDNS_RR_CLASS_IN, LDNS_RD);

	ldns_rdf_deep_free(domain);
	
        if (!p)  {
		exit(EXIT_FAILURE);
        } else {
		/* retrieve the RRSIG records from the answer section of that
		 * packet
		 */
		rrsig = ldns_pkt_rr_list_by_type(p, LDNS_RR_TYPE_RRSIG, LDNS_SECTION_ANSWER);
		if (!rrsig) {
			fprintf(stderr, 
					" *** invalid answer name %s after RRSIG query for %s\n",
					argv[1], argv[1]);
                        ldns_pkt_free(p);
                        ldns_resolver_deep_free(res);
			exit(EXIT_FAILURE);
		} else {
			rrsig_type = ldns_rr_list_new();

			/* okay, this needs to be doctered out, the rdf type
			 * is LDNS_RDF_TYPE_TYPE, but I need to compare it
			 * with LDNS_RR_TYPEs. How to convert, do we want to 
			 * convert? XXX */
			/*
			for(i = 0; i < ldns_rr_list_rr_count(rrsig); i++) {
				if (ldns_rr_get_type(
					ldns_rr_rrsig_typecovered(
					ldns_rr_list_rr(rrsig, i))) == t) {
					ldns_rr_list_push_rr(rrsig_type,
						ldns_rr_list_rr(rrsig, i));
				}
			}
			*/ 
			/* FOR NOW TAKE ONLY THE FIRST ONE */
			ldns_rr_list_push_rr(rrsig_type,
				ldns_rr_list_rr(rrsig, 0));

			for(i = 0; i < ldns_rr_list_rr_count(rrsig_type); i++) {
				incep = ldns_rdf2native_time_t(
					ldns_rr_rrsig_inception(
					ldns_rr_list_rr(rrsig_type, i)));
				expir = ldns_rdf2native_time_t(
					ldns_rr_rrsig_expiration(
					ldns_rr_list_rr(rrsig_type, i)));

				/* convert to human readable */
				ctime_r(&incep, incep_buf);
				ctime_r(&expir, expir_buf);
				/* kill the newline */
				incep_buf[24] = '\0';
				expir_buf[24] = '\0';

				/* assume SOA XXX*/
				fprintf(stdout, "%s RRSIG(SOA):  %s - %s\n",
					argv[1], incep_buf, expir_buf);


			}

		}
        }
        ldns_pkt_free(p);
        ldns_resolver_deep_free(res);
        return 0;
}
