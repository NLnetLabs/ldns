/*
 * chaos is a small programs that prints some information
 * about a nameserver
 */

#include <stdio.h>
#include <config.h>
#include <ldns/ldns.h>

int
usage(FILE *fp, char *prog) {
	fprintf(fp, "%s server\n", prog);
	fprintf(fp, "  print out some information about server\n");
	return 0;
}

int
main(int argc, char *argv[])
{
	ldns_resolver *res;
	ldns_rdf *name;
	ldns_rdf *version, *id;
	ldns_pkt *p;
	ldns_rr_list *addr;
	ldns_rr_list *info;
	size_t i;
	
	if (argc != 2) {
		usage(stdout, argv[0]);
		exit(1);
	} else {
		/* create a rdf from the command line arg */
		name = ldns_dname_new_frm_str(argv[1]);
		if (!name) {
			usage(stdout, argv[0]);
			exit(1);
		}
	}

	version = ldns_dname_new_frm_str("version.bind");
	id      = ldns_dname_new_frm_str("hostname.bind");

	/* create a new resolver from /etc/resolv.conf */
	res = ldns_resolver_new_frm_file(NULL);
	if (!res) {
		exit(1);
	}
	ldns_resolver_set_retry(res, 1); /* don't want to wait too long */
	
	/* use the resolver to send it a query for the a/aaaa of name */
	addr = ldns_get_rr_list_addr_by_name(res, name, LDNS_RR_CLASS_IN, LDNS_RD);
	if (!addr) {
		fprintf(stderr, " *** could not get an address for %s", argv[1]);
		exit(1);
	}
	/* remove old nameservers */
	for(; ldns_resolver_pop_nameserver(res);
		ldns_resolver_pop_nameserver(res)) { ; }

	/* can be multihomed */
	for(i = 0; i < ldns_rr_list_rr_count(addr); i++) {
		if (i > 0) {
			fprintf(stdout, "\n");
		}
			
		ldns_resolver_push_nameserver_rr(res,
				ldns_rr_list_rr(addr, i));

		ldns_rr_print(stdout, ldns_rr_list_rr(addr, i));
		fprintf(stdout, "\n");

		p = ldns_resolver_query(res, version, LDNS_RR_TYPE_TXT,
				LDNS_RR_CLASS_CH, LDNS_RD);
		if (p) {
			info = ldns_pkt_rr_list_by_type(p,
					LDNS_RR_TYPE_TXT, LDNS_SECTION_ANSWER);

			if (info) {
				ldns_rr_list_print(stdout, info);
			} else {
				printf(" *** version retrieval failed\n");
			}
		} else {
			printf(" *** query failed for %s\n", 
					ldns_rr2str(ldns_rr_list_rr(addr, i)));
			ldns_pkt_free(p);
		}

		p = ldns_resolver_query(res, id, LDNS_RR_TYPE_TXT,
				LDNS_RR_CLASS_CH, LDNS_RD);
		if (p) {
			info = ldns_pkt_rr_list_by_type(p,
					LDNS_RR_TYPE_TXT, LDNS_SECTION_ANSWER);
			if (info) {
				ldns_rr_list_print(stdout, info);
			} else {
				printf(" *** id retrieval failed\n");
			}
		} else {
			printf(" *** query failed for %s\n", 
					ldns_rr2str(ldns_rr_list_rr(addr, i)));
		}
		(void)ldns_resolver_pop_nameserver(res);

	}
	exit(0);
        return 0;
}
