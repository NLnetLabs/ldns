/*
 * dnssec.c
 * Some DNSSEC helper function are defined here
 * and tracing is done
 * (c) 2005 NLnet Labs
 *
 * See the file LICENSE for the license
 *
 */

#include "drill.h"
#include <ldns/dns.h>

/* get rr_type from a server from a server */
ldns_rr_list *
get_rr(ldns_resolver *res, ldns_rdf *zname, ldns_rr_type t, ldns_rr_class c)
{
	/* query, retrieve, extract and return */
	ldns_pkt *p;
	ldns_rr_list *found;

	p = ldns_pkt_new();
	found = NULL;

	if (ldns_resolver_send(&p, res, zname, t, c, 0) != LDNS_STATUS_OK) {
		/* oops */
		return NULL;
	} else {
		found = ldns_pkt_rr_list_by_type(p, t, LDNS_SECTION_ANY_NOQUESTION);
	}
	return found;
}

void
drill_pkt_print(FILE *fd, ldns_resolver *r, ldns_pkt *p)
{
	ldns_rr_list *new_nss;
	ldns_rr_list *hostnames;

	if (qdebug == -1) {
		return;
	}

	hostnames = ldns_get_rr_list_name_by_addr(r, ldns_pkt_answerfrom(p), 0, 0);

	new_nss = ldns_pkt_rr_list_by_type(p,
			LDNS_RR_TYPE_NS, LDNS_SECTION_ANSWER);
	ldns_rr_list_print(fd, new_nss);

	/* new_nss can be empty.... */

	fprintf(fd, ";; Received %d bytes from %s#%d(",
			(int) ldns_pkt_size(p),
			ldns_rdf2str(ldns_pkt_answerfrom(p)),
			(int) ldns_resolver_port(r));
	/* if we can resolve this print it, other print the ip again */
	if (hostnames) {
		ldns_rdf_print(fd,
				ldns_rr_rdf(ldns_rr_list_rr(hostnames, 0), 0));
		ldns_rr_list_deep_free(hostnames);
	} else {
		fprintf(fd, "%s", ldns_rdf2str(ldns_pkt_answerfrom(p)));
	}
	fprintf(fd, ") in %u ms\n\n", (unsigned int)ldns_pkt_querytime(p));
}

void
drill_pkt_print_footer(FILE *fd, ldns_resolver *r, ldns_pkt *p)
{
	ldns_rr_list *hostnames;

	if (qdebug == -1) {
		return;
	}

	hostnames = ldns_get_rr_list_name_by_addr(r, ldns_pkt_answerfrom(p), 0, 0);

	fprintf(fd, ";; Received %d bytes from %s#%d(",
			(int) ldns_pkt_size(p),
			ldns_rdf2str(ldns_pkt_answerfrom(p)),
			(int) ldns_resolver_port(r));
	/* if we can resolve this print it, other print the ip again */
	if (hostnames) {
		ldns_rdf_print(fd,
				ldns_rr_rdf(ldns_rr_list_rr(hostnames, 0), 0));
		ldns_rr_list_deep_free(hostnames);
	} else {
		fprintf(fd, "%s", ldns_rdf2str(ldns_pkt_answerfrom(p)));
	}
	fprintf(fd, ") in %u ms\n\n", (unsigned int)ldns_pkt_querytime(p));
}
