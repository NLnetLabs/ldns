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
#include <ldns/ldns.h>

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

	if (verbosity < 5) {
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

	if (verbosity < 5) {
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
/*
 * generic function to get some RRset from a nameserver
 * and possible some signatures too (that would be the day...)
 */
ldns_pkt_type
get_dnssec_rr(ldns_pkt *p, ldns_rdf *name, ldns_rr_type t, 
	ldns_rr_list **rrlist, ldns_rr_list **sig)
{
	ldns_pkt_type pt = LDNS_PACKET_UNKNOWN;
	ldns_rr_list *rr = NULL;
	ldns_rr_list *sigs = NULL;
	size_t i;

	if (!p) {
		return LDNS_PACKET_UNKNOWN;
	}

	pt = ldns_pkt_reply_type(p);
	if (name) {
		rr = ldns_pkt_rr_list_by_name_and_type(p, name, t, LDNS_SECTION_ANSWER);
		if (!rr) {
			rr = ldns_pkt_rr_list_by_name_and_type(p, name, t, LDNS_SECTION_AUTHORITY);
		}
		sigs = ldns_pkt_rr_list_by_name_and_type(p, name, LDNS_RR_TYPE_RRSIG, 
				LDNS_SECTION_ANSWER);
		if (!sigs) {
		sigs = ldns_pkt_rr_list_by_name_and_type(p, name, LDNS_RR_TYPE_RRSIG, 
				LDNS_SECTION_AUTHORITY);
		}
	} else {
               /* A DS-referral - get the DS records if they are there */
               rr = ldns_pkt_rr_list_by_type(p, t, LDNS_SECTION_AUTHORITY);
               sigs = ldns_pkt_rr_list_by_type(p, LDNS_RR_TYPE_RRSIG,
                               LDNS_SECTION_AUTHORITY);
	}
	if (sig) {
		*sig = ldns_rr_list_new();
		for (i = 0; i < ldns_rr_list_rr_count(sigs); i++) {
			/* only add the sigs that cover this type */
			if (ldns_rdf2rr_type(ldns_rr_rrsig_typecovered(ldns_rr_list_rr(sigs, i))) ==
			    t) {
			 	ldns_rr_list_push_rr(*sig, ldns_rr_clone(ldns_rr_list_rr(sigs, i)));   
			}
		}
	}
	ldns_rr_list_deep_free(sigs);
	if (rrlist) {
		*rrlist = rr;
	}

	if (pt == LDNS_PACKET_NXDOMAIN || pt == LDNS_PACKET_NODATA) {
		return pt;
	} else {
		return LDNS_PACKET_ANSWER;
	}
}


ldns_status
ldns_verify_denial(ldns_pkt *pkt, ldns_rdf *name, ldns_rr_type type, ldns_rr_list **nsec_rrs, ldns_rr_list **nsec_rr_sigs)
{
	uint16_t nsec_i;

	ldns_rr_list *nsecs;
	ldns_status result;
	
	if (verbosity >= 5) {
		printf("VERIFY DENIAL FROM:\n");
		ldns_pkt_print(stdout, pkt);
	}

	result = LDNS_STATUS_CRYPTO_NO_RRSIG;
	/* Try to see if there are NSECS in the packet */
	nsecs = ldns_pkt_rr_list_by_type(pkt, LDNS_RR_TYPE_NSEC, LDNS_SECTION_ANY_NOQUESTION);
	if (nsecs) {
		for (nsec_i = 0; nsec_i < ldns_rr_list_rr_count(nsecs); nsec_i++) {
			/* there are four options:
			 * - name equals ownername and is covered by the type bitmap
			 * - name equals ownername but is not covered by the type bitmap
			 * - name falls within nsec coverage but is not equal to the owner name
			 * - name falls outside of nsec coverage
			 */
			if (ldns_dname_compare(ldns_rr_owner(ldns_rr_list_rr(nsecs, nsec_i)), name) == 0) {
				/*
				printf("CHECKING NSEC:\n");
				ldns_rr_print(stdout, ldns_rr_list_rr(nsecs, nsec_i));
				printf("DAWASEM\n");
				*/
				if (ldns_nsec_bitmap_covers_type(ldns_rr_rdf(ldns_rr_list_rr(nsecs, nsec_i), 2), type)) {
					/* Error, according to the nsec this rrset is signed */
					result = LDNS_STATUS_CRYPTO_NO_RRSIG;
				} else {
					/* ok nsec denies existence */
					if (verbosity >= 3) {
						printf(";; Existence of data set with this type denied by NSEC\n");
					}
						/*printf(";; Verifiably insecure.\n");*/
						if (nsec_rrs && nsec_rr_sigs) {
							(void) get_dnssec_rr(pkt, ldns_rr_owner(ldns_rr_list_rr(nsecs, nsec_i)), LDNS_RR_TYPE_NSEC, nsec_rrs, nsec_rr_sigs);
						}
						ldns_rr_list_deep_free(nsecs);
						return LDNS_STATUS_OK;
				}
			} else if (ldns_nsec_covers_name(ldns_rr_list_rr(nsecs, nsec_i), name)) {
				if (verbosity >= 3) {
					printf(";; Existence of data set with this name denied by NSEC\n");
				}
				if (nsec_rrs && nsec_rr_sigs) {
					(void) get_dnssec_rr(pkt, ldns_rr_owner(ldns_rr_list_rr(nsecs, nsec_i)), LDNS_RR_TYPE_NSEC, nsec_rrs, nsec_rr_sigs);
				}
				ldns_rr_list_deep_free(nsecs);
				return LDNS_STATUS_OK;
			} else {
				/* nsec has nothing to do with this data */
			}
		}
		ldns_rr_list_deep_free(nsecs);
	}
	return result;
}

