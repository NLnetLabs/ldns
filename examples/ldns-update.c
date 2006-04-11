/* $Id: ldns-update.c,v 1.1 2005/09/13 09:37:05 ho Exp $ */
/*
 * Example of the update functionality
 *
 * See the file LICENSE for the license
 */


#include "config.h"

#include <strings.h>
#include <ldns/dns.h>

/* dynamic update stuff */
ldns_resolver *
ldns_update_resolver_new(const char *fqdn, const char *zone,
    ldns_rr_class class, uint16_t port, ldns_tsig_credentials *tsig_cred, ldns_rdf **zone_rdf)
{
        ldns_resolver   *r1, *r2;
        ldns_pkt        *query = NULL, *resp;
        ldns_rr_list    *nslist, *iplist;
        ldns_rdf        *soa_zone, *soa_mname, *ns_name;
        size_t          i;
        ldns_status     s;

        if (class == 0) {
                class = LDNS_RR_CLASS_IN;
        }

        if (port == 0) {
                port = LDNS_PORT;
        }

        /* First, get data from /etc/resolv.conf */
        s = ldns_resolver_new_frm_file(&r1, NULL);
        if (s != LDNS_STATUS_OK) {
                return NULL;
        }

        r2 = ldns_resolver_new();
        if (!r2) {
                goto bad;
        }
        ldns_resolver_set_port(r2, port);

        /* TSIG key data available? Copy into the resolver. */
        if (tsig_cred) {
                ldns_resolver_set_tsig_algorithm(r2, ldns_tsig_algorithm(tsig_cred));
                ldns_resolver_set_tsig_keyname(r2, ldns_tsig_keyname_clone(tsig_cred));
                /*
                 * XXX Weird that ldns_resolver_deep_free() will free()
                 * keyname but not hmac key data?
                 */
                ldns_resolver_set_tsig_keydata(r2, ldns_tsig_keydata_clone(tsig_cred));
        }

        /* Now get SOA zone, mname, NS, and construct r2. [RFC2136 4.3] */

        /* Explicit 'zone' or no? */
        if (zone) {
                soa_zone = ldns_dname_new_frm_str(zone);
                if (ldns_update_soa_mname(soa_zone, r1, class, &soa_mname)
                    != LDNS_STATUS_OK)
                        goto bad;
        } else {
                if (ldns_update_soa_zone_mname(fqdn, r1, class, &soa_zone,
                        &soa_mname) != LDNS_STATUS_OK)
                        goto bad;
        }

        /* Pass zone_rdf on upwards. */
        *zone_rdf = ldns_rdf_clone(soa_zone);

        /* NS */
        query = ldns_pkt_query_new(soa_zone, LDNS_RR_TYPE_NS, class, LDNS_RD);
        if (!query)
                goto bad;
        soa_zone = NULL;

        ldns_pkt_set_random_id(query);

        if (ldns_resolver_send_pkt(&resp, r1, query) != LDNS_STATUS_OK) {
                dprintf("%s", "NS query failed!\n");
                goto bad;
        }
        ldns_pkt_free(query);
        if (!resp)
                goto bad;

        /* Match SOA MNAME to NS list, adding it first */
        nslist = ldns_pkt_answer(resp);
        for (i = 0; i < ldns_rr_list_rr_count(nslist); i++) {
                ns_name = ldns_rr_rdf(ldns_rr_list_rr(nslist, i), 0);
                if (!ns_name)
                        continue;
                if (ldns_rdf_compare(soa_mname, ns_name) == 0) {
                        /* Match */
                        iplist = ldns_get_rr_list_addr_by_name(r1, ns_name, class, 0);
                        (void) ldns_resolver_push_nameserver_rr_list(r2, iplist);
                        break;
                }
        }

        /* Then all the other NSs. XXX Randomize? */
        for (i = 0; i < ldns_rr_list_rr_count(nslist); i++) {
                ns_name = ldns_rr_rdf(ldns_rr_list_rr(nslist, i), 0);
                if (!ns_name)
                        continue;
                if (ldns_rdf_compare(soa_mname, ns_name) != 0) {
                        /* No match, add it now. */
                        iplist = ldns_get_rr_list_addr_by_name(r1, ns_name, class, 0);
                        (void) ldns_resolver_push_nameserver_rr_list(r2, iplist);
                }
        }

        ldns_resolver_set_random(r2, false);
        ldns_pkt_free(resp);
        ldns_resolver_deep_free(r1);
        return r2;

  bad:
        if (r1)
                ldns_resolver_deep_free(r1);
        if (r2)
                ldns_resolver_deep_free(r2);
        if (query)
                ldns_pkt_free(query);
        if (resp)
                ldns_pkt_free(resp);
        return NULL;
}

void
usage(FILE *fp, char *prog) {
        fprintf(fp, "%s domain [zone] ip tsig_name tsig_alg tsig_hmac\n", prog);
        fprintf(fp, "  send a dynamic update packet to <ip>\n\n");
        fprintf(fp, "  Use 'none' instead of ip to remove any previous address\n");
        fprintf(fp, "  If 'zone'  is not specified, try to figure it out from the zone's SOA\n");
        fprintf(fp, "  Example: %s my.example.org 1.2.3.4\n", prog);
}


int
main(int argc, char **argv)
{
	char		*fqdn, *ipaddr, *zone, *prog;
	ldns_status	ret;
	ldns_tsig_credentials	tsig_cr, *tsig_cred;
	int		c = 2;
	uint16_t	defttl = 300;
	uint16_t 	port = 5353;
	
	prog = strdup(argv[0]);

	switch (argc) {
	case 3:
	case 4:
	case 6:
	case 7:
		break;
	default:
		usage(stderr, prog);
		exit(EXIT_FAILURE);
	}

	fqdn = argv[1]; 
	c = 2;
	if (argc == 4 || argc == 7) {
		zone = argv[c++];
	} else {
		zone = NULL;
	}
	
	if (strcmp(argv[c], "none") == 0) {
		ipaddr = NULL;
	} else {
		ipaddr = argv[c];
	}
	c++;
	if (argc == 6 || argc == 7) {
		tsig_cr.keyname = argv[c++];
		if (strncasecmp(argv[c], "hmac-sha1", 9) == 0) {
			tsig_cr.algorithm = (char*)"hmac-sha1.";
		} else if (strncasecmp(argv[c], "hmac-md5", 8) == 0) {
			tsig_cr.algorithm = (char*)"hmac-md5.sig-alg.reg.int.";
		} else {
			fprintf(stderr, "Unknown algorithm, try \"hmac-md5\" "
			    "or \"hmac-sha1\".\n");
			exit(EXIT_FAILURE);
		}
		tsig_cr.keydata = argv[++c];
		tsig_cred = &tsig_cr;
	} else {
		tsig_cred = NULL;
	}

	printf(";; trying UPDATE with FQDN \"%s\" and IP \"%s\"\n",
	    fqdn, ipaddr ? ipaddr : "<none>");
	printf(";; tsig: \"%s\" \"%s\" \"%s\"\n", tsig_cr.keyname,
	    tsig_cr.algorithm, tsig_cr.keydata);

	ret = ldns_update_send_simple_addr(fqdn, zone, ipaddr, port, defttl, tsig_cred);
	exit(ret);
}
