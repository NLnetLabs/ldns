/*
 * ldns-keyfetcher retrieves the DNSKEYS for a certain domain
 * for a particulary domain
 * It traces the authoritatives nameservers down from the root
 * And uses TCP, to minimize spoofing danger.
 * (c) NLnet Labs, 2006
 * See the file LICENSE for the license
 */

#include "config.h"
#include <ldns/dns.h>
#include <errno.h>

int verbosity = 0;

void
usage(FILE *fp, char *prog) {
	fprintf(fp, "%s domain\n", prog);
	fprintf(fp, "  retrieve out the dnskeys for domain\n");
	fprintf(fp, "Options:\n");
	fprintf(fp, "-h\t\tShow this help\n");
	fprintf(fp, "-r <file>\tUse file to read root hints from\n");
	fprintf(fp, "-v <int>\tVerbosity level (0-5, not verbose-very verbose)\n");
}

ldns_rr_list *
retrieve_dnskeys(ldns_resolver *local_res, ldns_rdf *name, ldns_rr_type t,
		ldns_rr_class c, ldns_rr_list *dns_root)
{
	ldns_resolver *res;
	ldns_pkt *p;
	ldns_rr_list *new_nss_a;
	ldns_rr_list *new_nss_aaaa;
	ldns_rr_list *final_answer;
	ldns_rr_list *new_nss;
	ldns_rr_list *ns_addr;
	ldns_rr_list *ns_addr2;
	uint16_t loop_count;
	ldns_rdf *pop; 
	ldns_status status;
	size_t i;

	size_t nss_i;
	ldns_rr_list *answer_list = NULL;
	ldns_rr_list *authority_list = NULL;
	
	size_t last_nameserver_count;
	ldns_rdf **last_nameservers;

	loop_count = 0;
	new_nss_a = NULL;
	new_nss_aaaa = NULL;
	new_nss = NULL;
	ns_addr = NULL;
	ns_addr2 = NULL;
	final_answer = NULL;
	p = ldns_pkt_new();
	res = ldns_resolver_new();
	
	if (!p || !res) {
                fprintf(stderr, "Memory allocation failed");
                return NULL;
        }

	if (verbosity >= 2) {
		printf("Finding dnskey data for zone: ");
		ldns_rdf_print(stdout, name);
		printf("\n");
	}

	/* transfer some properties of local_res to res,
	 * because they were given on the commandline */
	ldns_resolver_set_ip6(res, 
			ldns_resolver_ip6(local_res));
	ldns_resolver_set_port(res, 
			ldns_resolver_port(local_res));
	ldns_resolver_set_debug(res, 
			ldns_resolver_debug(local_res));
	ldns_resolver_set_dnssec(res, 
			ldns_resolver_dnssec(local_res));
	ldns_resolver_set_fail(res, 
			ldns_resolver_fail(local_res));
	ldns_resolver_set_usevc(res, 
			ldns_resolver_usevc(local_res));
	ldns_resolver_set_random(res, 
			ldns_resolver_random(local_res));
	ldns_resolver_set_recursive(res, false);

	/* setup the root nameserver in the new resolver */
	status = ldns_resolver_push_nameserver_rr_list(res, dns_root);
	if (status != LDNS_STATUS_OK) {
		fprintf(stderr, "Error setting root nameservers in resolver: %s\n", ldns_get_errorstr_by_id(status));
		return NULL;
	}

	ldns_pkt_free(p);
	status = ldns_resolver_send(&p, res, name, t, c, 0);
	if (status != LDNS_STATUS_OK) {
		printf("Error querying root servers: %s\n", ldns_get_errorstr_by_id);
		return NULL;
	}

	/* from now on, use TCP */
	ldns_resolver_set_usevc(res, true);

	while(status == LDNS_STATUS_OK && 
	      ldns_pkt_reply_type(p) == LDNS_PACKET_REFERRAL) {

		new_nss_a = ldns_pkt_rr_list_by_type(p,
				LDNS_RR_TYPE_A, LDNS_SECTION_ADDITIONAL);
		new_nss_aaaa = ldns_pkt_rr_list_by_type(p,
				LDNS_RR_TYPE_AAAA, LDNS_SECTION_ADDITIONAL);
		new_nss = ldns_pkt_rr_list_by_type(p,
				LDNS_RR_TYPE_NS, LDNS_SECTION_AUTHORITY);

		/* remove the old nameserver from the resolver */
		while((pop = ldns_resolver_pop_nameserver(res))) { ldns_rdf_deep_free(pop); }

		/* also check for new_nss emptyness */

		if (!new_nss_aaaa && !new_nss_a) {
			/* 
			 * no nameserver found!!! 
			 * try to resolve the names we do got 
			 */
			if (verbosity >= 3) {
				printf("Did not get address record for nameserver, doing seperate query.\n");
			}
			ns_addr = ldns_rr_list_new();
			for(i = 0; i < ldns_rr_list_rr_count(new_nss); i++) {
				/* get the name of the nameserver */
				pop = ldns_rr_rdf(ldns_rr_list_rr(new_nss, i), 0);
				if (!pop) {
					break;
				}

				/* retrieve it's addresses */
				ns_addr2 = ldns_get_rr_list_addr_by_name(local_res, pop, c, 0);
				if (!ldns_rr_list_cat(ns_addr, ns_addr2)) {
					fprintf(stderr, "Internal error adding nameserver address.\n");
					exit(EXIT_FAILURE);
				}
				ldns_rr_list_free(ns_addr2);
			}

			if (ns_addr) {
				if (ldns_resolver_push_nameserver_rr_list(res, ns_addr) != 
						LDNS_STATUS_OK) {
					fprintf(stderr, "Error adding new nameservers");
					ldns_pkt_free(p); 
					return NULL;
				}
				ldns_rr_list_deep_free(ns_addr);
			} else {
				ldns_rr_list_print(stdout, ns_addr);
				fprintf(stderr, "Could not find the nameserver ip addr; abort");
				ldns_pkt_free(p);
				return NULL;
			}
		}

		/* normally, the first working ns is used, but we need all now, so do it one by one
		 * if the answer is null, take it from the next resolver
		 * if the answer is not, compare it to that of the next resolver
		 * error if different, continue if the same
		 * if answer list null and no resolvers left die.
		 */

		ldns_rr_list_deep_free(authority_list);
		authority_list = NULL;
		for (nss_i = 0; nss_i < ldns_rr_list_rr_count(new_nss_aaaa); nss_i++) {
			while((pop = ldns_resolver_pop_nameserver(res))) { ldns_rdf_deep_free(pop); }

			status = ldns_resolver_push_nameserver(res, ldns_rr_rdf(ldns_rr_list_rr(new_nss_aaaa, nss_i), 0));
			if (status != LDNS_STATUS_OK) {
				fprintf(stderr, "Error adding nameserver to resolver: %s\n", ldns_get_errorstr_by_id(status));
			}
			
			if (verbosity >= 1) {
				printf("Querying nameserver: ");
				ldns_rr_print(stdout, ldns_rr_list_rr(new_nss_a, nss_i));
			}
			status = ldns_resolver_push_nameserver(res, ldns_rr_rdf(ldns_rr_list_rr(new_nss_a, nss_i), 0));
			if (status != LDNS_STATUS_OK) {
				fprintf(stderr, "Error adding nameserver to resolver: %s\n", ldns_get_errorstr_by_id(status));
			}

			ldns_pkt_free(p);
			status = ldns_resolver_send(&p, res, name, t, c, 0);

			if (status == LDNS_STATUS_OK) {
				if (verbosity >= 4) {
					ldns_pkt_print(stdout, p);
				}

				if (authority_list) {
					if (verbosity >= 2) {
						printf("Comparing authority list of answer to previous\n");
					}
					ldns_rr_list_sort(ldns_pkt_authority(p));
					if (ldns_rr_list_compare(authority_list, ldns_pkt_authority(p)) != 0) {
						fprintf(stderr, "ERROR: different authority answer from nameserver\n");
						fprintf(stderr, "I had (from previous servers):\n");
						ldns_rr_list_print(stderr, authority_list);
						fprintf(stderr, "I received (from nameserver at ");
						ldns_rdf_print(stderr, ldns_resolver_nameservers(res)[0]);
						fprintf(stderr, "):\n");
						ldns_rr_list_print(stderr, ldns_pkt_authority(p));
						exit(EXIT_FAILURE);
					}
				} else {
					authority_list = ldns_rr_list_clone(ldns_pkt_authority(p));
					ldns_rr_list_sort(authority_list);
					if (verbosity >= 2) {
						printf("First authority list for this set, nothing to compare with\n");
					}
					if (verbosity >= 3) {
						printf("NS RRset:\n");
						ldns_rr_list_print(stdout, authority_list);
					}
				}
			}
		}

		ldns_rr_list_deep_free(authority_list);
		authority_list = NULL;
		for (nss_i = 0; nss_i < ldns_rr_list_rr_count(new_nss_a); nss_i++) {

			while((pop = ldns_resolver_pop_nameserver(res))) {ldns_rdf_deep_free(pop); }

			if (verbosity >= 1) {
				printf("Querying nameserver: ");
				ldns_rr_print(stdout, ldns_rr_list_rr(new_nss_a, nss_i));
			}
			status = ldns_resolver_push_nameserver(res, ldns_rr_rdf(ldns_rr_list_rr(new_nss_a, nss_i), 0));
			if (status != LDNS_STATUS_OK) {
				fprintf(stderr, "Error adding nameserver to resolver: %s\n", ldns_get_errorstr_by_id(status));
			}
			
			ldns_pkt_free(p);
			status = ldns_resolver_send(&p, res, name, t, c, 0);

			if (status == LDNS_STATUS_OK) {
				if (verbosity >= 4) {
					ldns_pkt_print(stdout, p);
				}

				if (authority_list) {
					if (verbosity >= 2) {
						printf("Comparing authority list of answer to previous\n");
					}
					ldns_rr_list_sort(ldns_pkt_authority(p));
					if (ldns_rr_list_compare(authority_list, ldns_pkt_authority(p)) != 0) {
						fprintf(stderr, "ERROR: different authority answer from nameserver\n");
						fprintf(stderr, "I had (from previous servers):\n");
						ldns_rr_list_print(stderr, authority_list);
						fprintf(stderr, "I received (from nameserver at ");
						ldns_rdf_print(stderr, ldns_resolver_nameservers(res)[0]);
						fprintf(stderr, "):\n");
						ldns_rr_list_print(stderr, ldns_pkt_authority(p));
						exit(EXIT_FAILURE);
					}
				} else {
					if (verbosity >= 2) {
						printf("First authority list for this set, nothing to compare with\n");
					}
					authority_list = ldns_rr_list_clone(ldns_pkt_authority(p));
					ldns_rr_list_sort(authority_list);
					if (verbosity >= 3) {
						printf("NS RRset:\n");
						ldns_rr_list_print(stdout, authority_list);
					}
				}
			}
		}
		ldns_rr_list_deep_free(authority_list);
		authority_list = NULL;
		
		if (loop_count++ > 20) {
			/* unlikely that we are doing something usefull */
			fprintf(stderr, "Looks like we are looping");
			ldns_pkt_free(p); 
			return NULL;
		}
		
		ldns_pkt_free(p);
		status = ldns_resolver_send(&p, res, name, t, c, 0);
		ldns_rr_list_deep_free(new_nss_aaaa);
		ldns_rr_list_deep_free(new_nss_a);
		ldns_rr_list_deep_free(new_nss);
		new_nss_aaaa = NULL;
		new_nss_a = NULL;
		ns_addr = NULL;

	}

	ldns_rr_list_deep_free(answer_list);
	answer_list = NULL;
	/* clone the nameserver list, we are going to handle them one by one */
	last_nameserver_count = 0;
	last_nameservers = LDNS_XMALLOC(ldns_rdf *, ldns_resolver_nameserver_count(res));

	pop = NULL;
	while((pop = ldns_resolver_pop_nameserver(res))) { 
		last_nameservers[last_nameserver_count] = pop;
		last_nameserver_count++;
	}

	for (nss_i = 0; nss_i < last_nameserver_count; nss_i++) {
		/* remove previous nameserver */
		while((pop = ldns_resolver_pop_nameserver(res))) { ldns_rdf_deep_free(pop); }

		if (verbosity >= 1) {
			printf("Querying nameserver: ");
			ldns_rdf_print(stdout, last_nameservers[nss_i]);
			printf("\n");
		}
		status = ldns_resolver_push_nameserver(res, last_nameservers[nss_i]);
		if (status != LDNS_STATUS_OK) {
			fprintf(stderr, "Error adding nameserver to resolver: %s\n", ldns_get_errorstr_by_id(status));
		}

		ldns_pkt_free(p);
		status = ldns_resolver_send(&p, res, name, t, c, 0);

		if (!p) {
			fprintf(stderr, "no packet received\n");
			return NULL;
		}

		if (status == LDNS_STATUS_RES_NO_NS) {
			fprintf(stderr, "Error: nameserver at ");
			ldns_rdf_print(stderr, last_nameservers[nss_i]);
			fprintf(stderr, " not responding. Unable to check RRset here, aborting.\n");
			return NULL;
		}

		if (answer_list) {
			if (verbosity >= 2) {
				printf("Comparing answer rr list of answer to previous\n");
			}
			ldns_rr_list_sort(ldns_pkt_answer(p));
			if (ldns_rr_list_compare(answer_list, ldns_pkt_answer(p)) != 0) {
				printf("ERROR: different answer section in response from nameserver\n");
				fprintf(stderr, "I had:\n");
				ldns_rr_list_print(stderr, answer_list);
				fprintf(stderr, "I received (from nameserver at ");
				ldns_rdf_print(stderr, ldns_resolver_nameservers(res)[0]);
				fprintf(stderr, "):\n");
				ldns_rr_list_print(stderr, ldns_pkt_answer(p));
				exit(EXIT_FAILURE);
			}
		} else {
			if (verbosity >= 2) {
				printf("First answer rr list for this set, nothing to compare with\n");
			}
			answer_list = ldns_rr_list_clone(ldns_pkt_answer(p));
			if (verbosity >= 3) {
				printf("DNSKEY RRset:\n");
				ldns_rr_list_print(stdout, answer_list);
			}
		}

	}

	for (nss_i = 0; nss_i < last_nameserver_count; nss_i++) {
		ldns_rdf_deep_free(last_nameservers[nss_i]);
	}
	LDNS_FREE(last_nameservers);
	ldns_resolver_deep_free(res);
	ldns_pkt_free(p);
	return answer_list;
}


/*
 * The file with the given path should contain a list of NS RRs
 * for the root zone and A records for those NS RRs.
 * Read them, check them, and append the a records to the rr list given.
 */
ldns_rr_list *
read_root_hints(const char *filename)
{
	FILE *fp = NULL;
	int line_nr = 0;
	ldns_zone *z;
	ldns_status status;

	fp = fopen(filename, "r");
	if (!fp) {
		fprintf(stderr, "Unable to open %s for reading: %s\n", filename, strerror(errno));
		return NULL;
	}

	status = ldns_zone_new_frm_fp_l(&z, fp, NULL, 0, 0, &line_nr);
	fclose(fp);
	if (status != LDNS_STATUS_OK) {
		fprintf(stderr, "error\n");
		return NULL;
	} else {
		return ldns_zone_rrs(z);
	}
}


int
main(int argc, char *argv[])
{
	ldns_resolver *res;
	ldns_rdf *domain;
	ldns_rr_list *l = NULL;

	ldns_rr_list *dns_root = NULL;
	const char *root_file = "/etc/named.root";

	ldns_status status;
	
	int i;

	domain = NULL;
	res = NULL;

	if (argc < 2) {
		usage(stdout, argv[0]);
		exit(EXIT_FAILURE);
	} else {
		for (i = 1; i < argc; i++) {
			if (strncmp("-h", argv[i], 3) == 0) {
				usage(stdout, argv[0]);
				exit(EXIT_SUCCESS);
			} else if (strncmp("-r", argv[i], 3) == 0) {
				if (i+1 >= argc) {
					usage(stdout, argv[0]);
					exit(EXIT_FAILURE);
				}
				root_file = argv[i+1];
				i++;
			} else if (strncmp("-v", argv[i], 3) == 0) {
				if (i+1 > argc) {
					usage(stdout, argv[0]);
					exit(EXIT_FAILURE);
				}
				verbosity = atoi(argv[i+1]);
				i++;
			} else {
				/* create a rdf from the command line arg */
				if (domain) {
					fprintf(stdout, "You can only specify one domain at a time\n");
					exit(EXIT_FAILURE);
				}

				domain = ldns_dname_new_frm_str(argv[i]);
			}
		}
		if (!domain) {
			usage(stdout, argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	dns_root = read_root_hints(root_file);
	if (!dns_root) {
		fprintf(stderr, "cannot read the root hints file\n");
		exit(EXIT_FAILURE);
	}

	/* create a new resolver from /etc/resolv.conf */
	status = ldns_resolver_new_frm_file(&res, NULL);

	if (status != LDNS_STATUS_OK) {
		ldns_rdf_deep_free(domain);
		fprintf(stderr, "Error creating resolver: %s\n", ldns_get_errorstr_by_id(status));
		exit(EXIT_FAILURE);
	}

	l = retrieve_dnskeys(res, domain, LDNS_RR_TYPE_DNSKEY, LDNS_RR_CLASS_IN, dns_root);

	/* separator for result data and verbosity data */
	if (verbosity > 0) {
		fprintf(stdout, "; ---------------------------\n");
		fprintf(stdout, "; Got the following keys:\n");
	}
	if (l) {
		ldns_rr_list_print(stdout, l);
	} else {
		printf("no packet?!?\n");
	}
	printf("\n");

	ldns_rdf_deep_free(domain);
	ldns_resolver_deep_free(res);
	ldns_rr_list_deep_free(l);
	ldns_rr_list_deep_free(dns_root);
	return EXIT_SUCCESS;
}
