/*
 * ldns-walk uses educated guesses and NSEC data to retrieve the
 * contents of a dnssec signed zone
 * (c) NLnet Labs, 2005
 * See the file LICENSE for the license
 */

#include "config.h"

#include <ldns/dns.h>

int
usage(FILE *fp, char *prog) {
	fprintf(fp, "%s [options] domain\n", prog);
	fprintf(fp, "  print out the owner names for domain and the record types for those names\n");
	fprintf(fp, "OPTIONS:\n");
	fprintf(fp, "-s <name>\t\tStart from this name\n");
	fprintf(fp, "@<nameserver>\t\tUse this nameserver\n");
	return 0;
}

ldns_rdf *
create_dname_plus_1(ldns_rdf *dname)
{
	uint8_t *wire;
	ldns_rdf *newdname;
	uint8_t labellen;
	size_t pos;
	ldns_status status;
	
	labellen = ldns_rdf_data(dname)[0];
	if (labellen < 63) {
		wire = malloc(ldns_rdf_size(dname) + 1);
		if (!wire) {
			fprintf(stderr, "Malloc error: out of memory?\n");
			exit(127);
		}
		wire[0] = labellen + 1;
		memcpy(&wire[1], ldns_rdf_data(dname) + 1, labellen);
		memcpy(&wire[labellen+1], ldns_rdf_data(dname) + labellen, ldns_rdf_size(dname) - labellen);
		wire[labellen+1] = '\000';
		pos = 0;
		status = ldns_wire2dname(&newdname, wire, ldns_rdf_size(dname) + 1, &pos);
		free(wire);
	} else {
		fprintf(stderr, "maxlen not supported yet\n");
		exit(9);
	}

	if (status != LDNS_STATUS_OK) {
	  printf("Error: %s\n", ldns_get_errorstr_by_id(status));
	  exit(10);
        }
	
	return newdname;
}

ldns_rdf *
create_plus_1_dname(ldns_rdf *dname)
{
	ldns_rdf *label;
	ldns_status status;
	
	status = ldns_str2rdf_dname(&label, "\\000");
	if (status != LDNS_STATUS_OK) {
		printf("error creating \\000 dname: %s\n\n", ldns_get_errorstr_by_id(status));
		exit(2);
	}
	status = ldns_dname_cat(label, dname);
	if (status != LDNS_STATUS_OK) {
		printf("error catting \\000 dname: %s\n\n", ldns_get_errorstr_by_id(status));
		exit(3);
	}
	return label;
}

int
main(int argc, char *argv[])
{
	ldns_status status;

	ldns_resolver *res;
	ldns_rdf *domain = NULL;
	ldns_pkt *p;
	ldns_rr *soa;
	ldns_rr_list *rrlist;
	ldns_rr_list *rrlist2;
	ldns_rdf *soa_p1;
	ldns_rdf *next_dname;
	ldns_rdf *last_dname;
	ldns_rdf *last_dname_p;
	ldns_rdf *startpoint = NULL;
	ldns_rdf *rrtypes = NULL;

	char *serv = NULL;
	ldns_rdf *serv_rdf;
	ldns_resolver *cmdline_res;
	ldns_rr_list *cmdline_rr_list;
	ldns_rdf *cmdline_dname;

	int result = 0;
	size_t i;

	p = NULL;
	rrlist = NULL;
	rrlist2 = NULL;
	soa = NULL;
	domain = NULL;
	res = NULL;
	
	if (argc < 2) {
		usage(stdout, argv[0]);
		exit(EXIT_FAILURE);
	} else {
		for (i = 1; i < argc; i++) {
			if (strncmp(argv[i], "-s", 3) == 0) {
				if (i + 1 < argc) {
					if (!ldns_str2rdf_dname(&startpoint, argv[i + 1]) == LDNS_STATUS_OK) {
						printf("Bad start point name: %s\n", argv[i + 1]);
						exit(1);
					}
				} else {
					printf("Missing argument for -s\n");
					exit(1);
				}
				i++;
			} else {
                        	if (argv[i][0] == '@') {
					if (strlen(argv[i]) == 1) {
						if (i + 1 < argc) {
							serv = argv[i + 1];
							i++;
						} else {
							printf("Missing argument for -s\n");
							exit(1);
						}
					} else {
						serv = argv[i] + 1;
					}
                        	} else {
					if (i < argc) {
						if (!domain) {
							/* create a rdf from the command line arg */
							domain = ldns_dname_new_frm_str(argv[i]);
							if (!domain) {
								usage(stdout, argv[0]);
								exit(1);
							}
						} else {
							printf("One domain at a time please\n");
							exit(1);
						}
					} else {
						printf("No domain given to walk\n");
						exit(1);
					}
				}
			}
		}
	}
	if (!domain) {
		printf("Missing argument\n");
		exit(1);
	}


	/* create a new resolver from /etc/resolv.conf */
	if(!serv) {
		res = ldns_resolver_new_frm_file(NULL);
	} else {
		res = ldns_resolver_new();
		if (!res || strlen(serv) <= 0) {
			result = EXIT_FAILURE;
			goto exit;
		}
		/* add the nameserver */
		serv_rdf = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, serv);
        	if (!serv_rdf) {
			/* maybe ip6 */
			serv_rdf = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_AAAA, serv);
		}
		if (!serv_rdf) {
			/* try to resolv the name if possible */
			cmdline_res = ldns_resolver_new_frm_file(NULL);
			
			if (!cmdline_res) {
				fprintf(stderr, "%s", "@server ip could not be converted");
				result = EXIT_FAILURE;
				goto exit;
			}

			cmdline_dname = ldns_dname_new_frm_str(serv);
			cmdline_rr_list = ldns_get_rr_list_addr_by_name(
						cmdline_res, 
						cmdline_dname,
						LDNS_RR_CLASS_IN,
						0);
			ldns_rdf_deep_free(cmdline_dname);
			if (!cmdline_rr_list) {
				fprintf(stderr, "%s %s", "could not find any address for the name: ", serv);
				result = EXIT_FAILURE;
				goto exit;
			} else {
				if (ldns_resolver_push_nameserver_rr_list(
						res, 
						cmdline_rr_list
					) != LDNS_STATUS_OK) {
					fprintf(stderr, "%s", "pushing nameserver");
					result = EXIT_FAILURE;
					goto exit;
				}
			}
		} else {
			if (ldns_resolver_push_nameserver(res, serv_rdf) != LDNS_STATUS_OK) {
				fprintf(stderr, "%s", "pushing nameserver");
				result = EXIT_FAILURE;
				goto exit;
			} else {
				ldns_rdf_deep_free(serv_rdf);
			}
		}

	}

	ldns_resolver_set_dnssec(res, true);
	ldns_resolver_set_dnssec_cd(res, true);

	if (!res) {
		exit(2);
	}

	/* use the resolver to send it a query for the soa
	 * records of the domain given on the command line
	 */
	p = ldns_resolver_query(res, domain, LDNS_RR_TYPE_SOA, LDNS_RR_CLASS_IN, LDNS_RD);
	soa = NULL;

        if (!p)  {
		exit(3);
        } else {
		/* retrieve the MX records from the answer section of that
		 * packet
		 */
		rrlist = ldns_pkt_rr_list_by_type(p, LDNS_RR_TYPE_SOA, LDNS_SECTION_ANSWER);
		if (!rrlist || ldns_rr_list_rr_count(rrlist) != 1) {
			if (rrlist) {
				printf(" *** > 1 SOA: %u\n", ldns_rr_list_rr_count(rrlist));
			} else {
				printf(" *** No rrlist...\b");
			}
			/* TODO: conversion memory */
			fprintf(stderr, 
					" *** invalid answer name after SOA query for %s\n",
					ldns_rr2str(domain));
			ldns_pkt_print(stdout, p);
                        ldns_pkt_free(p);
                        ldns_resolver_deep_free(res);
			exit(4);
		} else {
			soa = ldns_rr_clone(ldns_rr_list_rr(rrlist, 0));
			ldns_rr_list_deep_free(rrlist);
		}
        }

	/* add \001 to soa */
	status = ldns_str2rdf_dname(&soa_p1, "\001");
	if (status != LDNS_STATUS_OK) {
		printf("error. %s\n", ldns_get_errorstr_by_id(status));
	}
	if (!soa) {
		printf("Error getting SOA\n");
		exit(1);
	}

	if (startpoint) {
		last_dname = startpoint;
		last_dname_p = create_dname_plus_1(last_dname);
	} else {
		last_dname = ldns_rdf_clone(domain);
		ldns_dname_cat(soa_p1, last_dname);
		last_dname_p = ldns_rdf_clone(soa_p1);
	}


	ldns_rdf_print(stdout, ldns_rr_owner(soa));
	printf("\t");

	next_dname = NULL;
	while (!next_dname || ldns_rdf_compare(next_dname, domain) != 0) {
		if (p) {
			ldns_pkt_free(p);
			p = NULL;
		}
		p = ldns_resolver_query(res, last_dname_p, LDNS_RR_TYPE_ANY, LDNS_RR_CLASS_IN, LDNS_RD);

		if (next_dname) {
			ldns_rdf_deep_free(next_dname);
			ldns_rdf_deep_free(rrtypes);
			next_dname = NULL;
		}

		if (!p)  {
		  fprintf(stderr, "Error trying to resolve: ");
		  ldns_rdf_print(stderr, last_dname_p);
		  fprintf(stderr, "\n");
		  while (!p) {
		    p = ldns_resolver_query(res, last_dname_p, LDNS_RR_TYPE_ANY, LDNS_RR_CLASS_IN, LDNS_RD);
		    if (!p)  {
		      fprintf(stderr, "Error trying to resolve: ");
		      ldns_rdf_print(stderr, last_dname_p);
		      fprintf(stderr, "\n");
		    }
		  }
		}

		/* if the current name is an empty non-terminal, bind returns
		 * SERVFAIL on the plus1-query...
		 * so requery with only the last dname
		 */
		if (ldns_pkt_rcode(p) == 2) {
			ldns_pkt_free(p);
			p = NULL;
			p = ldns_resolver_query(res, last_dname, LDNS_RR_TYPE_ANY, LDNS_RR_CLASS_IN, LDNS_RD);
			if (!p) {
				exit(51);
			}
			rrlist = ldns_pkt_rr_list_by_name_and_type(p, last_dname, LDNS_RR_TYPE_NSEC, LDNS_SECTION_ANSWER);
			rrlist2 = ldns_pkt_rr_list_by_name_and_type(p, last_dname_p, LDNS_RR_TYPE_NSEC, LDNS_SECTION_ANSWER);
		} else {
			rrlist = ldns_pkt_rr_list_by_name_and_type(p, last_dname, LDNS_RR_TYPE_NSEC, LDNS_SECTION_AUTHORITY);
			rrlist2 = ldns_pkt_rr_list_by_name_and_type(p, last_dname_p, LDNS_RR_TYPE_NSEC, LDNS_SECTION_ANSWER);
		}
	if (rrlist && rrlist2) {
		ldns_rr_list_cat(rrlist, rrlist2);
	} else if (rrlist2) {
		rrlist = rrlist2;
	}

	if (!rrlist || ldns_rr_list_rr_count(rrlist) != 1) {
	} else {
		next_dname = ldns_rdf_clone(ldns_rr_rdf(ldns_rr_list_rr(rrlist, 0), 0));
		rrtypes = ldns_rdf_clone(ldns_rr_rdf(ldns_rr_list_rr(rrlist, 0), 1));
		ldns_rr_list_deep_free(rrlist);
	}

	if (!next_dname) {
		/* apparently the zone also has prepended data (i.e. a.example and www.a.example, 
 		 * The www comes after the a but befpre a\\000, so we need to make another name (\\000.a)
		 */
		if (last_dname_p) {
			ldns_rdf_deep_free(last_dname_p);
		}
		last_dname_p = create_plus_1_dname(last_dname);
	} else {

		if (last_dname) {
			if (ldns_rdf_compare(last_dname, next_dname) == 0) {
				printf("Next dname is the same as current, this would loop forever. This is a problem that usually occurs when walking through a caching forwarder. Try using the authoritative nameserver to walk.\n");
				exit(2);
			}
			ldns_rdf_deep_free(last_dname);
		}
		last_dname = ldns_rdf_clone(next_dname);
		if (last_dname_p) {
			ldns_rdf_deep_free(last_dname_p);
		}
		last_dname_p = create_dname_plus_1(last_dname);
		ldns_rdf_print(stdout, rrtypes);
		printf("\n");
		ldns_rdf_print(stdout, next_dname);
		printf("\t");
	}
}

	ldns_rdf_deep_free(domain);
	ldns_rdf_deep_free(soa_p1);
	ldns_rdf_deep_free(last_dname_p);
	ldns_rdf_deep_free(last_dname);
	ldns_rdf_deep_free(next_dname);
	ldns_rdf_deep_free(rrtypes);

        ldns_pkt_free(p);

	ldns_rr_free(soa);
	

	printf("\n\n");
        ldns_resolver_deep_free(res);

        exit:
        return result;
}
