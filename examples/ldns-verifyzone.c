/*
 * read a zone file from disk and prints it, one RR per line
 *
 * (c) NLnetLabs 2005-2008
 *
 * See the file LICENSE for the license
 *
 * Missing from the checks: empty non-terminals
 */

#include "config.h"
#include <unistd.h>
#include <stdlib.h>

#include <ldns/ldns.h>

#include <errno.h>

#ifdef HAVE_SSL
#include <openssl/err.h>
#endif

int verbosity = 3;

bool
ldns_rr_list_contains_name(const ldns_rr_list *rr_list,
					  const ldns_rdf *name)
{
	size_t i;
	for (i = 0; i < ldns_rr_list_rr_count(rr_list); i++) {
		if (ldns_dname_compare(name, 
						   ldns_rr_owner(ldns_rr_list_rr(rr_list, 
												   i))
						   ) == 0
		    ) {
			return true;
		}
	}
	return false;
}

void
print_type(ldns_rr_type type)
{
	const ldns_rr_descriptor *descriptor;

	descriptor = ldns_rr_descript(type);
	if (descriptor && descriptor->_name) {
		fprintf(stdout, "%s", descriptor->_name);
	} else {
		fprintf(stdout, "TYPE%u",
			   type);
	}

}

ldns_dnssec_zone *
create_dnssec_zone(ldns_zone *orig_zone)
{
	size_t i;
	ldns_dnssec_zone *dnssec_zone;
	ldns_rr *cur_rr;
	ldns_status status;

	/* when reading NSEC3s, there is a chance that we encounter nsecs
	   for empty nonterminals, whose nonterminals we cannot derive yet
	   because the needed information is to be read later. in that case
	   we keep a list of those nsec3's and retry to add them later */
	ldns_rr_list *failed_nsec3s = ldns_rr_list_new();

	dnssec_zone = ldns_dnssec_zone_new();
    	if (ldns_dnssec_zone_add_rr(dnssec_zone, ldns_zone_soa(orig_zone)) !=
	    LDNS_STATUS_OK) {
		if (verbosity > 0) {
			fprintf(stderr,
				   "Error adding SOA to dnssec zone, skipping record\n");
		}
	}

	for (i = 0; i < ldns_rr_list_rr_count(ldns_zone_rrs(orig_zone)); i++) {
		cur_rr = ldns_rr_list_rr(ldns_zone_rrs(orig_zone), i);
		status = ldns_dnssec_zone_add_rr(dnssec_zone, cur_rr);
		if (status != LDNS_STATUS_OK) {
			if (status == LDNS_STATUS_DNSSEC_NSEC3_ORIGINAL_NOT_FOUND) {
				ldns_rr_list_push_rr(failed_nsec3s, cur_rr);
			} else {
				if (verbosity > 0) {
					fprintf(stderr, "Error adding RR to dnssec zone");
					fprintf(stderr, ", skipping record:\n");
					ldns_rr_print(stderr, cur_rr);
				}
			}
		}
	}

	if (ldns_rr_list_rr_count(failed_nsec3s) > 0) {
		ldns_dnssec_zone_add_empty_nonterminals(dnssec_zone);
		for (i = 0; i < ldns_rr_list_rr_count(failed_nsec3s); i++) {
			cur_rr = ldns_rr_list_rr(failed_nsec3s, i);
			status = ldns_dnssec_zone_add_rr(dnssec_zone, cur_rr);
		}
	}

	ldns_rr_list_free(failed_nsec3s);
	return dnssec_zone;
}

ldns_status
verify_dnssec_rrset(ldns_dnssec_rrsets *rrset, ldns_rr_list *keys)
{
	ldns_rr_list *rrset_rrs;
	ldns_dnssec_rrs *cur_rr, *cur_sig;
	ldns_status status;
	ldns_rr_list *good_keys;
	ldns_status result = LDNS_STATUS_OK;
	
	rrset_rrs = ldns_rr_list_new();
	cur_rr = rrset->rrs;
	while(cur_rr) {
		ldns_rr_list_push_rr(rrset_rrs, cur_rr->rr);
		cur_rr = cur_rr->next;
	}
	cur_sig = rrset->signatures;
	if (cur_sig) {
		while (cur_sig) {
			good_keys = ldns_rr_list_new();
			status = ldns_verify_rrsig_keylist(rrset_rrs,
										cur_sig->rr,
										keys,
										good_keys);
			if (status != LDNS_STATUS_OK) {
				if (verbosity > 0) {
					printf("Error: %s",
						  ldns_get_errorstr_by_id(status));
					printf(" for ");
					ldns_rdf_print(stdout,
								ldns_rr_owner(rrset->rrs->rr));
					printf("\t");
					print_type(rrset->type);
					printf("\n");
					if (result == LDNS_STATUS_OK) {
						result = status;
					}
#ifdef HAVE_SSL
					if (status == LDNS_STATUS_SSL_ERR) {
						ERR_load_crypto_strings();
						ERR_print_errors_fp(stdout);
					}
#endif
					if (verbosity >= 4) {
						printf("RRSet:\n");
						ldns_dnssec_rrs_print(stdout, rrset->rrs);
						printf("Signature:\n");
						ldns_rr_print(stdout, cur_sig->rr);
						printf("\n");
					}
				}
			}
			ldns_rr_list_free(good_keys);

			cur_sig = cur_sig->next;
		}
	} else {
		if (verbosity > 0) {
			printf("Error: no signatures for ");
			ldns_rdf_print(stdout, ldns_rr_owner(rrset->rrs->rr));
			printf("\t");
			print_type(rrset->type);
			printf("\n");
		}
	}
	ldns_rr_list_free(rrset_rrs);
	return result;
}

ldns_status
verify_single_rr(ldns_rr *rr,
			  ldns_dnssec_rrs *signature_rrs,
			  ldns_rr_list *keys)
{
	ldns_rr_list *rrset_rrs;
	ldns_rr_list *good_keys;
	ldns_dnssec_rrs *cur_sig;
	ldns_status status;
	ldns_status result = LDNS_STATUS_OK;
    
	rrset_rrs = ldns_rr_list_new();
	ldns_rr_list_push_rr(rrset_rrs, rr);

	cur_sig = signature_rrs;
	while (cur_sig) {
		good_keys = ldns_rr_list_new();
		status = ldns_verify_rrsig_keylist(rrset_rrs,
									cur_sig->rr,
									keys,
									good_keys);
		if (status != LDNS_STATUS_OK) {
			if (verbosity >= 1) {
				printf("Error: %s ", ldns_get_errorstr_by_id(status));
				if (result == LDNS_STATUS_OK) {
					result = status;
				}
				printf("for ");
				ldns_rdf_print(stdout, ldns_rr_owner(rr));
				printf("\t");
				print_type(ldns_rr_get_type(rr));
				printf("\n");
#ifdef HAVE_SSL
				if (status == LDNS_STATUS_SSL_ERR) {
					ERR_load_crypto_strings();
					ERR_print_errors_fp(stdout);
				}
#endif
				if (verbosity >= 4) {
					printf("RRSet:\n");
					ldns_rr_list_print(stdout, rrset_rrs);
					printf("Signature:\n");
					ldns_rr_print(stdout, cur_sig->rr);
					printf("\n");
				}
			}
			result = status;
		}
		ldns_rr_list_free(good_keys);
		cur_sig = cur_sig->next;
	}

	ldns_rr_list_free(rrset_rrs);

	return result;
}

ldns_status
verify_dnssec_name(ldns_dnssec_name *name,
			    ldns_rr_list *keys,
			    ldns_rr_list *glue_rrs)
{
	ldns_status result = LDNS_STATUS_OK;
	ldns_status status;
	ldns_dnssec_rrsets *cur_rrset;

	if (verbosity >= 3) {
		printf("Checking: ");
		ldns_rdf_print(stdout, name->name);
		printf("\n");
	}

	if (ldns_rr_list_contains_name(glue_rrs, name->name)) {
		/* glue */
		cur_rrset = name->rrsets;
		while (cur_rrset) {
			if (cur_rrset->signatures) {
				if (verbosity >= 1) {
					printf("Error: ");
					ldns_rdf_print(stdout, name->name);
					printf("\t");
					print_type(cur_rrset->type);
					printf(" has signature(s), but is glue\n");
				}
				result = LDNS_STATUS_ERR;
			}
			cur_rrset = cur_rrset->next;
		}
		if (name->nsec) {
			if (verbosity >= 1) {
				printf("Error: ");
				ldns_rdf_print(stdout, name->name);
				printf("\thas an NSEC(3), but is glue\n");
			}
			result = LDNS_STATUS_ERR;
		}
	} else {
		/* not glue, do real verify */
		cur_rrset = name->rrsets;
		while(cur_rrset) {
			status = verify_dnssec_rrset(cur_rrset, keys);
			if (status != LDNS_STATUS_OK && result == LDNS_STATUS_OK) {
				result = status;
			}
			cur_rrset = cur_rrset->next;
		}

		if (name->nsec) {
			if (name->nsec_signatures) {
				status = verify_single_rr(name->nsec,
									 name->nsec_signatures,
									 keys);
				if (result == LDNS_STATUS_OK) {
					result = status;
				}
			} else {
				if (verbosity >= 1) {
					printf("Error: the NSEC(3) record of ");
					ldns_rdf_print(stdout, name->name);
					printf(" has no signatures\n");
				}
				if (result == LDNS_STATUS_OK) {
					result = LDNS_STATUS_ERR;
				}
			}
		} else {
			if (verbosity >= 1) {
				printf("Error: there is no NSEC(3) for ");
				ldns_rdf_print(stdout, name->name);
				printf("\n");
			}
			if (result == LDNS_STATUS_OK) {
				result = LDNS_STATUS_ERR;
			}
		}
	}
	return result;
}

ldns_status
verify_dnssec_zone(ldns_dnssec_zone *dnssec_zone,
			    ldns_rdf *zone_name,
			    ldns_rr_list *glue_rrs)
{
	ldns_rr_list *keys;
	ldns_rbnode_t *cur_node;
	ldns_dnssec_rrsets *cur_key_rrset;
	ldns_dnssec_rrs *cur_key;
	ldns_dnssec_name *cur_name;
	ldns_status status;
	ldns_status result = LDNS_STATUS_OK;

	keys = ldns_rr_list_new();
	cur_key_rrset = ldns_dnssec_zone_find_rrset(dnssec_zone,
									    zone_name,
									    LDNS_RR_TYPE_DNSKEY);
	if (!cur_key_rrset || !cur_key_rrset->rrs) {
		if (verbosity >= 1) {
			printf("No DNSKEY records at zone apex\n");
		}
		result = LDNS_STATUS_ERR;
	} else {
		cur_key = cur_key_rrset->rrs;
		while (cur_key) {
			ldns_rr_list_push_rr(keys, cur_key->rr);
			cur_key = cur_key->next;
		}

		cur_node = ldns_rbtree_first(dnssec_zone->names);
		if (cur_node == LDNS_RBTREE_NULL) {
			if (verbosity >= 1) {
				printf("Empty zone?\n");
			}
			result = LDNS_STATUS_ERR;
		}
		while (cur_node != LDNS_RBTREE_NULL) {
			cur_name = (ldns_dnssec_name *) cur_node->data;
			status = verify_dnssec_name(cur_name, keys, glue_rrs);
			if (status != LDNS_STATUS_OK && result == LDNS_STATUS_OK) {
				result = status;
			}
			cur_node = ldns_rbtree_next(cur_node);
		}
	}

	ldns_rr_list_free(keys);
	return result;
}

int
main(int argc, char **argv)
{
	char *filename;
	FILE *fp;
	ldns_zone *z;
	int line_nr = 0;
	int c;
	ldns_status s;
	ldns_dnssec_zone *dnssec_zone;
	ldns_status result = LDNS_STATUS_ERR;
	ldns_rr_list *glue_rrs;
	
	while ((c = getopt(argc, argv, "hvV:")) != -1) {
		switch(c) {
		case 'h':
			printf("Usage: %s [OPTIONS] <zonefile>\n", argv[0]);
			printf("\tReads the zonefile and checks for DNSSEC errors.\n");
			printf("\nIt checks whether NSEC(3)s are present,");
			printf(" and verifies all signatures\n");
			printf("It does NOT check the NSEC(3) chain itself\n");
			printf("\nOPTIONS:\n");
			printf("\t-h show this text\n");
			printf("\t-v shows the version and exits\n");
			printf("\t-V [0-5]\tset verbosity level (default 3)\n");
			printf("\nif no file is given standard input is read\n");
			exit(EXIT_SUCCESS);
			break;
		case 'v':
			printf("read zone version %s (ldns version %s)\n", 
				  LDNS_VERSION, ldns_version());
			exit(EXIT_SUCCESS);
			break;
		case 'V':
			verbosity = atoi(optarg);
			break;
		}
	}

	argc -= optind;
	argv += optind;
	
	if (argc == 0) {
		fp = stdin;
	} else {
		filename = argv[0];

		fp = fopen(filename, "r");
		if (!fp) {
			fprintf(stderr,
				   "Unable to open %s: %s\n",
				   filename,
				   strerror(errno));
			exit(EXIT_FAILURE);
		}
	}
	
	s = ldns_zone_new_frm_fp_l(&z, fp, NULL, 0, LDNS_RR_CLASS_IN, &line_nr);

	glue_rrs = ldns_zone_glue_rr_list(z);

	if (s == LDNS_STATUS_OK) {
		dnssec_zone = create_dnssec_zone(z);

		if (verbosity >= 5) {
			ldns_dnssec_zone_print(stdout, dnssec_zone);
		}

		result = verify_dnssec_zone(dnssec_zone, 
							   ldns_rr_owner(ldns_zone_soa(z)),
							   glue_rrs);


		if (result == LDNS_STATUS_OK) {
			if (verbosity >= 1) {
				printf("Zone is verified and complete\n");
			}
		} else {
			if (verbosity >= 1) {
				printf("There were errors in the zone\n");
			}
		}

		ldns_zone_deep_free(z);
		ldns_dnssec_zone_free(dnssec_zone);
	} else {
		fprintf(stderr, "%s at %d\n", 
				ldns_get_errorstr_by_id(s),
				line_nr);
                exit(EXIT_FAILURE);
	}
	fclose(fp);

	exit(result);
}

