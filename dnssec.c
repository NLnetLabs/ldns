/* 
 * dnssec.c
 *
 * contains the cryptographic function needed for DNSSEC
 * The crypto library used is openssl
 *
 * (c) NLnet Labs, 2004-2006
 * a Net::DNS like library for C
 *
 * See the file LICENSE for the license
 */

#include <ldns/config.h>

#include <ldns/ldns.h>

#include <strings.h>
#include <time.h>

#ifdef HAVE_SSL
/* this entire file is rather useless when you don't have
 * crypto...
 */
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/md5.h>

ldns_rr *
ldns_dnssec_get_rrsig_for_name_and_type(const ldns_rdf *name,
                                        const ldns_rr_type type,
                                        const ldns_rr_list *rrs)
{
	size_t i;
	ldns_rr *candidate;
	
	if (!name || !rrs) {
		return NULL;
	}
	
	for (i = 0; i < ldns_rr_list_rr_count(rrs); i++) {
		candidate = ldns_rr_list_rr(rrs, i);
		if (ldns_rr_get_type(candidate) == LDNS_RR_TYPE_RRSIG) {
			if (ldns_dname_compare(ldns_rr_owner(candidate),
			                       name) == 0 &&
			    ldns_rdf2native_int8(ldns_rr_rrsig_typecovered(candidate)) ==
			    type
			   ) {
				return candidate;
			}
		}
	}
	
	return NULL;
}

ldns_rr *
ldns_dnssec_get_dnskey_for_rrsig(const ldns_rr *rrsig, const ldns_rr_list *rrs)
{
	size_t i;
	ldns_rr *candidate;
	
	if (!rrsig || !rrs) {
		return NULL;
	}
	
	for (i = 0; i < ldns_rr_list_rr_count(rrs); i++) {
		candidate = ldns_rr_list_rr(rrs, i);
		if (ldns_rr_get_type(candidate) == LDNS_RR_TYPE_DNSKEY) {
			if (ldns_dname_compare(ldns_rr_owner(candidate),
			                       ldns_rr_rrsig_signame(rrsig)) == 0 &&
			    ldns_rdf2native_int16(ldns_rr_rrsig_keytag(rrsig)) ==
			    ldns_calc_keytag(candidate)
			) {
				return candidate;
			}
		}
	}
	
	return NULL;
}

ldns_rdf *
ldns_nsec_get_bitmap(ldns_rr *nsec) {
	if (ldns_rr_get_type(nsec) == LDNS_RR_TYPE_NSEC) {
		return ldns_rr_rdf(nsec, 1);
	} else if (ldns_rr_get_type(nsec) == LDNS_RR_TYPE_NSEC3) {
		return ldns_rr_rdf(nsec, 5);
	} else {
		return NULL;
	}
}

ldns_status
ldns_dnssec_verify_denial(ldns_rr *rr,
                          ldns_rr_list *nsecs,
                          ldns_rr_list *rrsigs)
{
	ldns_rdf *rr_name;
	ldns_rdf *wildcard_name;
	ldns_rdf *chopped_dname;
	ldns_rr *cur_nsec;
	size_t i;
	ldns_status result;
	/* needed for wildcard check on exact match */
	ldns_rr *rrsig;
	bool name_covered = false;
	bool type_covered = false;
	bool wildcard_covered = false;
	bool wildcard_type_covered = false;

	wildcard_name = ldns_dname_new_frm_str("*");
	rr_name = ldns_rr_owner(rr);
	chopped_dname = ldns_dname_left_chop(rr_name);
	result = ldns_dname_cat(wildcard_name, chopped_dname);
	if (result != LDNS_STATUS_OK) {
		return result;
	}
	
	ldns_rdf_deep_free(chopped_dname);
	
	for  (i = 0; i < ldns_rr_list_rr_count(nsecs); i++) {
		cur_nsec = ldns_rr_list_rr(nsecs, i);
		if (ldns_dname_compare(rr_name, ldns_rr_owner(cur_nsec)) == 0) {
			/* see section 5.4 of RFC4035, if the label count of the NSEC's
			   RRSIG is equal, then it is proven that wildcard expansion could
			   not have been used to match the request */
			rrsig = ldns_dnssec_get_rrsig_for_name_and_type(ldns_rr_owner(cur_nsec), ldns_rr_get_type(cur_nsec), rrsigs);
			if (rrsig && ldns_rdf2native_int8(ldns_rr_rrsig_labels(rrsig)) == ldns_dname_label_count(rr_name)) {
				wildcard_covered = true;
			}
			
			if (ldns_nsec_bitmap_covers_type(ldns_nsec_get_bitmap(cur_nsec), ldns_rr_get_type(rr))) {
				type_covered = true;
			}
		}
		
		if (ldns_nsec_covers_name(cur_nsec, rr_name)) {
			name_covered = true;
		}
		
		if (ldns_dname_compare(wildcard_name, ldns_rr_owner(cur_nsec)) == 0) {
			if (ldns_nsec_bitmap_covers_type(ldns_nsec_get_bitmap(cur_nsec), ldns_rr_get_type(rr))) {
				wildcard_type_covered = true;
			}
		}
		
		if (ldns_nsec_covers_name(cur_nsec, wildcard_name)) {
			wildcard_covered = true;
		}
		
	}
	
	ldns_rdf_deep_free(wildcard_name);
	
	if (type_covered || !name_covered) {
		return LDNS_STATUS_DNSSEC_NSEC_RR_NOT_COVERED;
	}
	
	if (wildcard_type_covered || !wildcard_covered) {
		return LDNS_STATUS_DNSSEC_NSEC_WILDCARD_NOT_COVERED;
	}

	return LDNS_STATUS_OK;
}


ldns_dnssec_data_chain *
ldns_dnssec_data_chain_new()
{
	ldns_dnssec_data_chain *nc = LDNS_XMALLOC(ldns_dnssec_data_chain, 1);
	nc->rrset = NULL;
	nc->parent_type = 0;
	nc->parent = NULL;
	nc->signatures = NULL;
	return nc;
}

void
ldns_dnssec_data_chain_free(ldns_dnssec_data_chain *chain)
{
	LDNS_FREE(chain);
}

void
ldns_dnssec_data_chain_deep_free(ldns_dnssec_data_chain *chain)
{
	ldns_rr_list_deep_free(chain->rrset);
	ldns_rr_list_deep_free(chain->signatures);
	if (chain->parent) {
		ldns_dnssec_data_chain_deep_free(chain->parent);
	}
	LDNS_FREE(chain);
}

ldns_rr_list *
ldns_dnssec_pkt_get_rrsigs_for_name_and_type(const ldns_pkt *pkt, ldns_rdf *name, ldns_rr_type type)
{
	uint16_t t_netorder;
	ldns_rr_list *sigs;
	ldns_rr_list *sigs_covered;
	ldns_rdf *rdf_t;
	
	sigs = ldns_pkt_rr_list_by_name_and_type(pkt,
				                 name,
						 LDNS_RR_TYPE_RRSIG,
						 LDNS_SECTION_ANY_NOQUESTION
						);

	t_netorder = htons(type); /* rdf are in network order! */
	rdf_t = ldns_rdf_new(LDNS_RDF_TYPE_TYPE, sizeof(ldns_rr_type), &t_netorder);
	sigs_covered = ldns_rr_list_subtype_by_rdf(sigs, rdf_t, 0);
	
	ldns_rdf_free(rdf_t);
	ldns_rr_list_deep_free(sigs);

	return sigs_covered;

}

ldns_rr_list *
ldns_dnssec_pkt_get_rrsigs_for_type(const ldns_pkt *pkt, ldns_rr_type type)
{
	uint16_t t_netorder;
	ldns_rr_list *sigs;
	ldns_rr_list *sigs_covered;
	ldns_rdf *rdf_t;
	
	sigs = ldns_pkt_rr_list_by_type(pkt,
	                                LDNS_RR_TYPE_RRSIG,
	                                LDNS_SECTION_ANY_NOQUESTION
	                               );

	t_netorder = htons(type); /* rdf are in network order! */
	rdf_t = ldns_rdf_new(LDNS_RDF_TYPE_TYPE, sizeof(ldns_rr_type), &t_netorder);
	sigs_covered = ldns_rr_list_subtype_by_rdf(sigs, rdf_t, 0);
	
	ldns_rdf_free(rdf_t);
	ldns_rr_list_deep_free(sigs);

	return sigs_covered;

}


void
ldns_dnssec_data_chain_print(FILE *out, const ldns_dnssec_data_chain *chain)
{
	if (chain) {
		ldns_dnssec_data_chain_print(out, chain->parent);
		if (ldns_rr_list_rr_count(chain->rrset) > 0) {
			printf("rrset: %p\n", chain->rrset);
			ldns_rr_list_print(out, chain->rrset);
			printf("sigs: %p\n", chain->signatures);
			ldns_rr_list_print(out, chain->signatures);
			fprintf(out, "---\n");
		} else {
			fprintf(out, "<no data>\n");
		}
	}
}

ldns_dnssec_data_chain *
ldns_dnssec_build_data_chain(ldns_resolver *res, uint16_t qflags, const ldns_rr_list *rrset, const ldns_pkt *pkt, ldns_rr *orig_rr)
{
	ldns_rr_list *signatures = NULL, *signatures2 = NULL;
	ldns_rr_list *keys;
	ldns_rr_list *dss;
	
	ldns_rr_list *my_rrset;

	ldns_pkt *my_pkt;

	ldns_rdf *name, *key_name = NULL;
	ldns_rr_type type;
	ldns_rr_class c;
	
	bool other_rrset = false;
	
	ldns_dnssec_data_chain *new_chain = ldns_dnssec_data_chain_new();

	if (orig_rr) {
		new_chain->rrset = ldns_rr_list_new();
		ldns_rr_list_push_rr(new_chain->rrset, orig_rr);
		new_chain->parent = ldns_dnssec_build_data_chain(res, qflags, rrset, pkt, NULL);
		return new_chain;
	}
	
	if (!rrset || ldns_rr_list_rr_count(rrset) < 1) {
		/* hmm, no data, do we have denial? only works if pkt was given,
		   otherwise caller has to do the check himself */
		if (pkt) {
			my_rrset = ldns_pkt_rr_list_by_type(pkt, LDNS_RR_TYPE_NSEC, LDNS_SECTION_ANY_NOQUESTION);
			if (my_rrset) {
				if (ldns_rr_list_rr_count(my_rrset) > 0) {
					type = LDNS_RR_TYPE_NSEC;
					other_rrset = true;
				} else {
					ldns_rr_list_deep_free(my_rrset);
				}
			} else {
				/* nothing, stop */
				return new_chain;
			}
		} else {
			return new_chain;
		}
	} else {
		my_rrset = (ldns_rr_list *) rrset;
	}
	
	new_chain->rrset = ldns_rr_list_clone(my_rrset);
	name = ldns_rr_owner(ldns_rr_list_rr(my_rrset, 0));
	type = ldns_rr_get_type(ldns_rr_list_rr(my_rrset, 0));
	c = ldns_rr_get_class(ldns_rr_list_rr(my_rrset, 0));
	
	if (other_rrset) {
		ldns_rr_list_deep_free(my_rrset);
	}
	
	/* normally there will only be 1 signature 'set'
	   but there can be more than 1 denial (wildcards)
	   so check for NSEC
	 */
	if (type == LDNS_RR_TYPE_NSEC) {
		/* just throw in all signatures, the tree builder must sort
		   this out */
		if (pkt) {
			/*signatures = ldns_pkt_rr_list_by_type(pkt, LDNS_RR_TYPE_RRSIG, LDNS_SECTION_ANY_NOQUESTION);*/
			signatures = ldns_dnssec_pkt_get_rrsigs_for_type(pkt, type);
		} else {
			my_pkt = ldns_resolver_query(res, name, type, c, qflags);
			signatures = ldns_dnssec_pkt_get_rrsigs_for_type(pkt, type);
			/*signatures = ldns_pkt_rr_list_by_type(my_pkt, LDNS_RR_TYPE_RRSIG, LDNS_SECTION_ANY_NOQUESTION);*/
			ldns_pkt_free(my_pkt);
		}
	} else {
		if (pkt) {
			signatures = ldns_dnssec_pkt_get_rrsigs_for_name_and_type(pkt, name, type);
		}
		if (!signatures) {
			my_pkt = ldns_resolver_query(res, name, type, c, qflags);
			signatures = ldns_dnssec_pkt_get_rrsigs_for_name_and_type(my_pkt, name, type);
			ldns_pkt_free(my_pkt);
		}

	}

	if (signatures && ldns_rr_list_rr_count(signatures) > 0) {
		key_name = ldns_rr_rdf(ldns_rr_list_rr(signatures, 0), 7);
	}

	if (!key_name) {
		/* apparently we were not able to find a signing key, so
		   we assume the chain ends here
		*/
		return new_chain;
	}

	if (type != LDNS_RR_TYPE_DNSKEY) {
		if (signatures && ldns_rr_list_rr_count(signatures) > 0) {
			new_chain->signatures = ldns_rr_list_clone(signatures);
			new_chain->parent_type = 0;
			
			keys = ldns_pkt_rr_list_by_name_and_type(pkt,
					key_name,
					LDNS_RR_TYPE_DNSKEY,
					LDNS_SECTION_ANY_NOQUESTION
					);
			if (!keys) {
				my_pkt = ldns_resolver_query(res, key_name, LDNS_RR_TYPE_DNSKEY, c, qflags);
				keys = ldns_pkt_rr_list_by_name_and_type(my_pkt,
						key_name,
						LDNS_RR_TYPE_DNSKEY,
						LDNS_SECTION_ANY_NOQUESTION
						);
				new_chain->parent = ldns_dnssec_build_data_chain(res, qflags, keys, my_pkt, NULL);
				ldns_pkt_free(my_pkt);
			} else {
				new_chain->parent = ldns_dnssec_build_data_chain(res, qflags, keys, pkt, NULL);
			}
                        ldns_rr_list_deep_free(keys);
		}
	} else {
		/* 'self-signed', parent is a DS */
		
/* okay, either we have other keys signing the current one, or the current
 * one should have a DS record in the parent zone.
 * How do we find this out? Try both?
 *
 * request DNSKEYS for current zone, add all signatures to current level
 */


		new_chain->parent_type = 1;

		my_pkt = ldns_resolver_query(res, key_name, LDNS_RR_TYPE_DS, c, qflags);
		dss = ldns_pkt_rr_list_by_name_and_type(my_pkt,
							key_name,
							LDNS_RR_TYPE_DS,
							LDNS_SECTION_ANY_NOQUESTION
						       );
		if (dss) {
			new_chain->parent = ldns_dnssec_build_data_chain(res, qflags, dss, my_pkt, NULL);
			ldns_rr_list_deep_free(dss);
		}
		ldns_pkt_free(my_pkt);


		my_pkt = ldns_resolver_query(res, key_name, LDNS_RR_TYPE_DNSKEY, c, qflags);
		signatures2 = ldns_pkt_rr_list_by_name_and_type(my_pkt,
		                                         key_name,
		                                         LDNS_RR_TYPE_RRSIG,
							 LDNS_SECTION_ANSWER);
		if (signatures2) {
			/* TODO: what if there were still sigs there? */
			new_chain->signatures = signatures2;
		}
		ldns_pkt_free(my_pkt);
	}
	if (signatures) {
		ldns_rr_list_deep_free(signatures);
	}

	return new_chain;
}

ldns_dnssec_trust_tree *
ldns_dnssec_trust_tree_new()
{
	ldns_dnssec_trust_tree *new_tree = LDNS_XMALLOC(ldns_dnssec_trust_tree, 1);
	
	new_tree->rr = NULL;
	new_tree->rrset = NULL;
	new_tree->parent_count = 0;

	return new_tree;
}

void
ldns_dnssec_trust_tree_free(ldns_dnssec_trust_tree *tree)
{
	size_t i;
	if (tree) {
		for (i = 0; i < tree->parent_count; i++) {
			ldns_dnssec_trust_tree_free(tree->parents[i]);
		}
	}
	LDNS_FREE(tree);
}

ldns_status
ldns_dnssec_trust_tree_add_parent(ldns_dnssec_trust_tree *tree,
                                  const ldns_dnssec_trust_tree *parent,
                                  const ldns_rr *signature,
                                  const ldns_status parent_status)
{
	if (tree && parent && tree->parent_count < LDNS_DNSSEC_TRUST_TREE_MAX_PARENTS) {
/*
printf("Add parent for: ");
ldns_rr_print(stdout, tree->rr);
printf("parent: ");
ldns_rr_print(stdout, parent->rr);
*/
		tree->parents[tree->parent_count] = (ldns_dnssec_trust_tree *) parent;
		tree->parent_status[tree->parent_count] = parent_status;
		tree->parent_signature[tree->parent_count] = (ldns_rr *) signature;
		tree->parent_count++;
		return LDNS_STATUS_OK;
	} else {
		return LDNS_STATUS_ERR;
	}
}

static void
print_tabs(FILE *out, size_t nr, uint8_t *map, size_t treedepth)
{
	size_t i;
	for (i = 0; i < nr; i++) {
		if (i == nr - 1) {
			fprintf(out, "|---");
		} else if (map && i < treedepth && map[i] == 1) {
			fprintf(out, "|   ");
		} else {
			fprintf(out, "    ");
		}
	}
}

size_t
ldns_dnssec_trust_tree_depth(ldns_dnssec_trust_tree *tree)
{
	size_t result = 0;
	size_t parent = 0;
	size_t i;
	
	for (i = 0; i < tree->parent_count; i++) {
		parent = ldns_dnssec_trust_tree_depth(tree->parents[i]);
		if (parent > result) {
			result = parent;
		}
	}
	return 1 + result;
}

void
ldns_dnssec_trust_tree_print_sm(FILE *out, ldns_dnssec_trust_tree *tree, size_t tabs, bool extended, uint8_t *sibmap, size_t treedepth)
{
	size_t i;
	const ldns_rr_descriptor *descriptor;
	bool mapset = false;
	
	if (!sibmap) {
		treedepth = ldns_dnssec_trust_tree_depth(tree);
		sibmap = malloc(treedepth);
		memset(sibmap, 0, treedepth);
		mapset = true;
	}
	
	if (tree) {
		if (tree->rr) {
/*
			if (extended && tabs > 0) {
				print_tabs(out, tabs - 1);
				if (ldns_rr_get_type(tree->rr) == LDNS_RR_TYPE_DNSKEY) {
					fprintf(out, "which is signed by:\n");
				} else if (ldns_rr_get_type(tree->rr) == LDNS_RR_TYPE_DS) {
					fprintf(out, "which matches:\n");
				} else if (ldns_rr_get_type(tree->rr) == LDNS_RR_TYPE_NSEC) {
					fprintf(out, "whose existence is denied by:\n");
				}
			} else {
*/
/*
				if (ldns_rr_get_type(tree->rr) == LDNS_RR_TYPE_NSEC) {
					print_tabs(out, tabs, sibmap, treedepth);
					fprintf(out, "Existence is denied by:\n");
				}
*/
/*
			}
*/

			print_tabs(out, tabs, sibmap, treedepth);
			ldns_rdf_print(out, ldns_rr_owner(tree->rr));
			descriptor = ldns_rr_descript(ldns_rr_get_type(tree->rr));

			if (descriptor->_name) {
				fprintf(out, " (%s", descriptor->_name);
			} else {
				fprintf(out, " (TYPE%d", 
						ldns_rr_get_type(tree->rr));
			}
			if (ldns_rr_get_type(tree->rr) == LDNS_RR_TYPE_DNSKEY) {
				fprintf(out, " keytag: %u", ldns_calc_keytag(tree->rr));
			} else if (ldns_rr_get_type(tree->rr) == LDNS_RR_TYPE_DS) {
				fprintf(out, " keytag: ");
				ldns_rdf_print(out, ldns_rr_rdf(tree->rr, 0));
			}
			if (ldns_rr_get_type(tree->rr) == LDNS_RR_TYPE_NSEC) {
				fprintf(out, " ");
				ldns_rdf_print(out, ldns_rr_rdf(tree->rr, 0));
				fprintf(out, " ");
				ldns_rdf_print(out, ldns_rr_rdf(tree->rr, 1));
			}
			
			
			fprintf(out, ")\n");
			for (i = 0; i < tree->parent_count; i++) {
if (tree->parent_count > 1 && i < tree->parent_count - 1) {
sibmap[tabs] = 1;
} else {
sibmap[tabs] = 0;
}
				/* only print errors */
				if (ldns_rr_get_type(tree->parents[i]->rr) == LDNS_RR_TYPE_NSEC) {
					if (tree->parent_status[i] == LDNS_STATUS_OK) {
						print_tabs(out, tabs + 1, sibmap, treedepth);
						fprintf(out, "Existence is denied by:\n");
					} else {
						print_tabs(out, tabs + 1, sibmap, treedepth);
						fprintf(out, "Error in denial of existence: %s\n", ldns_get_errorstr_by_id(tree->parent_status[i]));
					}
				} else
				if (tree->parent_status[i] != LDNS_STATUS_OK) {
					print_tabs(out, tabs + 1, sibmap, treedepth);
					fprintf(out, "%s:\n", ldns_get_errorstr_by_id(tree->parent_status[i]));
					/*
					print_tabs(out, tabs + 1, sibmap, treedepth);
					*/
					ldns_rr_print(out, tree->parent_signature[i]);
					printf("For RRset:\n");
					ldns_rr_list_print(out, tree->rrset);
					printf("With key:\n");
					ldns_rr_print(out, tree->parents[i]->rr);
					/*
					print_tabs(out, tabs + 1, sibmap, treedepth);
					fprintf(out, "from:\n");
					*/
				}
				ldns_dnssec_trust_tree_print_sm(out, tree->parents[i], tabs+1, extended, sibmap, treedepth);
			}
		} else {
			print_tabs(out, tabs, sibmap, treedepth);
			fprintf(out, "<no data>\n");
		}
	} else {
		fprintf(out, "<null pointer>\n");
	}
	
	if (mapset) {
		free(sibmap);
	}
}

void
ldns_dnssec_trust_tree_print(FILE *out, ldns_dnssec_trust_tree *tree, size_t tabs, bool extended)
{
	ldns_dnssec_trust_tree_print_sm(out, tree, tabs, extended, NULL, 0);
}

void
ldns_dnssec_derive_trust_tree_normal_rrset(ldns_dnssec_trust_tree *new_tree,
                                           ldns_dnssec_data_chain *data_chain,
                                           ldns_rr *cur_sig_rr)
{
	size_t i, j;
	ldns_rr_list *cur_rrset = ldns_rr_list_clone(data_chain->rrset); 
	ldns_dnssec_trust_tree *cur_parent_tree;
	ldns_rr *cur_parent_rr;
	int cur_keytag;
	ldns_rr_list *tmp_rrset = NULL;
	ldns_status cur_status;

	cur_keytag = ldns_rdf2native_int16(ldns_rr_rrsig_keytag(cur_sig_rr));
	
	for (j = 0; j < ldns_rr_list_rr_count(data_chain->parent->rrset); j++) {
		cur_parent_rr = ldns_rr_list_rr(data_chain->parent->rrset, j);
		if (ldns_rr_get_type(cur_parent_rr) == LDNS_RR_TYPE_DNSKEY) {
			if (ldns_calc_keytag(cur_parent_rr) == cur_keytag) {

				/* TODO: check wildcard nsec too */
				if (cur_rrset && ldns_rr_list_rr_count(cur_rrset) > 0) {
					tmp_rrset = cur_rrset;
					if (ldns_rr_get_type(ldns_rr_list_rr(cur_rrset, 0)) == LDNS_RR_TYPE_NSEC) {
						/* might contain different names! sort and split */
						ldns_rr_list_sort(cur_rrset);
						if (tmp_rrset && tmp_rrset != cur_rrset) {
							ldns_rr_list_deep_free(tmp_rrset);
						}
						tmp_rrset = ldns_rr_list_pop_rrset(cur_rrset);
						
						/* with nsecs, this might be the wrong one */
						while (tmp_rrset &&
						       ldns_rr_list_rr_count(cur_rrset) > 0 &&
						       ldns_dname_compare(
						       ldns_rr_owner(ldns_rr_list_rr(tmp_rrset, 0)),
						       ldns_rr_owner(cur_sig_rr)) != 0) {
						        ldns_rr_list_deep_free(tmp_rrset);
							tmp_rrset = ldns_rr_list_pop_rrset(cur_rrset);
						}
					}
					cur_status = ldns_verify_rrsig(tmp_rrset, cur_sig_rr, cur_parent_rr);

					/* avoid dupes */
					for (i = 0; i < new_tree->parent_count; i++) {
						if (cur_parent_rr == new_tree->parents[i]->rr) {
							goto done;
						}
					}

					cur_parent_tree = ldns_dnssec_derive_trust_tree(data_chain->parent, cur_parent_rr);
					ldns_dnssec_trust_tree_add_parent(new_tree, cur_parent_tree, cur_sig_rr, cur_status);
				}


			}
		}
	}
	done:
	if (tmp_rrset && tmp_rrset != cur_rrset) {
		ldns_rr_list_deep_free(tmp_rrset);
	}
	ldns_rr_list_deep_free(cur_rrset);
}

void
ldns_dnssec_derive_trust_tree_dnskey_rrset(ldns_dnssec_trust_tree *new_tree,
                                           ldns_dnssec_data_chain *data_chain,
                                           ldns_rr *cur_rr,
                                           ldns_rr *cur_sig_rr)
{
	size_t j;
	ldns_rr_list *cur_rrset = data_chain->rrset;
	ldns_dnssec_trust_tree *cur_parent_tree;
	ldns_rr *cur_parent_rr;
	int cur_keytag;
	ldns_status cur_status;

	cur_keytag = ldns_rdf2native_int16(ldns_rr_rrsig_keytag(cur_sig_rr));

	for (j = 0; j < ldns_rr_list_rr_count(cur_rrset); j++) {
		cur_parent_rr = ldns_rr_list_rr(cur_rrset, j);
		if (cur_parent_rr != cur_rr &&
		    ldns_rr_get_type(cur_parent_rr) == LDNS_RR_TYPE_DNSKEY) {
			if (ldns_calc_keytag(cur_parent_rr) == cur_keytag
			   ) {
				/*cur_parent_tree = ldns_dnssec_derive_trust_tree(data_chain, cur_parent_rr);*/
				cur_parent_tree = ldns_dnssec_trust_tree_new();
				cur_parent_tree->rr = cur_parent_rr;
				cur_parent_tree->rrset = cur_rrset;
				cur_status = ldns_verify_rrsig(cur_rrset, cur_sig_rr, cur_parent_rr);
				ldns_dnssec_trust_tree_add_parent(new_tree, cur_parent_tree, cur_sig_rr, cur_status);
			}
		}
	}
}

void
ldns_dnssec_derive_trust_tree_ds_rrset(ldns_dnssec_trust_tree *new_tree,
                                       ldns_dnssec_data_chain *data_chain,
                                       ldns_rr *cur_rr)
{
	size_t j, h;
	ldns_rr_list *cur_rrset = data_chain->rrset;
	ldns_dnssec_trust_tree *cur_parent_tree;
	ldns_rr *cur_parent_rr;

	/* try the parent to see whether there are DSs there */
	if (ldns_rr_get_type(cur_rr) == LDNS_RR_TYPE_DNSKEY &&
	    data_chain->parent &&
	    data_chain->parent->rrset
	   ) {
		for (j = 0; j < ldns_rr_list_rr_count(data_chain->parent->rrset); j++) {
			cur_parent_rr = ldns_rr_list_rr(data_chain->parent->rrset, j);
			if (ldns_rr_get_type(cur_parent_rr) == LDNS_RR_TYPE_DS) {
				for (h = 0; h < ldns_rr_list_rr_count(cur_rrset); h++) {
					cur_rr = ldns_rr_list_rr(cur_rrset, h);
					if (ldns_rr_compare_ds(cur_rr, cur_parent_rr)) {
						cur_parent_tree = ldns_dnssec_derive_trust_tree(data_chain->parent, cur_parent_rr);
						ldns_dnssec_trust_tree_add_parent(new_tree, cur_parent_tree, NULL, LDNS_STATUS_OK);
					} else {
						/*ldns_rr_print(stdout, cur_parent_rr);*/
						
					}
				}
				cur_rr = ldns_rr_list_rr(cur_rrset, 0);
			}
		}
	}
}

void
breakme()
{
	// just to define a break point
	int i,j;
	i = 123;
	j = i + 1;	
}

void
ldns_dnssec_derive_trust_tree_no_sig(ldns_dnssec_trust_tree *new_tree,
                                     ldns_dnssec_data_chain *data_chain)
{
	size_t i;
	ldns_rr_list *cur_rrset;
	ldns_rr *cur_parent_rr;
	ldns_dnssec_trust_tree *cur_parent_tree;
	ldns_status result;
	
	if (data_chain->parent && data_chain->parent->rrset) {
		cur_rrset = data_chain->parent->rrset;
		/* nsec? check all */
		result = ldns_dnssec_verify_denial(new_tree->rr, cur_rrset, data_chain->parent->signatures);
		for (i = 0; i < ldns_rr_list_rr_count(cur_rrset); i++) {
			cur_parent_rr = ldns_rr_list_rr(cur_rrset, i);
			cur_parent_tree = ldns_dnssec_derive_trust_tree(data_chain->parent, cur_parent_rr);
			printf("Adding without checking: ");
			ldns_rr_print(stdout, cur_parent_rr);
			ldns_dnssec_trust_tree_add_parent(new_tree, cur_parent_tree, NULL, result);
		}
	}
}

/* if rr is null, take the first from the rrset */
ldns_dnssec_trust_tree *
ldns_dnssec_derive_trust_tree(ldns_dnssec_data_chain *data_chain, ldns_rr *rr)
{
	ldns_rr_list *cur_rrset;
	ldns_rr_list *cur_sigs;
	ldns_rr *cur_rr = NULL;
	ldns_rr *cur_sig_rr;
	uint16_t cur_keytag;
	size_t i, j;

	ldns_dnssec_trust_tree *new_tree = ldns_dnssec_trust_tree_new();
	
	if (data_chain && data_chain->rrset) {
		cur_rrset = data_chain->rrset;
	
		cur_sigs = data_chain->signatures;

			if (rr) {
				cur_rr = rr;
			}

			if (!cur_rr && ldns_rr_list_rr_count(cur_rrset) > 0) {
				cur_rr = ldns_rr_list_rr(cur_rrset, 0);
			}

			if (cur_rr) {
				new_tree->rr = cur_rr;
				new_tree->rrset = cur_rrset;
				/* there are three possibilities:
				   1 - 'normal' rrset, signed by a key
				   2 - dnskey signed by other dnskey
				   3 - dnskey proven by higher level DS
				   (data denied by nsec is a special case that can
				    occur in multiple places)
				   
				*/
				if (cur_sigs) {
					for (i = 0; i < ldns_rr_list_rr_count(cur_sigs); i++) {
						/* find the appropriate key in the parent list */
						cur_sig_rr = ldns_rr_list_rr(cur_sigs, i);
						cur_keytag = ldns_rdf2native_int16(ldns_rr_rrsig_keytag(cur_sig_rr));

						if (ldns_rr_get_type(cur_rr) == LDNS_RR_TYPE_NSEC) {
							if (ldns_dname_compare(ldns_rr_owner(cur_sig_rr), 
									       ldns_rr_owner(cur_rr)))
							{
								/* find first that does match */

								for (j = 0;
								     j < ldns_rr_list_rr_count(cur_rrset) && 
								     ldns_dname_compare(ldns_rr_owner(cur_sig_rr),ldns_rr_owner(cur_rr)) != 0;
								     j++) {
									cur_rr = ldns_rr_list_rr(cur_rrset, j);
									
								}
								if (ldns_dname_compare(ldns_rr_owner(cur_sig_rr), 
										       ldns_rr_owner(cur_rr)))
								{
									break;
								}
							}
							
						}
						/* option 1 */
						if (data_chain->parent) {
							ldns_dnssec_derive_trust_tree_normal_rrset(new_tree, data_chain, cur_sig_rr);
						}

						/* option 2 */
						ldns_dnssec_derive_trust_tree_dnskey_rrset(new_tree, data_chain, cur_rr, cur_sig_rr);
					}
					
					ldns_dnssec_derive_trust_tree_ds_rrset(new_tree, data_chain, cur_rr);
				} else {
					/* no signatures? maybe it's nsec data */
					
					/* just add every rr from parent as new parent */
					ldns_dnssec_derive_trust_tree_no_sig(new_tree, data_chain);
				}
			}
	}

	return new_tree;
}

/*
 * returns OK if there is a path from tree to key with only OK
 * the (first) error in between otherwise
 * or NOT_FOUND if the key wasn't present at all
 */
ldns_status
ldns_dnssec_trust_tree_contains_keys(ldns_dnssec_trust_tree *tree, ldns_rr_list *trusted_keys)
{
	size_t i;
	ldns_status result = LDNS_STATUS_CRYPTO_NO_DNSKEY;
	bool equal;
	ldns_status parent_result;
	
	if (tree && trusted_keys && ldns_rr_list_rr_count(trusted_keys) > 0)
		{ if (tree->rr) {
			for (i = 0; i < ldns_rr_list_rr_count(trusted_keys); i++) {
				/*
				printf("Trying key: ");
				ldns_rr_print(stdout, tree->rr);
				*/
				equal = ldns_rr_compare_ds(tree->rr, ldns_rr_list_rr(trusted_keys, i));
				if (equal) {
					result = LDNS_STATUS_OK;
					return result;
				}
			}
		}
		for (i = 0; i < tree->parent_count; i++) {
			parent_result = ldns_dnssec_trust_tree_contains_keys(tree->parents[i], trusted_keys);
			if (parent_result != LDNS_STATUS_CRYPTO_NO_DNSKEY) {
				if (tree->parent_status[i] != LDNS_STATUS_OK) {
					result = tree->parent_status[i];
				} else {
					if (ldns_rr_get_type(tree->rr) == LDNS_RR_TYPE_NSEC &&
					    parent_result == LDNS_STATUS_OK
					   ) {
						result = LDNS_STATUS_DNSSEC_EXISTENCE_DENIED;
					} else {
						result = parent_result;
					}
				}
			}
		}
	} else {
		result = LDNS_STATUS_ERR;
	}
	
	return result;
}

/* used only on the public key RR */
uint16_t
ldns_calc_keytag(const ldns_rr *key)
{
	uint16_t ac16;
	ldns_buffer *keybuf;
	size_t keysize;

	if (!key) {
		return 0;
	}

/*
printf("calc keytag for key at %p:\n", key);
ldns_rr_print(stdout, key);
*/
	if (ldns_rr_get_type(key) != LDNS_RR_TYPE_DNSKEY &&
	    ldns_rr_get_type(key) != LDNS_RR_TYPE_KEY
	   ) {
		return 0;
	}

	/* rdata to buf - only put the rdata in a buffer */
	keybuf = ldns_buffer_new(LDNS_MIN_BUFLEN); /* grows */
	if (!keybuf) {
		return 0;
	}
	(void)ldns_rr_rdata2buffer_wire(keybuf, key);
	/* the current pos in the buffer is the keysize */
	keysize= ldns_buffer_position(keybuf);

	ac16 = ldns_calc_keytag_raw(ldns_buffer_begin(keybuf), keysize);
	ldns_buffer_free(keybuf);
	return ac16;
}

uint16_t ldns_calc_keytag_raw(uint8_t* key, size_t keysize)
{
	unsigned int i;
	uint32_t ac32;
	uint16_t ac16;

	if(keysize < 4)
		return 0;
	/* look at the algorithm field, copied from 2535bis */
	if (key[3] == LDNS_RSAMD5) {
		ac16 = 0;
		if (keysize > 4) {
			memmove(&ac16, key + keysize - 3, 2);
		}
		ac16 = ntohs(ac16);
		return (uint16_t) ac16;
	} else {
		ac32 = 0;
		for (i = 0; (size_t)i < keysize; ++i) {
			ac32 += (i & 1) ? key[i] : key[i] << 8;
		}
		ac32 += (ac32 >> 16) & 0xFFFF;
		return (uint16_t) (ac32 & 0xFFFF);
	}
}

ldns_status
ldns_verify(ldns_rr_list *rrset, ldns_rr_list *rrsig, const ldns_rr_list *keys, 
		ldns_rr_list *good_keys)
{
	uint16_t i;
	bool valid;
	ldns_status verify_result = LDNS_STATUS_ERR;

	if (!rrset || !rrsig || !keys) {
		return LDNS_STATUS_ERR;
	}

	valid = false;

	if (ldns_rr_list_rr_count(rrset) < 1) {
		return LDNS_STATUS_ERR;
	}

	if (ldns_rr_list_rr_count(rrsig) < 1) {
		return LDNS_STATUS_CRYPTO_NO_RRSIG;
	}
	
	if (ldns_rr_list_rr_count(keys) < 1) {
		verify_result = LDNS_STATUS_CRYPTO_NO_TRUSTED_DNSKEY;
	} else {
		for (i = 0; i < ldns_rr_list_rr_count(rrsig); i++) {

			if (ldns_verify_rrsig_keylist(rrset,
					ldns_rr_list_rr(rrsig, i),
					keys, good_keys) == LDNS_STATUS_OK) {
				verify_result = LDNS_STATUS_OK;
			}
		}
	}
	return verify_result;
}

ldns_rr_list *
ldns_fetch_valid_domain_keys(const ldns_resolver * res, const ldns_rdf * domain, const ldns_rr_list * keys, ldns_status *status)
{
  ldns_rr_list * trusted_keys = NULL;
  ldns_rr_list * ds_keys = NULL;

  if (res && domain && keys) {

    if ((trusted_keys = ldns_validate_domain_dnskey(res, domain, keys))) {
      *status = LDNS_STATUS_OK;
    } else {
      
      /* No trusted keys in this domain, we'll have to find some in the parent domain */
      *status = LDNS_STATUS_CRYPTO_NO_TRUSTED_DNSKEY;
      
      if (ldns_rdf_size(domain) > 1) { /* Fail if we are at the root */
        ldns_rr_list * parent_keys;
        ldns_rdf * parent_domain = ldns_dname_left_chop(domain);
	
        if ((parent_keys = ldns_fetch_valid_domain_keys(res, parent_domain, keys, status))) {
	  
          /* Check DS records */
          if ((ds_keys = ldns_validate_domain_ds(res, domain, parent_keys))) {
            trusted_keys = ldns_fetch_valid_domain_keys(res, domain, ds_keys, status);
            ldns_rr_list_deep_free(ds_keys);
          } else {
            /* No valid DS at the parent -- fail */
            *status = LDNS_STATUS_CRYPTO_NO_TRUSTED_DS ;
          }
          ldns_rr_list_deep_free(parent_keys);
        }
        ldns_rdf_free(parent_domain);
      }
    }
  }
  return trusted_keys;
}

ldns_rr_list *
ldns_validate_domain_dnskey (const ldns_resolver * res, const ldns_rdf * domain, const ldns_rr_list * keys)
{
  ldns_status status;
  ldns_pkt * keypkt;
  ldns_rr * cur_key;
  uint16_t key_i; uint16_t key_j; uint16_t key_k;
  uint16_t sig_i; ldns_rr * cur_sig;

  ldns_rr_list * domain_keys = NULL;
  ldns_rr_list * domain_sigs = NULL;
  ldns_rr_list * trusted_keys = NULL;

  /* Fetch keys for the domain */
  if ((keypkt = ldns_resolver_query(res, domain, LDNS_RR_TYPE_DNSKEY, LDNS_RR_CLASS_IN, LDNS_RD))) {

    domain_keys = ldns_pkt_rr_list_by_type(keypkt, LDNS_RR_TYPE_DNSKEY, LDNS_SECTION_ANSWER);
    domain_sigs = ldns_pkt_rr_list_by_type(keypkt, LDNS_RR_TYPE_RRSIG, LDNS_SECTION_ANSWER);

    /* Try to validate the record using our keys */
    for (key_i=0; key_i< ldns_rr_list_rr_count(domain_keys); key_i++) {
      
      cur_key = ldns_rr_list_rr(domain_keys, key_i);
      for (key_j=0; key_j<ldns_rr_list_rr_count(keys); key_j++) {
        if (ldns_rr_compare_ds(ldns_rr_list_rr(keys, key_j), cur_key)) {
          
          /* Current key is trusted -- validate */
          trusted_keys = ldns_rr_list_new();
          
          for (sig_i=0; sig_i<ldns_rr_list_rr_count(domain_sigs); sig_i++) {
            cur_sig = ldns_rr_list_rr(domain_sigs, sig_i);
            /* Avoid non-matching sigs */
            if (ldns_rdf2native_int16(ldns_rr_rrsig_keytag(cur_sig)) == ldns_calc_keytag(cur_key)) {
              if ((status=ldns_verify_rrsig(domain_keys, cur_sig, cur_key)) == LDNS_STATUS_OK) {
                
                /* Push the whole rrset -- we can't do much more */
                for (key_k=0; key_k<ldns_rr_list_rr_count(domain_keys); key_k++) {
                  ldns_rr_list_push_rr(trusted_keys, ldns_rr_clone(ldns_rr_list_rr(domain_keys, key_k)));
                }
                
                ldns_rr_list_deep_free(domain_keys);
                ldns_rr_list_deep_free(domain_sigs);
                ldns_pkt_free(keypkt);
                return trusted_keys;
              } /* else {
                fprintf(stderr, "# Signature verification failed: %s\n", ldns_get_errorstr_by_id(status));
              }
            } else {
              fprintf(stderr, "# Non-matching keytag for sig %u. Skipping.\n", sig_i);
                */
            }
          }
	  
          /* Only push our trusted key */
          ldns_rr_list_push_rr(trusted_keys, ldns_rr_clone(cur_key));
        }
      }
    }

    ldns_rr_list_deep_free(domain_keys);
    ldns_rr_list_deep_free(domain_sigs);
    ldns_pkt_free(keypkt);

  } else {
    status = LDNS_STATUS_CRYPTO_NO_DNSKEY;
  }
    
  return trusted_keys;
}

ldns_rr_list *
ldns_validate_domain_ds (const ldns_resolver * res, const ldns_rdf * domain, const ldns_rr_list * keys)
{
  ldns_status status;
  ldns_pkt * dspkt;
  uint16_t key_i;
  ldns_rr_list * rrset = NULL;
  ldns_rr_list * sigs = NULL;
  ldns_rr_list * trusted_keys = NULL;

  /* Fetch DS for the domain */
  if ((dspkt = ldns_resolver_query(res, domain, LDNS_RR_TYPE_DS, LDNS_RR_CLASS_IN, LDNS_RD))) {

    rrset = ldns_pkt_rr_list_by_type(dspkt, LDNS_RR_TYPE_DS, LDNS_SECTION_ANSWER);
    sigs = ldns_pkt_rr_list_by_type(dspkt, LDNS_RR_TYPE_RRSIG, LDNS_SECTION_ANSWER);

    /* Validate sigs */
    if ((status = ldns_verify(rrset, sigs, keys, NULL)) == LDNS_STATUS_OK) {
      trusted_keys = ldns_rr_list_new();
      for (key_i=0; key_i<ldns_rr_list_rr_count(rrset); key_i++) {
	ldns_rr_list_push_rr(trusted_keys, ldns_rr_clone(ldns_rr_list_rr(rrset, key_i)));
      }
    }

    ldns_rr_list_deep_free(rrset);
    ldns_rr_list_deep_free(sigs);
    ldns_pkt_free(dspkt);

  } else {
    status = LDNS_STATUS_CRYPTO_NO_DS;
  }

  return trusted_keys;
}

#ifdef HAVE_SSL
ldns_status
ldns_verify_trusted(ldns_resolver * res, ldns_rr_list * rrset, ldns_rr_list * rrsigs, ldns_rr_list * validating_keys)
{
  /* */
  uint16_t sig_i; uint16_t key_i;
  ldns_rr * cur_sig; ldns_rr * cur_key;
  ldns_rr_list * trusted_keys = NULL;
  ldns_status result = LDNS_STATUS_ERR;
printf("[verify_trusted] set default result to %s\n", ldns_get_errorstr_by_id(result));

  if (!res || !rrset || !rrsigs) {
    return LDNS_STATUS_ERR;
  }

  if (ldns_rr_list_rr_count(rrset) < 1) {
    return LDNS_STATUS_ERR;
  }

  if (ldns_rr_list_rr_count(rrsigs) < 1) {
    return LDNS_STATUS_CRYPTO_NO_RRSIG;
  }
  
  /* Look at each sig */
  for (sig_i=0; sig_i < ldns_rr_list_rr_count(rrsigs); sig_i++) {

    cur_sig = ldns_rr_list_rr(rrsigs, sig_i);
    /* Get a valid signer key and validate the sig */
    if ((trusted_keys = ldns_fetch_valid_domain_keys(res, ldns_rr_rrsig_signame(cur_sig), ldns_resolver_dnssec_anchors(res), &result))) {

      for (key_i = 0; key_i < ldns_rr_list_rr_count(trusted_keys); key_i++) {
        cur_key = ldns_rr_list_rr(trusted_keys, key_i);
printf("[verify_trusted] trying:\n[verify_trusted] ");

        if ((result = ldns_verify_rrsig(rrset, cur_sig, cur_key)) == LDNS_STATUS_OK) {
          if (validating_keys) {
            ldns_rr_list_push_rr(validating_keys, ldns_rr_clone(cur_key));
          }
          ldns_rr_list_deep_free(trusted_keys);
          printf("[verify_trusted] returning OK\n");
          return LDNS_STATUS_OK;
        }
        else {
        	printf("RESULT: %s\nFOR:\n", ldns_get_errorstr_by_id(result));
        	ldns_rr_list_print(stdout, rrset);
        	ldns_rr_print(stdout, cur_sig);
        	ldns_rr_print(stdout, cur_key);
        	
        }
printf("[verify_trusted] set result to %s\n", ldns_get_errorstr_by_id(result));
      }
    }
    else {
    printf("[verify_trusted] no valid domain keys\n");
    }
  }

  ldns_rr_list_deep_free(trusted_keys);
  printf("[verify_trusted] returning: %s\n", ldns_get_errorstr_by_id(result));
  return result;
}
#endif


ldns_status
ldns_verify_rrsig_buffers(ldns_buffer *rawsig_buf, ldns_buffer *verify_buf, 
	ldns_buffer *key_buf, uint8_t algo)
{
	return ldns_verify_rrsig_buffers_raw((unsigned char*)ldns_buffer_begin(
		rawsig_buf), ldns_buffer_position(rawsig_buf), verify_buf,
		(unsigned char*)ldns_buffer_begin(key_buf), 
		ldns_buffer_position(key_buf), algo);
}

ldns_status
ldns_verify_rrsig_buffers_raw(unsigned char* sig, size_t siglen,
	ldns_buffer *verify_buf, unsigned char* key, size_t keylen, 
	uint8_t algo)
{
	/* check for right key */
	switch(algo) {
		case LDNS_DSA:
		case LDNS_DSA_NSEC3:
			return ldns_verify_rrsig_dsa_raw(sig, siglen, verify_buf, key, keylen);
			break;
		case LDNS_RSASHA1:
		case LDNS_RSASHA1_NSEC3:
			return ldns_verify_rrsig_rsasha1_raw(sig, siglen, verify_buf, key, keylen);
			break;
		case LDNS_RSAMD5:
			return ldns_verify_rrsig_rsamd5_raw(sig, siglen, verify_buf, key, keylen);
			break;
		default:
			/* do you know this alg?! */
			return LDNS_STATUS_CRYPTO_UNKNOWN_ALGO;
	}
}

/* Post 1.0 TODO: next 2 functions contain a lot of similar code */
/* 
 * to verify:
 * - create the wire fmt of the b64 key rdata
 * - create the wire fmt of the sorted rrset
 * - create the wire fmt of the b64 sig rdata
 * - create the wire fmt of the sig without the b64 rdata
 * - cat the sig data (without b64 rdata) to the rrset
 * - verify the rrset+sig, with the b64 data and the b64 key data
 */
ldns_status
ldns_verify_rrsig_keylist(ldns_rr_list *rrset, ldns_rr *rrsig, const ldns_rr_list *keys, 
		ldns_rr_list *good_keys)
{
	ldns_buffer *rawsig_buf;
	ldns_buffer *verify_buf;
	ldns_buffer *key_buf;
	uint32_t orig_ttl;
	uint16_t i;
	uint8_t sig_algo;
	ldns_status result;
	ldns_rr *current_key;
	ldns_rr_list *rrset_clone;
	ldns_rr_list *validkeys;
	time_t now, inception, expiration;
	uint8_t label_count;
	ldns_rdf *wildcard_name;
	ldns_rdf *wildcard_chopped;
	ldns_rdf *wildcard_chopped_tmp;


	if (!rrset) {
		return LDNS_STATUS_ERR;
	}

	validkeys = ldns_rr_list_new();
	if (!validkeys) {
		return LDNS_STATUS_MEM_ERR;
	}
	
	/* canonicalize the sig */
	ldns_dname2canonical(ldns_rr_owner(rrsig));
	
	/* clone the rrset so that we can fiddle with it */
	rrset_clone = ldns_rr_list_clone(rrset);

	/* check if the typecovered is equal to the type checked */
	if (ldns_rdf2rr_type(ldns_rr_rrsig_typecovered(rrsig)) !=
			ldns_rr_get_type(ldns_rr_list_rr(rrset_clone, 0))) {
		ldns_rr_list_deep_free(rrset_clone);
		ldns_rr_list_deep_free(validkeys);
		return LDNS_STATUS_CRYPTO_TYPE_COVERED_ERR;
	}
	
	/* create the buffers which will certainly hold the raw data */
	rawsig_buf = ldns_buffer_new(LDNS_MAX_PACKETLEN);
	verify_buf  = ldns_buffer_new(LDNS_MAX_PACKETLEN);
	
	sig_algo = ldns_rdf2native_int8(ldns_rr_rdf(rrsig, 1));
	result = LDNS_STATUS_ERR;

	/* check the signature time stamps */
	inception = ldns_rdf2native_time_t(ldns_rr_rrsig_inception(rrsig));
	expiration = ldns_rdf2native_time_t(ldns_rr_rrsig_expiration(rrsig));
	now = time(NULL);

	if (expiration - inception < 0) {
		/* bad sig, expiration before inception?? Tsssg */
		ldns_buffer_free(verify_buf);
		ldns_buffer_free(rawsig_buf);
		ldns_rr_list_deep_free(rrset_clone);
		ldns_rr_list_deep_free(validkeys);
		return LDNS_STATUS_CRYPTO_EXPIRATION_BEFORE_INCEPTION;
	}
	if (now - inception < 0) {
		/* bad sig, inception date has not yet come to pass */
		ldns_buffer_free(rawsig_buf);
		ldns_buffer_free(verify_buf);
		ldns_rr_list_deep_free(rrset_clone);
		ldns_rr_list_deep_free(validkeys);
		return LDNS_STATUS_CRYPTO_SIG_NOT_INCEPTED;
	}
	if (expiration - now < 0) {
		/* bad sig, expiration date has passed */
		ldns_buffer_free(rawsig_buf);
		ldns_buffer_free(verify_buf);
		ldns_rr_list_deep_free(rrset_clone);
		ldns_rr_list_deep_free(validkeys);
		return LDNS_STATUS_CRYPTO_SIG_EXPIRED;
	}
	
	/* create a buffer with b64 signature rdata */
	if (ldns_rdf2buffer_wire(rawsig_buf, ldns_rr_rdf(rrsig, 8)) != LDNS_STATUS_OK) {
		ldns_buffer_free(rawsig_buf);
		ldns_buffer_free(verify_buf);
		ldns_rr_list_deep_free(rrset_clone);
		ldns_rr_list_deep_free(validkeys);
		return LDNS_STATUS_MEM_ERR;
	}

	orig_ttl = ldns_rdf2native_int32( ldns_rr_rdf(rrsig, 3));
	label_count = ldns_rdf2native_int8(ldns_rr_rdf(rrsig, 2));

	/* reset the ttl in the rrset with the orig_ttl from the sig */
	/* and update owner name if it was wildcard */
	for(i = 0; i < ldns_rr_list_rr_count(rrset_clone); i++) {
		if (label_count < 
			ldns_dname_label_count(
					ldns_rr_owner(ldns_rr_list_rr(rrset_clone, i)))) {
			(void) ldns_str2rdf_dname(&wildcard_name, "*");
			wildcard_chopped = ldns_rdf_clone(ldns_rr_owner(ldns_rr_list_rr(rrset_clone, i)));
			while (label_count < ldns_dname_label_count(wildcard_chopped)) {
				wildcard_chopped_tmp = ldns_dname_left_chop(wildcard_chopped);
				ldns_rdf_deep_free(wildcard_chopped);
				wildcard_chopped = wildcard_chopped_tmp;
			}
			(void) ldns_dname_cat(wildcard_name, wildcard_chopped);
			ldns_rdf_deep_free(wildcard_chopped);
			ldns_rdf_deep_free(ldns_rr_owner(ldns_rr_list_rr(rrset_clone, i)));
			ldns_rr_set_owner(ldns_rr_list_rr(rrset_clone, i), 
					wildcard_name);
				  	
		}
		ldns_rr_set_ttl(ldns_rr_list_rr(rrset_clone, i), orig_ttl);
		/* convert to lowercase */
		ldns_rr2canonical(ldns_rr_list_rr(rrset_clone, i));
	}

	/* sort the rrset in canonical order  */
	ldns_rr_list_sort(rrset_clone);

	/* put the signature rr (without the b64) to the verify_buf */
	if (ldns_rrsig2buffer_wire(verify_buf, rrsig) != LDNS_STATUS_OK) {
		ldns_buffer_free(rawsig_buf);
		ldns_buffer_free(verify_buf);
		ldns_rr_list_deep_free(rrset_clone);
		ldns_rr_list_deep_free(validkeys);
		return LDNS_STATUS_MEM_ERR;
	}

	/* add the rrset in verify_buf */
	if (ldns_rr_list2buffer_wire(verify_buf, rrset_clone) != LDNS_STATUS_OK) {
		ldns_buffer_free(rawsig_buf);
		ldns_buffer_free(verify_buf);
		ldns_rr_list_deep_free(rrset_clone);
		ldns_rr_list_deep_free(validkeys);
		return LDNS_STATUS_MEM_ERR;
	}

	for(i = 0; i < ldns_rr_list_rr_count(keys); i++) {
		current_key = ldns_rr_list_rr(keys, i);
		/* before anything, check if the keytags match */
		if (ldns_calc_keytag(current_key) ==
			ldns_rdf2native_int16(ldns_rr_rrsig_keytag(rrsig))) {
			key_buf = ldns_buffer_new(LDNS_MAX_PACKETLEN);
			
			/* put the key-data in a buffer, that's the third rdf, with
			 * the base64 encoded key data */
			if (ldns_rdf2buffer_wire(key_buf,
					ldns_rr_rdf(current_key, 3)) != LDNS_STATUS_OK) {
				ldns_buffer_free(rawsig_buf);
				ldns_buffer_free(verify_buf);
				/* returning is bad might screw up good keys later in the list
				   what to do? */
				ldns_rr_list_deep_free(rrset_clone);
				ldns_rr_list_deep_free(validkeys);
				return LDNS_STATUS_MEM_ERR;
			}

			/* check for right key */
			if (sig_algo == ldns_rdf2native_int8(ldns_rr_rdf(current_key, 
							2))) {
				result = ldns_verify_rrsig_buffers(rawsig_buf, 
						verify_buf, key_buf, sig_algo);
			} else {
				result = LDNS_STATUS_CRYPTO_UNKNOWN_ALGO;
			}
			
			ldns_buffer_free(key_buf); 

			if (result == LDNS_STATUS_OK) {
				/* one of the keys has matched, don't break
				 * here, instead put the 'winning' key in
				 * the validkey list and return the list 
				 * later */
				if (!ldns_rr_list_push_rr(validkeys, current_key)) {
					/* couldn't push the key?? */
					ldns_buffer_free(rawsig_buf);
					ldns_buffer_free(verify_buf);
					ldns_rr_list_deep_free(rrset_clone);
					ldns_rr_list_deep_free(validkeys);
					return LDNS_STATUS_MEM_ERR;
				}
			} 
		} else {
			if (result == LDNS_STATUS_ERR) {
				result = LDNS_STATUS_CRYPTO_NO_MATCHING_KEYTAG_DNSKEY;
			}
		}
	}

	/* no longer needed */
	ldns_rr_list_deep_free(rrset_clone);
	ldns_buffer_free(rawsig_buf);
	ldns_buffer_free(verify_buf);
	if (ldns_rr_list_rr_count(validkeys) == 0) {
		/* no keys were added, return last error */
		ldns_rr_list_deep_free(validkeys); 
		return result;
	} else {
		ldns_rr_list_cat(good_keys, validkeys);
		ldns_rr_list_free(validkeys);
		return LDNS_STATUS_OK;
	}
}

ldns_status
ldns_convert_dsa_rrsig_rdata(
                             ldns_buffer *target_buffer,
                             ldns_rdf *sig_rdf
                             )
{
	/* the EVP api wants the DER encoding of the signature... */
	uint8_t t;
	BIGNUM *R, *S;
	DSA_SIG *dsasig;
	unsigned char *raw_sig = NULL;
	int raw_sig_len;
	
	/* extract the R and S field from the sig buffer */
	t = ldns_rdf_data(sig_rdf)[0];
	R = BN_new();
	(void) BN_bin2bn(ldns_rdf_data(sig_rdf) + 1, SHA_DIGEST_LENGTH, R);
	S = BN_new();
	(void) BN_bin2bn(ldns_rdf_data(sig_rdf) + 21, SHA_DIGEST_LENGTH, S);

	dsasig = DSA_SIG_new();
	if (!dsasig) {
		return LDNS_STATUS_MEM_ERR;
	}

	dsasig->r = R;
	dsasig->s = S;
	
	raw_sig_len = i2d_DSA_SIG(dsasig, &raw_sig);
	
	/* todo reserve() */
	if (ldns_buffer_reserve(target_buffer, raw_sig_len)) {
		ldns_buffer_write(target_buffer, raw_sig, raw_sig_len);
	}
	return ldns_buffer_status(target_buffer);
}


ldns_status
ldns_verify_rrsig(ldns_rr_list *rrset, ldns_rr *rrsig, ldns_rr *key)
{
	ldns_buffer *rawsig_buf;
	ldns_buffer *verify_buf;
	ldns_buffer *key_buf;
	uint32_t orig_ttl;
	uint16_t i;
	uint8_t sig_algo;
	uint16_t label_count;
	ldns_status result;
	ldns_rr_list *rrset_clone;
	time_t now, inception, expiration;
	ldns_rdf *wildcard_name;
	ldns_rdf *wildcard_chopped;
	ldns_rdf *wildcard_chopped_tmp;


	if (!rrset) {
		return LDNS_STATUS_NO_DATA;
	}

	/* lowercase the rrsig owner name */
	ldns_dname2canonical(ldns_rr_owner(rrsig));

	/* check the signature time stamps */
	inception = ldns_rdf2native_time_t(ldns_rr_rrsig_inception(rrsig));
	expiration = ldns_rdf2native_time_t(ldns_rr_rrsig_expiration(rrsig));
	now = time(NULL);

	if (expiration - inception < 0) {
		/* bad sig, expiration before inception?? Tsssg */
		return LDNS_STATUS_CRYPTO_EXPIRATION_BEFORE_INCEPTION;
	}
	if (now - inception < 0) {
		/* bad sig, inception date has passed */
		return LDNS_STATUS_CRYPTO_SIG_NOT_INCEPTED;
	}

	if (expiration - now < 0) {
		/* bad sig, expiration date has passed */
		return LDNS_STATUS_CRYPTO_SIG_EXPIRED;
	}
	/* clone the rrset so that we can fiddle with it */
	rrset_clone = ldns_rr_list_clone(rrset);
	
	/* create the buffers which will certainly hold the raw data */
	rawsig_buf = ldns_buffer_new(LDNS_MAX_PACKETLEN);
	verify_buf  = ldns_buffer_new(LDNS_MAX_PACKETLEN);
	
	sig_algo = ldns_rdf2native_int8(ldns_rr_rdf(rrsig, 1));
	
	/* check for known and implemented algo's now (otherwise 
	 * the function could return a wrong error
	 */
	/* create a buffer with signature rdata */
	/* for some algorithms we need other data than for others... */
	/* (the DSA API wants DER encoding for instance) */

	switch(sig_algo) {
		case LDNS_RSAMD5:
		case LDNS_RSASHA1:
		case LDNS_RSASHA1_NSEC3:
			if (ldns_rdf2buffer_wire(rawsig_buf,
						ldns_rr_rdf(rrsig, 8)) != LDNS_STATUS_OK) {
				ldns_buffer_free(rawsig_buf);
				ldns_buffer_free(verify_buf);
				return LDNS_STATUS_MEM_ERR;
			}
			break;
		case LDNS_DSA:
		case LDNS_DSA_NSEC3:
			if (ldns_convert_dsa_rrsig_rdata(rawsig_buf,
						ldns_rr_rdf(rrsig, 8)) != LDNS_STATUS_OK) {
				ldns_buffer_free(rawsig_buf);
				ldns_buffer_free(verify_buf);
				return LDNS_STATUS_MEM_ERR;
			}
			break;
			break;
		case LDNS_DH:
		case LDNS_ECC:
		case LDNS_INDIRECT:
			ldns_buffer_free(rawsig_buf);
			ldns_buffer_free(verify_buf);
			return LDNS_STATUS_CRYPTO_ALGO_NOT_IMPL;
		default:
			ldns_buffer_free(rawsig_buf);
			ldns_buffer_free(verify_buf);
			ldns_rr_list_deep_free(rrset_clone);
			return LDNS_STATUS_CRYPTO_UNKNOWN_ALGO;
	}
	
	result = LDNS_STATUS_ERR;

	/* remove labels if the label count is higher than the label count
	   from the rrsig */
	label_count = ldns_rdf2native_int8(ldns_rr_rdf(rrsig, 2));

	orig_ttl = ldns_rdf2native_int32(
			ldns_rr_rdf(rrsig, 3));

	/* reset the ttl in the rrset with the orig_ttl from the sig */
	for(i = 0; i < ldns_rr_list_rr_count(rrset_clone); i++) {
		if (label_count < 
			ldns_dname_label_count(
				   	ldns_rr_owner(ldns_rr_list_rr(rrset_clone, i)))) {
			(void) ldns_str2rdf_dname(&wildcard_name, "*");
			wildcard_chopped = ldns_rdf_clone(ldns_rr_owner(ldns_rr_list_rr(rrset_clone, i)));
			while (label_count < ldns_dname_label_count(wildcard_chopped)) {
				wildcard_chopped_tmp = ldns_dname_left_chop(wildcard_chopped);
				ldns_rdf_deep_free(wildcard_chopped);
				wildcard_chopped = wildcard_chopped_tmp;
			}
			(void) ldns_dname_cat(wildcard_name, wildcard_chopped);
			ldns_rdf_deep_free(wildcard_chopped);
			ldns_rdf_deep_free(ldns_rr_owner(ldns_rr_list_rr(rrset_clone, i)));
			ldns_rr_set_owner(ldns_rr_list_rr(rrset_clone, i), 
					wildcard_name);
				  	
		}
		ldns_rr_set_ttl(
				ldns_rr_list_rr(rrset_clone, i),
				orig_ttl);
		/* convert to lowercase */
		ldns_rr2canonical(ldns_rr_list_rr(rrset_clone, i));
	}

	/* sort the rrset in canonical order  */
	ldns_rr_list_sort(rrset_clone);

	/* put the signature rr (without the b64) to the verify_buf */
	if (ldns_rrsig2buffer_wire(verify_buf, rrsig) != LDNS_STATUS_OK) {
		ldns_rr_list_deep_free(rrset_clone);
		ldns_buffer_free(rawsig_buf);
		ldns_buffer_free(verify_buf);
		return LDNS_STATUS_ERR;
	}

	/* add the rrset in verify_buf */
	if (ldns_rr_list2buffer_wire(verify_buf, rrset_clone) != LDNS_STATUS_OK) {
		ldns_rr_list_deep_free(rrset_clone);
		ldns_buffer_free(rawsig_buf);
		ldns_buffer_free(verify_buf);
		return LDNS_STATUS_ERR;
	}

	if (ldns_calc_keytag(key)
		==
		ldns_rdf2native_int16(ldns_rr_rrsig_keytag(rrsig))
	   ) {
		key_buf = ldns_buffer_new(LDNS_MAX_PACKETLEN);
		
		/* before anything, check if the keytags match */

		/* put the key-data in a buffer, that's the third rdf, with
		 * the base64 encoded key data */
		if (ldns_rdf2buffer_wire(key_buf,
				ldns_rr_rdf(key, 3)) != LDNS_STATUS_OK) {
			ldns_rr_list_deep_free(rrset_clone);
			ldns_buffer_free(rawsig_buf);
			ldns_buffer_free(verify_buf);
			/* returning is bad might screw up
			   good keys later in the list
			   what to do? */
			return LDNS_STATUS_ERR;
		}
		
		if (sig_algo == ldns_rdf2native_int8(ldns_rr_rdf(key, 2))) {
			result = ldns_verify_rrsig_buffers(rawsig_buf, verify_buf, key_buf, sig_algo);
		}
		
		ldns_buffer_free(key_buf); 
	}
	 else {
		/* No keys with the corresponding keytag are found */
		if (result == LDNS_STATUS_ERR) {
			result = LDNS_STATUS_CRYPTO_NO_MATCHING_KEYTAG_DNSKEY;
		}
	}
	/* no longer needed */
	ldns_rr_list_deep_free(rrset_clone);
	ldns_buffer_free(rawsig_buf);
	ldns_buffer_free(verify_buf);
/*
	printf("RETURNING RESULT: %s\n", ldns_get_errorstr_by_id(result));
	printf("for:\n");
	ldns_rr_list_print(stdout, rrset);
	printf("sig:\n");
	ldns_rr_print(stdout, rrsig);
	printf("key:\n");
	ldns_rr_print(stdout, key);
*/
	return result;
}

ldns_status
ldns_verify_rrsig_evp(ldns_buffer *sig, ldns_buffer *rrset, EVP_PKEY *key, const EVP_MD *digest_type)
{
	return ldns_verify_rrsig_evp_raw((unsigned char*)ldns_buffer_begin(
		sig), ldns_buffer_position(sig), rrset, key, digest_type);
}

ldns_status
ldns_verify_rrsig_evp_raw(unsigned char *sig, size_t siglen, 
	ldns_buffer *rrset, EVP_PKEY *key, const EVP_MD *digest_type)
{
	EVP_MD_CTX ctx;
	int res;

	EVP_MD_CTX_init(&ctx);
	
	EVP_VerifyInit(&ctx, digest_type);
	EVP_VerifyUpdate(&ctx, ldns_buffer_begin(rrset), ldns_buffer_position(rrset));
	res = EVP_VerifyFinal(&ctx, sig, siglen, key);
	
	EVP_MD_CTX_cleanup(&ctx);
	
	if (res == 1) {
		return LDNS_STATUS_OK;
	} else if (res == 0) {
		return LDNS_STATUS_CRYPTO_BOGUS;
	}
	/* TODO how to communicate internal SSL error? let caller use ssl's get_error() */
	return LDNS_STATUS_SSL_ERR;
}

ldns_status
ldns_verify_rrsig_dsa(ldns_buffer *sig, ldns_buffer *rrset, ldns_buffer *key)
{
	return ldns_verify_rrsig_dsa_raw((unsigned char*)ldns_buffer_begin(
		sig), ldns_buffer_position(sig), rrset, (unsigned char*)
		ldns_buffer_begin(key), ldns_buffer_position(key));
}

ldns_status
ldns_verify_rrsig_rsasha1(ldns_buffer *sig, ldns_buffer *rrset, ldns_buffer *key)
{
	return ldns_verify_rrsig_rsasha1_raw((unsigned char*)ldns_buffer_begin(
		sig), ldns_buffer_position(sig), rrset, (unsigned char*)
		ldns_buffer_begin(key), ldns_buffer_position(key));
}

ldns_status
ldns_verify_rrsig_rsamd5(ldns_buffer *sig, ldns_buffer *rrset, ldns_buffer *key)
{
	return ldns_verify_rrsig_rsamd5_raw((unsigned char*)ldns_buffer_begin(
		sig), ldns_buffer_position(sig), rrset, (unsigned char*)
		ldns_buffer_begin(key), ldns_buffer_position(key));
}

ldns_status
ldns_verify_rrsig_dsa_raw(unsigned char* sig, size_t siglen,
        ldns_buffer* rrset, unsigned char* key, size_t keylen)
{
	EVP_PKEY *evp_key;
	ldns_status result;

	evp_key = EVP_PKEY_new();
	EVP_PKEY_assign_DSA(evp_key, ldns_key_buf2dsa_raw(key, keylen));
	result = ldns_verify_rrsig_evp_raw(sig, siglen, rrset, evp_key, EVP_dss1());
	EVP_PKEY_free(evp_key);
	return result;

}

ldns_status
ldns_verify_rrsig_rsasha1_raw(unsigned char* sig, size_t siglen,
        ldns_buffer* rrset, unsigned char* key, size_t keylen)
{
	EVP_PKEY *evp_key;
	ldns_status result;

	evp_key = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(evp_key, ldns_key_buf2rsa_raw(key, keylen));
	result = ldns_verify_rrsig_evp_raw(sig, siglen, rrset, evp_key, EVP_sha1());
	EVP_PKEY_free(evp_key);

	return result;
}


ldns_status
ldns_verify_rrsig_rsamd5_raw(unsigned char* sig, size_t siglen,
        ldns_buffer* rrset, unsigned char* key, size_t keylen)
{
	EVP_PKEY *evp_key;
	ldns_status result;

	evp_key = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(evp_key, ldns_key_buf2rsa_raw(key, keylen));
	result = ldns_verify_rrsig_evp_raw(sig, siglen, rrset, evp_key, EVP_md5());
	EVP_PKEY_free(evp_key);

	return result;
}

#ifdef HAVE_SSL
DSA *
ldns_key_buf2dsa(ldns_buffer *key)
{
	return ldns_key_buf2dsa_raw((unsigned char*)ldns_buffer_begin(key),
		ldns_buffer_position(key));
}

DSA *
ldns_key_buf2dsa_raw(unsigned char* key, size_t len)
{
	uint8_t T;
	uint16_t length;
	uint16_t offset;
	DSA *dsa;
	BIGNUM *Q; BIGNUM *P;
	BIGNUM *G; BIGNUM *Y;

	if(len == 0)
		return NULL;
	T = (uint8_t)key[0];
	length = (64 + T * 8);
	offset = 1;
	
	if (T > 8) {
		return NULL;
	}
	if(len < (size_t)1 + SHA_DIGEST_LENGTH + 3*length)
		return NULL;
	
	Q = BN_bin2bn(key+offset, SHA_DIGEST_LENGTH, NULL);
	offset += SHA_DIGEST_LENGTH;
	
	P = BN_bin2bn(key+offset, (int)length, NULL);
	offset += length;
	
	G = BN_bin2bn(key+offset, (int)length, NULL);
	offset += length;
	
	Y = BN_bin2bn(key+offset, (int)length, NULL);
	offset += length;
	
	/* create the key and set its properties */
	dsa = DSA_new();
	dsa->p = P;
	dsa->q = Q;
	dsa->g = G;
	dsa->pub_key = Y;

	return dsa;
}
#endif

RSA *
ldns_key_buf2rsa(ldns_buffer *key)
{
	return ldns_key_buf2rsa_raw((unsigned char*)ldns_buffer_begin(key),
		ldns_buffer_position(key));
}

RSA *
ldns_key_buf2rsa_raw(unsigned char* key, size_t len)
{
	uint16_t offset;
	uint16_t exp;
	uint16_t int16;
	RSA *rsa;
	BIGNUM *modulus;
	BIGNUM *exponent;

	if (len == 0)
		return NULL;
	if (key[0] == 0) {
		if(len < 3)
			return NULL;
		/* need some smart comment here XXX*/
		/* the exponent is too large so it's places
		 * futher...???? */
		memmove(&int16, key+1, 2);
		exp = ntohs(int16);
		offset = 3;
	} else {
		exp = key[0];
		offset = 1;
	}

	/* key length at least one */
	if(len < (size_t)offset + exp + 1)
		return NULL;
	
	/* Exponent */
	exponent = BN_new();
	(void) BN_bin2bn(key+offset, (int)exp, exponent);
	offset += exp;

	/* Modulus */
	modulus = BN_new();
	/* length of the buffer must match the key length! */
	(void) BN_bin2bn(key+offset, (int)(len - offset), modulus);

	rsa = RSA_new();
	rsa->n = modulus;
	rsa->e = exponent;

	return rsa;
}

ldns_rr *
ldns_key_rr2ds(const ldns_rr *key, ldns_hash h)
{
	ldns_rdf *tmp;
	ldns_rr *ds;
	uint16_t keytag;
	uint8_t  sha1hash;
	uint8_t *digest;
	ldns_buffer *data_buf;

	if (ldns_rr_get_type(key) != LDNS_RR_TYPE_DNSKEY) {
		return NULL;
	}

	ds = ldns_rr_new();
	if (!ds) {
		return NULL;
	}
	ldns_rr_set_type(ds, LDNS_RR_TYPE_DS);
	ldns_rr_set_owner(ds, ldns_rdf_clone(
				ldns_rr_owner(key)));
	ldns_rr_set_ttl(ds, ldns_rr_ttl(key));
	ldns_rr_set_class(ds, ldns_rr_get_class(key));

	switch(h) {
		default:
		case LDNS_SHA1:
			digest = LDNS_XMALLOC(uint8_t, SHA_DIGEST_LENGTH);
			if (!digest) {
				ldns_rr_free(ds);
				return NULL;
			}
		break;
		case LDNS_SHA256:
			#ifdef SHA256_DIGEST_LENGTH
			digest = LDNS_XMALLOC(uint8_t, SHA256_DIGEST_LENGTH);
			if (!digest) {
				ldns_rr_free(ds);
				return NULL;
			}
			#else
			return NULL;
			#endif
		break;
	}

	data_buf = ldns_buffer_new(LDNS_MAX_PACKETLEN);
	if (!data_buf) {
		LDNS_FREE(digest);
		ldns_rr_free(ds);
		return NULL;
	}

	/* keytag */
	keytag = htons(ldns_calc_keytag((ldns_rr*)key));
	tmp = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_INT16, sizeof(uint16_t), &keytag);
	ldns_rr_push_rdf(ds, tmp);

	/* copy the algorithm field */
	ldns_rr_push_rdf(ds, ldns_rdf_clone( ldns_rr_rdf(key, 2))); /* second rfd */

	/* digest hash type */
	sha1hash = (uint8_t)h;
	tmp = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_INT8, sizeof(uint8_t), &sha1hash);
	ldns_rr_push_rdf(ds, tmp);

	/* digest */
	/* owner name */
        tmp = ldns_rdf_clone(ldns_rr_owner(key));
        ldns_dname2canonical(tmp);
	if (ldns_rdf2buffer_wire(data_buf, tmp) != LDNS_STATUS_OK) {
		LDNS_FREE(digest);
		ldns_buffer_free(data_buf);
		ldns_rr_free(ds);
		ldns_rdf_deep_free(tmp);
		return NULL;
	}
	ldns_rdf_deep_free(tmp);

	/* all the rdata's */
	if (ldns_rr_rdata2buffer_wire(data_buf, (ldns_rr*)key) != LDNS_STATUS_OK) { 
		LDNS_FREE(digest);
		ldns_buffer_free(data_buf);
		ldns_rr_free(ds);
		return NULL;
	}
	switch(h) {
		case LDNS_SHA1:
		(void) SHA1((unsigned char *) ldns_buffer_begin(data_buf),
				ldns_buffer_position(data_buf),
				(unsigned char*) digest);

		tmp = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_HEX, SHA_DIGEST_LENGTH,
				digest);
		ldns_rr_push_rdf(ds, tmp);

		break;
		case LDNS_SHA256:
#ifdef SHA256_DIGEST_LENGTH
		(void) SHA256((unsigned char *) ldns_buffer_begin(data_buf),
			    ldns_buffer_position(data_buf),
			    (unsigned char*) digest);
		tmp = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_HEX, SHA256_DIGEST_LENGTH,
				digest);
		ldns_rr_push_rdf(ds, tmp);
#endif
		break;
	}

	LDNS_FREE(digest);
	ldns_buffer_free(data_buf);
	return ds;
}

/*
 * use this function to sign with a public/private key alg
 * return the created signatures
 */
ldns_rr_list *
ldns_sign_public(ldns_rr_list *rrset, ldns_key_list *keys)
{
	ldns_rr_list *signatures;
	ldns_rr_list *rrset_clone;
	ldns_rr *current_sig;
	ldns_rdf *b64rdf;
	ldns_key *current_key;
	size_t key_count;
	uint16_t i;
	ldns_buffer *sign_buf;
	uint32_t orig_ttl;
	time_t now;
	uint8_t label_count;
	ldns_rdf *first_label;
	ldns_rdf *wildcard_label;
	ldns_rdf *new_owner;

	if (!rrset || ldns_rr_list_rr_count(rrset) < 1 || !keys) {
		return NULL;
	}

	key_count = 0;
	signatures = ldns_rr_list_new();

	/* prepare a signature and add all the know data
	 * prepare the rrset. Sign this together.  */
	rrset_clone = ldns_rr_list_clone(rrset);
	if (!rrset_clone) {
		return NULL;
	}

	/* check for label count and wildcard */
	label_count = ldns_dname_label_count(ldns_rr_owner(ldns_rr_list_rr(rrset, 0)));
	(void) ldns_str2rdf_dname(&wildcard_label, "*");
	first_label = ldns_dname_label(ldns_rr_owner(ldns_rr_list_rr(rrset, 0)), 0);
	if (ldns_rdf_compare(first_label, wildcard_label) == 0) {
		label_count--;
		for (i = 0; i < ldns_rr_list_rr_count(rrset_clone); i++) {
			new_owner = ldns_dname_cat_clone(wildcard_label, 
					ldns_dname_left_chop(ldns_rr_owner(ldns_rr_list_rr(rrset_clone, i))));
			ldns_rr_set_owner(ldns_rr_list_rr(rrset_clone, i), new_owner);
		}
	}
	ldns_rdf_deep_free(wildcard_label);
	ldns_rdf_deep_free(first_label);

	/* make it canonical */
	for(i = 0; i < ldns_rr_list_rr_count(rrset_clone); i++) {
		ldns_rr2canonical(ldns_rr_list_rr(rrset_clone, i));
	}
	/* sort */
	ldns_rr_list_sort(rrset_clone);
	
	for (key_count = 0; key_count < ldns_key_list_key_count(keys); key_count++) {
		sign_buf = ldns_buffer_new(LDNS_MAX_PACKETLEN);
		b64rdf = NULL;

		current_key = ldns_key_list_key(keys, key_count);
		/* sign all RRs with keys that have ZSKbit, !SEPbit.
		   sign DNSKEY RRs with keys that have ZSKbit&SEPbit */
		if (
			ldns_key_flags(current_key) & LDNS_KEY_ZONE_KEY &&
			(!(ldns_key_flags(current_key) & LDNS_KEY_SEP_KEY) ||
			ldns_rr_get_type(ldns_rr_list_rr(rrset, 0)) == LDNS_RR_TYPE_DNSKEY)
		   ) {
			current_sig = ldns_rr_new_frm_type(LDNS_RR_TYPE_RRSIG);
			
			/* set the type on the new signature */
			orig_ttl = ldns_rr_ttl(ldns_rr_list_rr(rrset, 0));

			ldns_rr_set_ttl(current_sig, orig_ttl);
			ldns_rr_set_owner(current_sig, 
					ldns_rdf_clone(ldns_rr_owner(ldns_rr_list_rr(rrset_clone, 0))));

			/* fill in what we know of the signature */

			/* set the orig_ttl */
			(void)ldns_rr_rrsig_set_origttl(current_sig, 
					ldns_native2rdf_int32(LDNS_RDF_TYPE_INT32, orig_ttl));
			/* the signers name */

			(void)ldns_rr_rrsig_set_signame(current_sig, 
					ldns_rdf_clone(ldns_key_pubkey_owner(current_key)));
			/* label count - get it from the first rr in the rr_list */
			(void)ldns_rr_rrsig_set_labels(current_sig, 
					ldns_native2rdf_int8(LDNS_RDF_TYPE_INT8, label_count));
			/* inception, expiration */
			now = time(NULL);
			if (ldns_key_inception(current_key) != 0) {
				(void)ldns_rr_rrsig_set_inception(current_sig,
						ldns_native2rdf_int32(LDNS_RDF_TYPE_TIME, 
							ldns_key_inception(current_key)));
			} else {
				(void)ldns_rr_rrsig_set_inception(current_sig,
						ldns_native2rdf_int32(LDNS_RDF_TYPE_TIME, now));
			}
			if (ldns_key_expiration(current_key) != 0) {
				(void)ldns_rr_rrsig_set_expiration(current_sig,
						ldns_native2rdf_int32(LDNS_RDF_TYPE_TIME, 
							ldns_key_expiration(current_key)));
			} else {
				(void)ldns_rr_rrsig_set_expiration(current_sig,
						ldns_native2rdf_int32(LDNS_RDF_TYPE_TIME, 
							now + LDNS_DEFAULT_EXP_TIME));
			}

			/* key-tag */
/*printf("SETTING KEYTAG TO: %u\n", ldns_key_keytag(current_key));*/
			(void)ldns_rr_rrsig_set_keytag(current_sig,
					ldns_native2rdf_int16(LDNS_RDF_TYPE_INT16, 
						ldns_key_keytag(current_key)));

			/* algorithm - check the key and substitute that */
			(void)ldns_rr_rrsig_set_algorithm(current_sig,
					ldns_native2rdf_int8(LDNS_RDF_TYPE_ALG, 
						ldns_key_algorithm(current_key)));
			/* type-covered */
			(void)ldns_rr_rrsig_set_typecovered(current_sig,
					ldns_native2rdf_int16(LDNS_RDF_TYPE_TYPE,
						ldns_rr_get_type(ldns_rr_list_rr(rrset_clone, 0))));
			/* right now, we have: a key, a semi-sig and an rrset. For
			 * which we can create the sig and base64 encode that and
			 * add that to the signature */
			
			if (ldns_rrsig2buffer_wire(sign_buf, current_sig) != LDNS_STATUS_OK) {
				ldns_buffer_free(sign_buf);
				/* ERROR */
				ldns_rr_list_deep_free(rrset_clone);
				return NULL;
			}
			/* add the rrset in sign_buf */

			if (ldns_rr_list2buffer_wire(sign_buf, rrset_clone) != LDNS_STATUS_OK) {
				ldns_buffer_free(sign_buf);
				ldns_rr_list_deep_free(rrset_clone);
				return NULL;
			}
			
			switch(ldns_key_algorithm(current_key)) {
				case LDNS_SIGN_DSA:
				case LDNS_DSA_NSEC3:
					b64rdf = ldns_sign_public_evp(sign_buf, ldns_key_evp_key(current_key), EVP_dss1());
/*					b64rdf = ldns_sign_public_dsa(sign_buf, ldns_key_dsa_key(current_key));*/
					break;
				case LDNS_SIGN_RSASHA1:
				case LDNS_RSASHA1_NSEC3:
					b64rdf = ldns_sign_public_evp(sign_buf, ldns_key_evp_key(current_key), EVP_sha1());
/*					b64rdf = ldns_sign_public_rsasha1(sign_buf, ldns_key_rsa_key(current_key));*/
					break;
				case LDNS_SIGN_RSAMD5:
					b64rdf = ldns_sign_public_evp(sign_buf, ldns_key_evp_key(current_key), EVP_md5());
					break;
				default:
					/* do _you_ know this alg? */
					printf("unknown alg\n");
					break;
			}
			if (!b64rdf) {
				/* signing went wrong */
				ldns_rr_list_deep_free(rrset_clone);
				return NULL;
			}
			ldns_rr_rrsig_set_sig(current_sig, b64rdf);

			/* push the signature to the signatures list */
			ldns_rr_list_push_rr(signatures, current_sig);
		}
		ldns_buffer_free(sign_buf); /* restart for the next key */
	}
	ldns_rr_list_deep_free(rrset_clone);

	return signatures;
}

ldns_rdf *
ldns_sign_public_dsa(ldns_buffer *to_sign, DSA *key)
{
	unsigned char *sha1_hash;
	ldns_rdf *sigdata_rdf;
	ldns_buffer *b64sig;

	DSA_SIG *sig;
	uint8_t *data;
	size_t pad;

	b64sig = ldns_buffer_new(LDNS_MAX_PACKETLEN);
	if (!b64sig) {
		return NULL;
	}
	
	sha1_hash = SHA1((unsigned char*)ldns_buffer_begin(to_sign),
			ldns_buffer_position(to_sign), NULL);
	if (!sha1_hash) {
		ldns_buffer_free(b64sig);
		return NULL;
	}


	sig = DSA_do_sign(sha1_hash, SHA_DIGEST_LENGTH, key);

	data = LDNS_XMALLOC(uint8_t, 1 + 2 * SHA_DIGEST_LENGTH);

	data[0] = 1;
	pad = 20 - (size_t) BN_num_bytes(sig->r);
	if (pad > 0) {
		memset(data + 1, 0, pad);
	}
	BN_bn2bin(sig->r, (unsigned char *) (data + 1) + pad);

	pad = 20 - (size_t) BN_num_bytes(sig->s);
	if (pad > 0) {
		memset(data + 1 + SHA_DIGEST_LENGTH, 0, pad);
	}
	BN_bn2bin(sig->s, (unsigned char *) (data + 1 + SHA_DIGEST_LENGTH + pad));

	sigdata_rdf = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_B64,  1 + 2 * SHA_DIGEST_LENGTH, data);

	ldns_buffer_free(b64sig);
	LDNS_FREE(data);

	return sigdata_rdf;
}

ldns_rdf *
ldns_sign_public_evp(ldns_buffer *to_sign, EVP_PKEY *key, const EVP_MD *digest_type)
{
	unsigned int siglen;
	ldns_rdf *sigdata_rdf;
	ldns_buffer *b64sig;
	EVP_MD_CTX ctx;
	const EVP_MD *md_type;
	int r;

	siglen = 0;
	b64sig = ldns_buffer_new(LDNS_MAX_PACKETLEN);
	if (!b64sig) {
		return NULL;
	}

	/* initializes a signing context */
	md_type = digest_type;
	if(!md_type) {
		printf("Unknown message digest");
		exit(1);
	}

	EVP_MD_CTX_init(&ctx);
	r = EVP_SignInit(&ctx, md_type);
	if(r == 1)
		r = EVP_SignUpdate(&ctx, (unsigned char*)
			ldns_buffer_begin(to_sign), 
			ldns_buffer_position(to_sign));
	if(r == 1)
		r = EVP_SignFinal(&ctx, (unsigned char*)
			ldns_buffer_begin(b64sig), &siglen, key);
	if(r != 1) {
		ldns_buffer_free(b64sig);
		return NULL;
	}

	sigdata_rdf = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_B64, siglen,
			ldns_buffer_begin(b64sig));
	ldns_buffer_free(b64sig);
	EVP_MD_CTX_cleanup(&ctx);
	return sigdata_rdf;
}


ldns_rdf *
ldns_sign_public_rsasha1(ldns_buffer *to_sign, RSA *key)
{
	unsigned char *sha1_hash;
	unsigned int siglen;
	ldns_rdf *sigdata_rdf;
	ldns_buffer *b64sig;

	siglen = 0;
	b64sig = ldns_buffer_new(LDNS_MAX_PACKETLEN);
	if (!b64sig) {
		return NULL;
	}

	sha1_hash = SHA1((unsigned char*)ldns_buffer_begin(to_sign),
			ldns_buffer_position(to_sign), NULL);
	if (!sha1_hash) {
		ldns_buffer_free(b64sig);
		return NULL;
	}

	RSA_sign(NID_sha1, sha1_hash, SHA_DIGEST_LENGTH,
			(unsigned char*)ldns_buffer_begin(b64sig),
			&siglen, key);
	sigdata_rdf = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_B64, siglen, 
			ldns_buffer_begin(b64sig));
	ldns_buffer_free(b64sig); /* can't free this buffer ?? */
	return sigdata_rdf;
}

ldns_rdf *
ldns_sign_public_rsamd5(ldns_buffer *to_sign, RSA *key)
{
	unsigned char *md5_hash;
	unsigned int siglen;
	ldns_rdf *sigdata_rdf;
	ldns_buffer *b64sig;

	b64sig = ldns_buffer_new(LDNS_MAX_PACKETLEN);
	if (!b64sig) {
		return NULL;
	}
	
	md5_hash = MD5((unsigned char*)ldns_buffer_begin(to_sign),
			ldns_buffer_position(to_sign), NULL);
	if (!md5_hash) {
		ldns_buffer_free(b64sig);
		return NULL;
	}

	RSA_sign(NID_md5, md5_hash, MD5_DIGEST_LENGTH,
			(unsigned char*)ldns_buffer_begin(b64sig),
			&siglen, key);

	sigdata_rdf = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_B64, siglen, 
			ldns_buffer_begin(b64sig));
	ldns_buffer_free(b64sig);
	return sigdata_rdf;
}

ldns_rr *
ldns_create_nsec(ldns_rdf *cur_owner, ldns_rdf *next_owner, ldns_rr_list *rrs)
{
	/* we do not do any check here - garbage in, garbage out */
	
	/* the the start and end names - get the type from the
	 * before rrlist */

	/* we don't have an nsec encoder... :( */

	/* inefficient, just give it a name, a next name, and a list of rrs */
	/* we make 1 big uberbitmap first, then windows */
	/* todo: make something more efficient :) */
	uint16_t i;
	ldns_rr *i_rr;

	uint8_t *bitmap = LDNS_XMALLOC(uint8_t, 2);
	uint16_t bm_len = 0;
	uint16_t i_type;

	ldns_rr *nsec = NULL;

	uint8_t *data = NULL;
	uint8_t cur_data[32];
	uint8_t cur_window = 0;
	uint8_t cur_window_max = 0;
	uint16_t cur_data_size = 0;

	nsec = ldns_rr_new();
	ldns_rr_set_type(nsec, LDNS_RR_TYPE_NSEC);
	ldns_rr_set_owner(nsec, ldns_rdf_clone(cur_owner));
	/* TODO: TTL jelte? */
	ldns_rr_push_rdf(nsec, ldns_rdf_clone(next_owner));

	bitmap[0] = 0;
	for (i = 0; i < ldns_rr_list_rr_count(rrs); i++) {
		i_rr = ldns_rr_list_rr(rrs, i);

		if (ldns_rdf_compare(cur_owner,
					 ldns_rr_owner(i_rr)) == 0) {
			/* add type to bitmap */
			i_type = ldns_rr_get_type(i_rr);
			if ((i_type / 8) + 1 > bm_len) {
				bitmap = LDNS_XREALLOC(bitmap, uint8_t, (i_type / 8) + 2);
				/* set to 0 */
				for (; bm_len <= i_type / 8; bm_len++) {
					bitmap[bm_len] = 0;
				}
			}
			ldns_set_bit(bitmap + (int) i_type / 8, (int) (7 - (i_type % 8)), true);
		}
	}
	/* add NSEC and RRSIG anyway */
	i_type = LDNS_RR_TYPE_RRSIG;
	if (i_type / 8 > bm_len) {
		bitmap = LDNS_XREALLOC(bitmap, uint8_t, (i_type / 8) + 2);
		/* set to 0 */
		for (; bm_len <= i_type / 8; bm_len++) {
			bitmap[bm_len] = 0;
		}
	}
	ldns_set_bit(bitmap + (int) i_type / 8, (int) (7 - (i_type % 8)), true);
	i_type = LDNS_RR_TYPE_NSEC;

	if (i_type / 8 > bm_len) {
		bitmap = LDNS_XREALLOC(bitmap, uint8_t, (i_type / 8) + 2);
		/* set to 0 */
		for (; bm_len <= i_type / 8; bm_len++) {
			bitmap[bm_len] = 0;
		}
	}
	ldns_set_bit(bitmap + (int) i_type / 8, (int) (7 - (i_type % 8)), true);

	memset(cur_data, 0, 32);
	for (i = 0; i < bm_len; i++) {
		if (i / 32 > cur_window) {
			/* check, copy, new */
			if (cur_window_max > 0) {
				/* this window has stuff, add it */
				data = LDNS_XREALLOC(data, uint8_t, cur_data_size + cur_window_max + 3);
				data[cur_data_size] = cur_window;
				data[cur_data_size + 1] = cur_window_max + 1;
				memcpy(data + cur_data_size + 2, cur_data, cur_window_max+1);
				cur_data_size += cur_window_max + 3;
			}
			cur_window++;
			cur_window_max = 0;
			memset(cur_data, 0, 32);
		} else {
			cur_data[i%32] = bitmap[i];
			if (bitmap[i] > 0) {
				cur_window_max = i%32;
			}
		}
	}
	if (cur_window_max > 0) {
		/* this window has stuff, add it */
		data = LDNS_XREALLOC(data, uint8_t, cur_data_size + cur_window_max + 3);
		data[cur_data_size] = cur_window;
		data[cur_data_size + 1] = cur_window_max + 1;
		memcpy(data + cur_data_size + 2, cur_data, cur_window_max+1);
		cur_data_size += cur_window_max + 3;
	}

	ldns_rr_push_rdf(nsec, ldns_rdf_new_frm_data(LDNS_RDF_TYPE_NSEC, cur_data_size, data));

	LDNS_FREE(bitmap);
	LDNS_FREE(data);
	return nsec;
}

ldns_rdf *
ldns_nsec3_hash_name(ldns_rdf *name, uint8_t algorithm, uint16_t iterations, uint8_t salt_length, uint8_t *salt)
{
	char *orig_owner_str;
	size_t hashed_owner_str_len;
	ldns_rdf *hashed_owner;
	char *hashed_owner_str;
	char *hashed_owner_b32;
	int hashed_owner_b32_len;
	uint32_t cur_it;
	char *hash = NULL;
	ldns_status status;
	
	/* prepare the owner name according to the draft section bla */
	orig_owner_str = ldns_rdf2str(name);
	
	/* TODO: mnemonic list for hash algs SHA-1, default to 1 now (sha1) */
	algorithm = algorithm;
	
	hashed_owner_str_len = salt_length + ldns_rdf_size(name);
	hashed_owner_str = LDNS_XMALLOC(char, hashed_owner_str_len);
        memcpy(hashed_owner_str, ldns_rdf_data(name), ldns_rdf_size(name));
	memcpy(hashed_owner_str + ldns_rdf_size(name), salt, salt_length);

	for (cur_it = iterations + 1; cur_it > 0; cur_it--) {
		/*xprintf_hex(hashed_owner_str, hashed_owner_str_len);*/
		hash = (char *) SHA1((unsigned char *) hashed_owner_str, hashed_owner_str_len, NULL);

		LDNS_FREE(hashed_owner_str);
		hashed_owner_str_len = salt_length + SHA_DIGEST_LENGTH;
		hashed_owner_str = LDNS_XMALLOC(char, hashed_owner_str_len);
		if (!hashed_owner_str) {
			fprintf(stderr, "Memory error\n");
			abort();
		}
		memcpy(hashed_owner_str, hash, SHA_DIGEST_LENGTH);
		memcpy(hashed_owner_str + SHA_DIGEST_LENGTH, salt, salt_length);
		hashed_owner_str_len = SHA_DIGEST_LENGTH + salt_length;
	}

	LDNS_FREE(orig_owner_str);
	LDNS_FREE(hashed_owner_str);
	hashed_owner_str = hash;
	hashed_owner_str_len = SHA_DIGEST_LENGTH;

	hashed_owner_b32 = LDNS_XMALLOC(char, b32_ntop_calculate_size(hashed_owner_str_len) + 1);
	hashed_owner_b32_len = (size_t) b32_ntop_extended_hex((uint8_t *) hashed_owner_str, hashed_owner_str_len, hashed_owner_b32, b32_ntop_calculate_size(hashed_owner_str_len));
	if (hashed_owner_b32_len < 1) {
		fprintf(stderr, "Error in base32 extended hex encoding of hashed owner name (name: ");
		ldns_rdf_print(stderr, name);
		fprintf(stderr, ", return code: %d)\n", hashed_owner_b32_len);
		exit(4);
	}
	hashed_owner_str_len = hashed_owner_b32_len;
        hashed_owner_b32[hashed_owner_b32_len] = '\0';

	status = ldns_str2rdf_dname(&hashed_owner, hashed_owner_b32);
	if (status != LDNS_STATUS_OK) {
		fprintf(stderr, "Error creating rdf from %s\n", hashed_owner_b32);
		exit(1);
	}

	LDNS_FREE(hashed_owner_b32);
	return hashed_owner;
}

void
ldns_nsec3_add_param_rdfs(ldns_rr *rr,
                           uint8_t algorithm, 
                           uint8_t flags,
                           uint16_t iterations,
                           uint8_t salt_length,
                           uint8_t *salt)
{
	ldns_rdf *salt_rdf = NULL;
	uint8_t *salt_data = NULL;
	
	ldns_rr_set_rdf(rr, ldns_rdf_new_frm_data(LDNS_RDF_TYPE_INT8, 1, (void*)&algorithm), 0);
	ldns_rr_set_rdf(rr, ldns_rdf_new_frm_data(LDNS_RDF_TYPE_INT8, 1, (void*)&flags), 1);
	ldns_rr_set_rdf(rr, ldns_native2rdf_int16(LDNS_RDF_TYPE_INT16, iterations), 2);
	
	salt_data = LDNS_XMALLOC(uint8_t, salt_length + 1);
	salt_data[0] = salt_length;
	memcpy(salt_data + 1, salt, salt_length);
	salt_rdf = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_NSEC3_SALT, salt_length + 1, salt_data);
	ldns_rr_set_rdf(rr,  salt_rdf, 3);

	ldns_rr_set_rdf(rr, salt_rdf, 3);
}

/* this will NOT return the NSEC3  completed, you will have to run the
   finalize function on the rrlist later! */
ldns_rr *
ldns_create_nsec3(ldns_rdf *cur_owner,
                  ldns_rdf *cur_zone,
                  ldns_rr_list *rrs,
                  uint8_t algorithm,
                  uint8_t flags,
                  uint16_t iterations,
                  uint8_t salt_length,
                  uint8_t *salt,
                  bool emptynonterminal)
{
	size_t i;
	ldns_rr *i_rr;

	uint8_t *bitmap = LDNS_XMALLOC(uint8_t, 1);
	uint16_t bm_len = 0;
	uint16_t i_type;

	ldns_rr *nsec = NULL;
	ldns_rdf *hashed_owner = NULL;
	
	uint8_t *data = NULL;
	uint8_t cur_data[32];
	uint8_t cur_window = 0;
	uint8_t cur_window_max = 0;
	uint16_t cur_data_size = 0;

	ldns_status status;
	
        /*
        printf("HASH FOR: ");
        ldns_rdf_print(stdout, cur_owner);
        */
	
	/*
	printf("\n");
	for (i=0; i<hashed_owner_str_len; i++) {
		printf("%02x ", (uint8_t) hashed_owner_str[i]);
	}
	printf("\n");
	*/
	hashed_owner = ldns_nsec3_hash_name(cur_owner, algorithm, iterations, salt_length, salt);
	status = ldns_dname_cat(hashed_owner, cur_zone);
	
	nsec = ldns_rr_new_frm_type(LDNS_RR_TYPE_NSEC3);
	ldns_rr_set_type(nsec, LDNS_RR_TYPE_NSEC3);
	ldns_rr_set_owner(nsec, hashed_owner);
	/* TODO: TTL? */
	
	ldns_nsec3_add_param_rdfs(nsec, algorithm, flags, iterations, salt_length, salt);
	ldns_rr_set_rdf(nsec, NULL, 4);

	bitmap[0] = 0;
	for (i = 0; i < ldns_rr_list_rr_count(rrs); i++) {
		i_rr = ldns_rr_list_rr(rrs, i);

		if (ldns_rdf_compare(cur_owner,
		                     ldns_rr_owner(i_rr)) == 0) {
			/* add type to bitmap */
			i_type = ldns_rr_get_type(i_rr);
			if ((i_type / 8) + 1 > bm_len) {
				bitmap = LDNS_XREALLOC(bitmap, uint8_t, (i_type / 8) + 1);
				/* set to 0 */
				for (; bm_len <= i_type / 8; bm_len++) {
					bitmap[bm_len] = 0;
				}
			}
			ldns_set_bit(bitmap + (int) i_type / 8, (int) (7 - (i_type % 8)), true);
		}
	}
	/* add NSEC and RRSIG anyway */
	if (!emptynonterminal) {
		i_type = LDNS_RR_TYPE_RRSIG;
		if (i_type / 8 > bm_len) {
			bitmap = LDNS_XREALLOC(bitmap, uint8_t, (i_type / 8) + 1);
			/* set to 0 */
			for (; bm_len <= i_type / 8; bm_len++) {
				bitmap[bm_len] = 0;
			}
		}
		ldns_set_bit(bitmap + (int) i_type / 8, (int) (7 - (i_type % 8)), true);
	}

	/* and SOA if owner == zone */
	if (ldns_dname_compare(cur_zone, cur_owner) == 0) {
		i_type = LDNS_RR_TYPE_SOA;
		if (i_type / 8 > bm_len) {
			bitmap = LDNS_XREALLOC(bitmap, uint8_t, (i_type / 8) + 1);
			/* set to 0 */
			for (; bm_len <= i_type / 8; bm_len++) {
				bitmap[bm_len] = 0;
			}
		}
		ldns_set_bit(bitmap + (int) i_type / 8, (int) (7 - (i_type % 8)), true);
	}

	memset(cur_data, 0, 32);
	for (i = 0; i < bm_len; i++) {
		if (i / 32 > cur_window) {
			/* check, copy, new */
			if (cur_window_max > 0) {
				/* this window has stuff, add it */
				data = LDNS_XREALLOC(data, uint8_t, cur_data_size + cur_window_max + 3);
				data[cur_data_size] = cur_window;
				data[cur_data_size + 1] = cur_window_max + 1;
				memcpy(data + cur_data_size + 2, cur_data, cur_window_max+1);
				cur_data_size += cur_window_max + 3;
			}
			cur_window++;
			cur_window_max = 0;
			memset(cur_data, 0, 32);
		} else {
			cur_data[i%32] = bitmap[i];
			if (bitmap[i] > 0) {
				cur_window_max = i%32;
			}
		}
	}
	if (cur_window_max > 0) {
		/* this window has stuff, add it */
		data = LDNS_XREALLOC(data, uint8_t, cur_data_size + cur_window_max + 3);
		data[cur_data_size] = cur_window;
		data[cur_data_size + 1] = cur_window_max + 1;
		memcpy(data + cur_data_size + 2, cur_data, cur_window_max+1);
		cur_data_size += cur_window_max + 3;
	}

	ldns_rr_set_rdf(nsec, ldns_rdf_new_frm_data(LDNS_RDF_TYPE_NSEC, cur_data_size, data), 5);

	LDNS_FREE(bitmap);
	LDNS_FREE(data);

/*
printf(";; Created NSEC3 for:\n");
printf(";; ");
ldns_rdf_print(stdout, cur_owner);
printf("\n");
printf(";; ");
ldns_rr_print(stdout, nsec);
*/
	return nsec;
}

uint8_t
ldns_nsec3_algorithm(const ldns_rr *nsec3_rr)
{
	if (nsec3_rr && ldns_rr_get_type(nsec3_rr) == LDNS_RR_TYPE_NSEC3 &&
	    ldns_rdf_size(ldns_rr_rdf(nsec3_rr, 0)) > 0
	   ) {
		/*return ldns_rdf_data(ldns_rr_rdf(nsec3_rr, 0))[0];*/
		return ldns_rdf2native_int8(ldns_rr_rdf(nsec3_rr, 0));
	}
	return 0;
}

uint8_t
ldns_nsec3_flags(const ldns_rr *nsec3_rr)
{
	if (nsec3_rr && ldns_rr_get_type(nsec3_rr) == LDNS_RR_TYPE_NSEC3 &&
	    ldns_rdf_size(ldns_rr_rdf(nsec3_rr, 1)) > 0
	   ) {
		/*return ldns_rdf_data(ldns_rr_rdf(nsec3_rr, 0))[0];*/
		return ldns_rdf2native_int8(ldns_rr_rdf(nsec3_rr, 0));
	}
	return 0;
}

bool
ldns_nsec3_optout(const ldns_rr *nsec3_rr)
{
	return (ldns_nsec3_flags(nsec3_rr) & LDNS_NSEC3_VARS_OPTOUT_MASK);
}

uint16_t
ldns_nsec3_iterations(const ldns_rr *nsec3_rr)
{
	if (nsec3_rr && ldns_rr_get_type(nsec3_rr) == LDNS_RR_TYPE_NSEC3 &&
	    ldns_rdf_size(ldns_rr_rdf(nsec3_rr, 2)) > 0
	   ) {
		return ldns_rdf2native_int16(ldns_rr_rdf(nsec3_rr, 2));
	}
	return 0;
	
}

ldns_rdf
*ldns_nsec3_salt(const ldns_rr *nsec3_rr)
{
	if (nsec3_rr && ldns_rr_get_type(nsec3_rr) == LDNS_RR_TYPE_NSEC3) {
		return ldns_rr_rdf(nsec3_rr, 3);
	}
	return NULL;
}

uint8_t
ldns_nsec3_salt_length(const ldns_rr *nsec3_rr)
{
	ldns_rdf *salt_rdf = ldns_nsec3_salt(nsec3_rr);
	if (salt_rdf && ldns_rdf_size(salt_rdf) > 0) {
		return (uint8_t) ldns_rdf_data(salt_rdf)[0];
	}
	return 0;
}

/* allocs data, free with LDNS_FREE() */
uint8_t *
ldns_nsec3_salt_data(const ldns_rr *nsec3_rr)
{
	uint8_t salt_length;
	uint8_t *salt;

	ldns_rdf *salt_rdf = ldns_nsec3_salt(nsec3_rr);
	if (salt_rdf && ldns_rdf_size(salt_rdf) > 0) {
	    	salt_length = ldns_rdf_data(salt_rdf)[0];
		salt = LDNS_XMALLOC(uint8_t, salt_length);
		memcpy(salt, &ldns_rdf_data(salt_rdf)[1], salt_length);
		return salt;
	}
	return NULL;
}

ldns_rdf *
ldns_nsec3_next_owner(const ldns_rr *nsec3_rr)
{
	if (!nsec3_rr || ldns_rr_get_type(nsec3_rr) != LDNS_RR_TYPE_NSEC3) {
		return NULL;
	} else {
		return ldns_rr_rdf(nsec3_rr, 4);
	}
}

ldns_rdf *
ldns_nsec3_bitmap(const ldns_rr *nsec3_rr)
{
	if (!nsec3_rr || ldns_rr_get_type(nsec3_rr) != LDNS_RR_TYPE_NSEC3) {
		return NULL;
	} else {
		return ldns_rr_rdf(nsec3_rr, 5);
	}
}

ldns_rdf *
ldns_nsec3_hash_name_frm_nsec3(const ldns_rr *nsec, ldns_rdf *name)
{
	uint8_t algorithm;
	uint16_t iterations;
/*	uint8_t *data;*/
	uint8_t salt_length;
	uint8_t *salt = 0;
/*uint8_t salt_i;*/
	
	ldns_rdf *hashed_owner;

/*
printf("NSEC RDF: ");
ldns_rdf_print(stdout, ldns_rr_rdf(nsec, 0));
printf("\n\n");
*/
	algorithm = ldns_nsec3_algorithm(nsec);
	salt_length = ldns_nsec3_salt_length(nsec);
	salt = ldns_nsec3_salt_data(nsec);
	iterations = ldns_nsec3_iterations(nsec);
	
	hashed_owner = ldns_nsec3_hash_name(name, algorithm, iterations, salt_length, salt);
	
/*
printf(";; Iterations: %u, Salt: ", iterations);
for (salt_i = 0; salt_i < salt_length; salt_i++) {
	printf("%02x", salt[salt_i]);
}
printf("\n");
*/
	LDNS_FREE(salt);
	return hashed_owner;
}

bool
ldns_nsec_bitmap_covers_type(const ldns_rdf *nsec_bitmap, ldns_rr_type type)
{
	uint8_t window_block_nr;
	uint8_t bitmap_length;
	uint16_t cur_type;
	uint16_t pos = 0;
	uint16_t bit_pos;
	uint8_t *data = ldns_rdf_data(nsec_bitmap);
	
	while(pos < ldns_rdf_size(nsec_bitmap)) {
		window_block_nr = data[pos];
		bitmap_length = data[pos + 1];
		pos += 2;
		
		for (bit_pos = 0; bit_pos < (bitmap_length) * 8; bit_pos++) {
			if (ldns_get_bit(&data[pos], bit_pos)) {
				cur_type = 256 * (uint16_t) window_block_nr + bit_pos;
				if (cur_type == type) {
					return true;
				}
			}
		}
		
		pos += (uint16_t) bitmap_length;
	}
	return false;
}

bool
ldns_nsec_covers_name(const ldns_rr *nsec, const ldns_rdf *name)
{
	ldns_rdf *nsec_owner = ldns_rr_owner(nsec);
	ldns_rdf *hash_next;
	char *next_hash_str;
	ldns_rdf *nsec_next = NULL;
	ldns_status status;
	ldns_rdf *chopped_dname;
	bool result;
	
	if (ldns_rr_get_type(nsec) == LDNS_RR_TYPE_NSEC) {
		nsec_next = ldns_rdf_clone(ldns_rr_rdf(nsec, 0));
	} else if (ldns_rr_get_type(nsec) == LDNS_RR_TYPE_NSEC3) {
		hash_next = ldns_nsec3_next_owner(nsec);
		next_hash_str = ldns_rdf2str(hash_next);
		nsec_next = ldns_dname_new_frm_str(next_hash_str);
		LDNS_FREE(next_hash_str);
		chopped_dname = ldns_dname_left_chop(nsec_owner);
		status = ldns_dname_cat(nsec_next, chopped_dname);
		ldns_rdf_deep_free(chopped_dname);
		if (status != LDNS_STATUS_OK) {
			printf("error catting: %s\n", ldns_get_errorstr_by_id(status));
		}
	} else {
		ldns_rdf_deep_free(nsec_next);
		return false;
	}
	
/*
printf("nsec coverage:\n");
ldns_rdf_print(stdout, nsec_owner);
printf(" <= \n");
ldns_rdf_print(stdout, name);
printf(" <  \n");
ldns_rdf_print(stdout, nsec_next);
printf("\n\n");
*/
	/* in the case of the last nsec */
	if(ldns_dname_compare(nsec_owner, nsec_next) > 0) {
		result = (ldns_dname_compare(nsec_owner, name) <= 0 ||
			  ldns_dname_compare(name, nsec_next) < 0);
	} else {
		result = (ldns_dname_compare(nsec_owner, name) <= 0 &&
		          ldns_dname_compare(name, nsec_next) < 0);
	}
	
	ldns_rdf_deep_free(nsec_next);
	return result;
}

/* sig may be null - if so look in the packet */
ldns_status
ldns_pkt_verify(ldns_pkt *p, ldns_rr_type t, ldns_rdf *o, 
		ldns_rr_list *k, ldns_rr_list *s, ldns_rr_list *good_keys)
{
	ldns_rr_list *rrset;
	ldns_rr_list *sigs;
	ldns_rr_list *sigs_covered;
	ldns_rdf *rdf_t;
	ldns_rr_type t_netorder;

	if (!k) {
		return LDNS_STATUS_ERR;
		/* return LDNS_STATUS_CRYPTO_NO_DNSKEY; */
	}

	if (t == LDNS_RR_TYPE_RRSIG) {
		/* we don't have RRSIG(RRSIG) (yet? ;-) ) */
		/* return LDNS_STATUS_ERR; */
		return LDNS_STATUS_ERR;
	}
	
	if (s) {
		/* if s is not NULL, the sigs are given to use */
		sigs = s;
	} else {
		/* otherwise get them from the packet */
		sigs = ldns_pkt_rr_list_by_name_and_type(p, o, LDNS_RR_TYPE_RRSIG, 
				LDNS_SECTION_ANY_NOQUESTION);
		if (!sigs) {
			/* no sigs */
			return LDNS_STATUS_ERR;
			/* return LDNS_STATUS_CRYPTO_NO_RRSIG; */
		}
	}

	/* *sigh* rrsig are subtyped, so now we need to find the correct
	 * sigs for the type t
	 */
	t_netorder = htons(t); /* rdf are in network order! */
	rdf_t = ldns_rdf_new(LDNS_RDF_TYPE_TYPE, sizeof(ldns_rr_type), &t_netorder);
	sigs_covered = ldns_rr_list_subtype_by_rdf(sigs, rdf_t, 0);
	
	rrset = ldns_pkt_rr_list_by_name_and_type(p, o, t, LDNS_SECTION_ANY_NOQUESTION);

	if (!rrset) {
		return LDNS_STATUS_ERR;
	}

	if (!sigs_covered) {
		return LDNS_STATUS_ERR;
	}

	return ldns_verify(rrset, sigs, k, good_keys);
}

ldns_zone *
ldns_zone_sign(const ldns_zone *zone, ldns_key_list *key_list)
{
	/*
	 * Algorithm to be created:
	 * - sort the rrs (name/class/type?)
	 * - if sorted, every next rr is belongs either to the rrset
	 * you are working on, or the rrset is complete
	 * for each rrset, calculate rrsig and nsec
	 * put the rrset, rrsig and nsec in the new zone
	 * done!
	 * ow and don't sign old rrsigs etc.
	 */
	
	ldns_zone *signed_zone;
	ldns_rr_list *cur_rrset;
	ldns_rr_list *cur_rrsigs;
	ldns_rr_list *orig_zone_rrs;
	ldns_rr_list *signed_zone_rrs;
	ldns_rr_list *pubkeys;
	ldns_rr_list *glue_rrs;
	
	ldns_rdf *start_dname = NULL;
	ldns_rdf *cur_dname = NULL;
	ldns_rr *next_rr = NULL;
	ldns_rdf *next_dname = NULL;
	ldns_rr *nsec;
	ldns_rr *ckey;
	uint16_t i;
	ldns_rr_type cur_rrset_type;
	
	signed_zone = ldns_zone_new();

	/* there should only be 1 SOA, so the soa record is 1 rrset */
	cur_rrsigs = NULL;
	ldns_zone_set_soa(signed_zone, ldns_rr_clone(ldns_zone_soa(zone)));
	ldns_rr2canonical(ldns_zone_soa(signed_zone));
	
	orig_zone_rrs = ldns_rr_list_clone(ldns_zone_rrs(zone));

	ldns_rr_list_push_rr(orig_zone_rrs, ldns_rr_clone(ldns_zone_soa(zone)));
	
	/* canon now, needed for correct nsec creation */
        for (i = 0; i < ldns_rr_list_rr_count(orig_zone_rrs); i++) {
		ldns_rr2canonical(ldns_rr_list_rr(orig_zone_rrs, i));
	}
	glue_rrs = ldns_zone_glue_rr_list(zone);

	/* add the key (TODO: check if it's there already? */
	pubkeys = ldns_rr_list_new();
	for (i = 0; i < ldns_key_list_key_count(key_list); i++) {
		ckey = ldns_key2rr(ldns_key_list_key(key_list, i));
		ldns_rr_list_push_rr(pubkeys, ckey);
	}

	signed_zone_rrs = ldns_rr_list_new();
	
	ldns_rr_list_sort(orig_zone_rrs);
	
	/* add nsecs */
	for (i = 0; i < ldns_rr_list_rr_count(orig_zone_rrs); i++) {
		if (!start_dname) {
			/*start_dname = ldns_rr_owner(ldns_zone_soa(zone));*/
			start_dname = ldns_rr_owner(ldns_rr_list_rr(orig_zone_rrs, i));
			cur_dname = start_dname;
		} else {
			next_rr = ldns_rr_list_rr(orig_zone_rrs, i);
			next_dname = ldns_rr_owner(next_rr);
			if (ldns_rdf_compare(cur_dname, next_dname) != 0) {
				/* skip glue */
				if (ldns_rr_list_contains_rr(glue_rrs, next_rr)) {
					cur_dname = next_dname;
				} else {
					nsec = ldns_create_nsec(cur_dname, 
								next_dname,
								orig_zone_rrs);
					ldns_rr_set_ttl(nsec, ldns_rdf2native_int32(ldns_rr_rdf(ldns_zone_soa(zone), 6)));
					ldns_rr_list_push_rr(signed_zone_rrs, nsec);
					/*start_dname = next_dname;*/
					cur_dname = next_dname;
				}
			}
		}
		ldns_rr_list_push_rr(signed_zone_rrs, ldns_rr_list_rr(orig_zone_rrs, i));
	}
	nsec = ldns_create_nsec(cur_dname, 
				start_dname,
				orig_zone_rrs);
	ldns_rr_list_push_rr(signed_zone_rrs, nsec);
	ldns_rr_list_free(orig_zone_rrs);
	ldns_rr_set_ttl(nsec, ldns_rdf2native_int32(ldns_rr_rdf(ldns_zone_soa(zone), 6)));

	/* Sign all rrsets in the zone */
	cur_rrset = ldns_rr_list_pop_rrset(signed_zone_rrs);
	while (cur_rrset) {
		/* don't sign certain types */
		cur_rrset_type = ldns_rr_get_type(ldns_rr_list_rr(cur_rrset, 0));
		cur_dname = ldns_rr_owner(ldns_rr_list_rr(cur_rrset, 0));

		/* if we have KSKs, use them for DNSKEYS, otherwise
		   make them selfsigned (?) */
                /* don't sign sigs, delegations, and glue */
		if (cur_rrset_type != LDNS_RR_TYPE_RRSIG &&
		    ((ldns_dname_is_subdomain(cur_dname, ldns_rr_owner(ldns_zone_soa(signed_zone)))
                      && cur_rrset_type != LDNS_RR_TYPE_NS
                     ) ||
		     ldns_rdf_compare(cur_dname, ldns_rr_owner(ldns_zone_soa(signed_zone))) == 0
		    ) &&
		    !(ldns_rr_list_contains_rr(glue_rrs, ldns_rr_list_rr(cur_rrset, 0)))
		   ) {
			cur_rrsigs = ldns_sign_public(cur_rrset, key_list);

			/* TODO: make optional, replace exit call */
			/* if not optional it should be left out completely
			   (for it is possible to generate bad signarures, by
			   specifying a future inception date */
			
			ldns_zone_push_rr_list(signed_zone, cur_rrset);
			ldns_zone_push_rr_list(signed_zone, cur_rrsigs);
			ldns_rr_list_free(cur_rrsigs);
		} else {
			/* push it unsigned (glue, sigs, delegations) */
			ldns_zone_push_rr_list(signed_zone, cur_rrset);
		}
		ldns_rr_list_free(cur_rrset);
		cur_rrset = ldns_rr_list_pop_rrset(signed_zone_rrs);
	}
	ldns_rr_list_deep_free(signed_zone_rrs);
	ldns_rr_list_deep_free(pubkeys);
	ldns_rr_list_free(glue_rrs);
	return signed_zone;
	
}

static int
qsort_rr_compare_nsec3(const void *a, const void *b)
{
	const ldns_rr *rr1 = * (const ldns_rr **) a;
	const ldns_rr *rr2 = * (const ldns_rr **) b;
	if (rr1 == NULL && rr2 == NULL) {
		return 0;
	}
	if (rr1 == NULL) {
		return -1;
	} 
	if (rr2 == NULL) {
		return 1;
	}
	return ldns_rdf_compare(ldns_rr_owner(rr1), ldns_rr_owner(rr2));
}

void ldns_rr_list_sort_nsec3(ldns_rr_list *unsorted) {
	qsort(unsorted->_rrs,
	      ldns_rr_list_rr_count(unsorted),
	      sizeof(ldns_rr *),
	      qsort_rr_compare_nsec3);
}

ldns_zone *
ldns_zone_sign_nsec3(ldns_zone *zone, ldns_key_list *key_list, uint8_t algorithm, uint8_t flags, uint16_t iterations, uint8_t salt_length, uint8_t *salt)
{
	/*
	 * Algorithm to be created:
	 * - sort the rrs (name/class/type?)
	 * - if sorted, every next rr is belongs either to the rrset
	 * you are working on, or the rrset is complete
	 * for each rrset, calculate rrsig and nsec
	 * put the rrset, rrsig and nsec in the new zone
	 * done!
	 * ow and don't sign old rrsigs etc.
	 */
	
	ldns_zone *signed_zone;
	ldns_rr_list *cur_rrset;
	ldns_rr_list *cur_rrsigs;
	ldns_rr_list *orig_zone_rrs;
	ldns_rr_list *signed_zone_rrs;
	ldns_rr_list *pubkeys;
	ldns_rr_list *glue_rrs;
	ldns_rr_list *nsec3_rrs;
	ldns_rr *nsec3params;
	
	ldns_status status;
	
	ldns_rdf *start_dname = NULL;
	ldns_rdf *cur_dname = NULL;
	ldns_rr *next_rr = NULL;
	ldns_rdf *next_dname = NULL;
	char *next_nsec_owner_str = NULL;
	ldns_rdf *next_nsec_rdf = NULL;
	ldns_rr *nsec;
	ldns_rr *ckey;
	uint16_t i;
	uint16_t next_label_count;
	uint16_t cur_label_count;

	/* for the empty nonterminal finding algorithm */
	uint16_t j;
	ldns_rdf *l1, *l2, *post, *post2;
	bool found_difference;
	
	ldns_rr_type cur_rrset_type;
	
	signed_zone = ldns_zone_new();

	/* there should only be 1 SOA, so the soa record is 1 rrset */
	cur_rrsigs = NULL;
	ldns_zone_set_soa(signed_zone, ldns_rr_clone(ldns_zone_soa(zone)));
	/*ldns_rr2canonical(ldns_zone_soa(signed_zone));*/
	
	orig_zone_rrs = ldns_rr_list_clone(ldns_zone_rrs(zone));

	ldns_rr_list_push_rr(orig_zone_rrs, ldns_rr_clone(ldns_zone_soa(zone)));
	
	/* canon now, needed for correct nsec creation */
	/*
	for (i = 0; i < ldns_rr_list_rr_count(orig_zone_rrs); i++) {
		ldns_rr2canonical(ldns_rr_list_rr(orig_zone_rrs, i));
	}
	*/
	glue_rrs = ldns_zone_glue_rr_list(zone);

	/* create and add the nsec3params rr */
	nsec3params = ldns_rr_new_frm_type(LDNS_RR_TYPE_NSEC3PARAMS);
	ldns_rr_set_owner(nsec3params, ldns_rdf_clone(ldns_rr_owner(ldns_zone_soa(signed_zone))));
	ldns_nsec3_add_param_rdfs(nsec3params, algorithm, flags, iterations, salt_length, salt);
/*	ldns_rdf_set_type(ldns_rr_rdf(nsec3params, 0), LDNS_RDF_TYPE_NSEC3_PARAMS_VARS);*/
	ldns_rr_list_push_rr(orig_zone_rrs, nsec3params);
/*
ldns_rr_print(stdout, nsec3params);
exit(0);
*/
	/* add the key (TODO: check if it's there already? */
	pubkeys = ldns_rr_list_new();
	for (i = 0; i < ldns_key_list_key_count(key_list); i++) {
		ckey = ldns_key2rr(ldns_key_list_key(key_list, i));
		ldns_rr_list_push_rr(pubkeys, ckey);
	}

	signed_zone_rrs = ldns_rr_list_new();
	
	ldns_rr_list_sort(orig_zone_rrs);
	
	nsec3_rrs = ldns_rr_list_new();
	
	/* add nsecs */
	for (i = 0; i < ldns_rr_list_rr_count(orig_zone_rrs); i++) {
		if (!start_dname) {
			/*start_dname = ldns_rr_owner(ldns_zone_soa(zone));*/
			start_dname = ldns_rr_owner(ldns_rr_list_rr(orig_zone_rrs, i));
			cur_dname = start_dname;
		} else {

			next_rr = ldns_rr_list_rr(orig_zone_rrs, i);
			next_dname = ldns_rr_owner(next_rr);
			if (ldns_rdf_compare(cur_dname, next_dname) != 0) {

				/* every ownername should have an nsec3, and every empty nonterminal */
				/* the zone is sorted, so nonterminals should be visible? */
				/* if labels after first differ with previous it's an empty nonterm? */

				/* empty non-terminal detection algorithm 0.001a-pre1
				 * walk backwards to the first different label. for each label that
				 * is not the first label, we have found an empty nonterminal
				 */
				cur_label_count = ldns_dname_label_count(cur_dname);
				next_label_count = ldns_dname_label_count(next_dname);
				post = ldns_dname_new_frm_str(".");
				found_difference = false;
				for (j = 1; j <= cur_label_count && j <= next_label_count && !found_difference; j++) {
					l1 = ldns_dname_label(cur_dname, cur_label_count - j);
					l2 = ldns_dname_label(next_dname, next_label_count - j);
					
					post2 = ldns_dname_cat_clone(l2, post);
					ldns_rdf_deep_free(post);
					post = post2;

					if (ldns_dname_compare(l1, l2) != 0 &&
					    /*j < cur_label_count &&*/
					    j < next_label_count
					   ) {
					        /*
						printf("Found empty non-terminal: ");
						ldns_rdf_print(stdout, post);
						printf("\n");
						*/
						found_difference = true;
						nsec = ldns_create_nsec3(post, 
									ldns_rr_owner(ldns_zone_soa(zone)),
									orig_zone_rrs,
									algorithm,
									false,
									iterations,
									salt_length,
									salt,
									true);
						
						printf("Created NSEC3 for: ");
						ldns_rdf_print(stdout, post);
						printf(":\n");
						ldns_rr_print(stdout, nsec);
						
						ldns_rr_set_ttl(nsec, ldns_rdf2native_int32(ldns_rr_rdf(ldns_zone_soa(zone), 6)));
						ldns_rr_list_push_rr(nsec3_rrs, nsec);
					}
					ldns_rdf_deep_free(l1);
					ldns_rdf_deep_free(l2);
				}
				/* and if next label is longer than cur + 1, these must be empty nons too */
				/* skip current label (total now equal to cur_dname) */
				if (!found_difference && j < cur_label_count && j < next_label_count) {
					l2 = ldns_dname_label(next_dname, next_label_count - j);
					post2 = ldns_dname_cat_clone(l2, post);
					ldns_rdf_deep_free(post);
					post = post2;
					j++;
				}
				while (j < next_label_count) {
					l2 = ldns_dname_label(next_dname, next_label_count - j);
					post2 = ldns_dname_cat_clone(l2, post);
					ldns_rdf_deep_free(post);
					post = post2;
					/*
					printf("Found empty non-terminal: ");
					ldns_rdf_print(stdout, post);
					printf("\n");
					*/
					ldns_rdf_deep_free(l2);
					j++;	
					nsec = ldns_create_nsec3(post, 
								ldns_rr_owner(ldns_zone_soa(zone)),
								orig_zone_rrs,
								algorithm,
								false,
								iterations,
								salt_length,
								salt,
								true);
/*
					printf("Created NSEC3 for: ");
					ldns_rdf_print(stdout, post);
					printf(":\n");
					ldns_rr_print(stdout, nsec);
*/
					ldns_rr_set_ttl(nsec, ldns_rdf2native_int32(ldns_rr_rdf(ldns_zone_soa(zone), 6)));
					ldns_rr_list_push_rr(nsec3_rrs, nsec);
				}
				ldns_rdf_deep_free(post);

				/* skip glue */
				if (ldns_rr_list_contains_rr(glue_rrs, next_rr)) {
/*					cur_dname = next_dname;*/
					printf("Skip glue: ");
					ldns_rdf_print(stdout, cur_dname);
					printf("\n");
				} else {
					nsec = ldns_create_nsec3(cur_dname, 
								ldns_rr_owner(ldns_zone_soa(zone)),
								orig_zone_rrs,
								algorithm,
								false,
								iterations,
								salt_length,
								salt,
								false);

/*
					printf("Created NSEC3 for: ");
					ldns_rdf_print(stdout, cur_dname);
					printf(":\n");
					ldns_rr_print(stdout, nsec);
*/
					ldns_rr_set_ttl(nsec, ldns_rdf2native_int32(ldns_rr_rdf(ldns_zone_soa(zone), 6)));
					ldns_rr_list_push_rr(nsec3_rrs, nsec);
					/*start_dname = next_dname;*/
					cur_dname = next_dname;
				}
			}
		}
		ldns_rr_list_push_rr(signed_zone_rrs, ldns_rr_list_rr(orig_zone_rrs, i));
	}
	nsec = ldns_create_nsec3(cur_dname, 
				ldns_rr_owner(ldns_zone_soa(zone)),
				orig_zone_rrs,
				algorithm,
				false,
				iterations,
				salt_length,
				salt,
				false);
	ldns_rr_list_set_rr(nsec3_rrs, nsec, 4);
	ldns_rr_list_free(orig_zone_rrs);
	ldns_rr_set_ttl(nsec, ldns_rdf2native_int32(ldns_rr_rdf(ldns_zone_soa(zone), 6)));
	ldns_rr_list_push_rr(nsec3_rrs, nsec);

	printf("Created NSEC3 for: ");
	ldns_rdf_print(stdout, cur_dname);
	printf(":\n");
	ldns_rr_print(stdout, nsec);
	/* sort nsec3s separately, set nexts and append to signed zone */
	ldns_rr_list_sort_nsec3(nsec3_rrs);
	for (i = 0; i < ldns_rr_list_rr_count(nsec3_rrs); i++) {
		if (i == ldns_rr_list_rr_count(nsec3_rrs) - 1) {
			next_nsec_owner_str = ldns_rdf2str(ldns_dname_label(ldns_rr_owner(ldns_rr_list_rr(nsec3_rrs, 0)), 0));
			if (next_nsec_owner_str[strlen(next_nsec_owner_str) - 1] == '.') {
				next_nsec_owner_str[strlen(next_nsec_owner_str) - 1] = '\0';
			}
			status = ldns_str2rdf_b32_ext(&next_nsec_rdf, next_nsec_owner_str);
			if (!ldns_rr_set_rdf(ldns_rr_list_rr(nsec3_rrs, i), next_nsec_rdf, 4)) {
				/* todo: error */
			}
		} else {
			next_nsec_owner_str = ldns_rdf2str(ldns_dname_label(ldns_rr_owner(ldns_rr_list_rr(nsec3_rrs, i + 1)), 0));
			if (next_nsec_owner_str[strlen(next_nsec_owner_str) - 1] == '.') {
				next_nsec_owner_str[strlen(next_nsec_owner_str) - 1] = '\0';
			}
			status = ldns_str2rdf_b32_ext(&next_nsec_rdf, next_nsec_owner_str);
			if (!ldns_rr_set_rdf(ldns_rr_list_rr(nsec3_rrs, i), next_nsec_rdf, 4)) {
				/* todo: error */
			}
		}
	}
	
	ldns_rr_list_cat(signed_zone_rrs, nsec3_rrs);
/*
printf("going to sort:\n");
ldns_rr_list_print(stdout, signed_zone_rrs);
*/
	ldns_rr_list_sort(signed_zone_rrs);
	
	/* Sign all rrsets in the zone */
	cur_rrset = ldns_rr_list_pop_rrset(signed_zone_rrs);
	while (cur_rrset) {
		/* don't sign certain types */
		cur_rrset_type = ldns_rr_get_type(ldns_rr_list_rr(cur_rrset, 0));
		cur_dname = ldns_rr_owner(ldns_rr_list_rr(cur_rrset, 0));

		/* if we have KSKs, use them for DNSKEYS, otherwise
		   make them selfsigned (?) */
		/* don't sign sigs, delegations, and glue */
		if (cur_rrset_type != LDNS_RR_TYPE_RRSIG &&
			((ldns_dname_is_subdomain(cur_dname, ldns_rr_owner(ldns_zone_soa(signed_zone)))
			  && cur_rrset_type != LDNS_RR_TYPE_NS
			 ) ||
			 ldns_rdf_compare(cur_dname, ldns_rr_owner(ldns_zone_soa(signed_zone))) == 0
			) &&
			!(ldns_rr_list_contains_rr(glue_rrs, ldns_rr_list_rr(cur_rrset, 0)))
		   ) {
		   	/*
		   	printf("About to sign RRSET:\n");
		   	ldns_rr_list_print(stdout, cur_rrset);
			*/
			cur_rrsigs = ldns_sign_public(cur_rrset, key_list);

			/* TODO: make optional, replace exit call */
			/* if not optional it should be left out completely
			   (for it is possible to generate bad signarures, by
			   specifying a future inception date */
/*
			result = ldns_verify(cur_rrset, cur_rrsigs, pubkeys, NULL);
			if (result != LDNS_STATUS_OK) {
				dprintf("%s", "Cannot verify own sig:\n");
				dprintf("%s\n", ldns_get_errorstr_by_id(result));
				ERR_load_crypto_strings();
				ERR_print_errors_fp(stdout);
				exit(result);
			} else {
				printf("VERIFIED\n");
			}
*/
			ldns_zone_push_rr_list(signed_zone, cur_rrset);
			ldns_zone_push_rr_list(signed_zone, cur_rrsigs);
			ldns_rr_list_free(cur_rrsigs);
		} else {
			/* push it unsigned (glue, sigs, delegations) */
			ldns_zone_push_rr_list(signed_zone, cur_rrset);
		}
		ldns_rr_list_free(cur_rrset);
		cur_rrset = ldns_rr_list_pop_rrset(signed_zone_rrs);
	}
	ldns_rr_list_deep_free(signed_zone_rrs);
	ldns_rr_list_deep_free(pubkeys);
	ldns_rr_list_free(glue_rrs);
	return signed_zone;
	
}

/* taken from the ENGINE man page */
/*
int ldns_load_engine_fn(const char *engine_id, const char **pre_cmds, int pre_num, const char **post_cmds, int post_num)
{
	ENGINE *e
*/
#endif /* HAVE_SSL */
