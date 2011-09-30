/*
 * dnssec_nsec4.c
 *
 * contains the cryptographic function needed for DNSSEC in ldns
 * The crypto library used is openssl
 *
 * (c) NLnet Labs, 2011
 *
 * See the file LICENSE for the license
 */

#include <ldns/config.h>

#include <ldns/ldns.h>
#include <ldns/dnssec.h>
#include <ldns/dnssec_zone.h>
#include <ldns/dnssec_nsec4.h>

#include <strings.h>
#include <time.h>

#if USE_NSEC4

static int
rr_list_delegation_only(ldns_rdf *origin, ldns_rr_list *rr_list)
{
        size_t i;
        ldns_rr *cur_rr;
        if (!origin || !rr_list) return 0;
        for (i = 0; i < ldns_rr_list_rr_count(rr_list); i++) {
                cur_rr = ldns_rr_list_rr(rr_list, i);
                if (ldns_dname_compare(ldns_rr_owner(cur_rr), origin) == 0) {
                        return 0;
                }
                if (ldns_rr_get_type(cur_rr) != LDNS_RR_TYPE_NS) {
                        return 0;
                }
        }
        return 1;
}


/*return the owner name of the closest encloser for name from the list of rrs */
/* this is NOT the hash, but the original name! */
ldns_rdf *
ldns_dnssec_nsec4_closest_encloser(ldns_rdf *qname,
                                   ATTR_UNUSED(ldns_rr_type qtype),
                                   ldns_rr_list *nsec4s)
{
       /* remember parameters, they must match */
        uint8_t algorithm;
        uint32_t iterations;
        uint8_t salt_length;
        uint8_t *salt;

        ldns_rdf *sname, *hashed_sname, *tmp;
        ldns_rr *ce;
        bool flag;
	int hashed_name = 0;

        bool exact_match_found;
        bool in_range_found;

        ldns_status status;
        ldns_rdf *zone_name;

        size_t nsec_i;
        ldns_rr *nsec;
        ldns_rdf *result = NULL;
        qtype = qtype;

        if (!qname || !nsec4s || ldns_rr_list_rr_count(nsec4s) < 1) {
                return NULL;
        }

        nsec = ldns_rr_list_rr(nsec4s, 0);
        algorithm = ldns_nsec4_algorithm(nsec);
        salt_length = ldns_nsec4_salt_length(nsec);
        salt = ldns_nsec4_salt_data(nsec);
        iterations = ldns_nsec4_iterations(nsec);
        sname = ldns_rdf_clone(qname);
        ce = NULL;
	flag = false;
	zone_name = ldns_dname_left_chop(ldns_rr_owner(nsec));

        /* algorithm from nsec3-07 8.3 */
	while (ldns_dname_label_count(sname) > 0) {
		exact_match_found = false;
		in_range_found = false;

		if (algorithm) {
			hashed_sname = ldns_nsec3_hash_name(sname,
				algorithm, iterations, salt_length, salt);
			status = ldns_dname_cat(hashed_sname, zone_name);
		        if(status != LDNS_STATUS_OK) {
				LDNS_FREE(salt);
				ldns_rdf_deep_free(zone_name);
		                ldns_rdf_deep_free(sname);
		                return NULL;
		        }
			hashed_name = 1;
		} else {
			hashed_sname = sname;
			hashed_name = 0;
		}
		for (nsec_i = 0; nsec_i < ldns_rr_list_rr_count(nsec4s); nsec_i++) {
                        nsec = ldns_rr_list_rr(nsec4s, nsec_i);
                        /* check values of iterations etc! */

                        /* exact match? */
                        if (ldns_dname_compare(ldns_rr_owner(nsec), hashed_sname) == 0) {
                                exact_match_found = true;
                        } else if (ldns_nsec_covers_name(nsec, hashed_sname)) {
                                in_range_found = true;
                        }
		}
		if (!exact_match_found && in_range_found) {
                        flag = true;
                } else if (exact_match_found && flag) {
                        result = ldns_rdf_clone(sname);
                        /* RFC 5155: 8.3. 2.** "The proof is complete" */
			if (hashed_name) {
	                        ldns_rdf_deep_free(hashed_sname);
				hashed_name = 0;
			}
                        goto done;
                } else if (exact_match_found && !flag) {
                        /* error! */
			if (hashed_name) {
	                        ldns_rdf_deep_free(hashed_sname);
				hashed_name = 0;
			}
                        goto done;
                } else {
                        flag = false;
                }

		if (hashed_name) {
	                ldns_rdf_deep_free(hashed_sname);
			hashed_name = 0;
		}
                tmp = sname;
                sname = ldns_dname_left_chop(sname);
                ldns_rdf_deep_free(tmp);
        }

        done:
        LDNS_FREE(salt);
        ldns_rdf_deep_free(zone_name);
        ldns_rdf_deep_free(sname);

        return result;


}

ldns_rr *
ldns_dnssec_create_nsec4(ldns_dnssec_name *from, ldns_dnssec_name *to,
	ldns_rdf *zone_name, uint8_t algorithm, uint8_t flags,
	uint16_t iterations, uint8_t salt_length, uint8_t *salt)
{
	ldns_rr *nsec_rr;
	ldns_rr_type types[65536];
	size_t type_count = 0;
	ldns_dnssec_rrsets *cur_rrsets;
	ldns_status status;
	int on_delegation_point;

	flags = flags;
	if (!from) {
		return NULL;
	}
	nsec_rr = ldns_rr_new_frm_type(LDNS_RR_TYPE_NSEC4);
	if (algorithm) {
		ldns_rr_set_owner(nsec_rr,
	                  ldns_nsec3_hash_name(ldns_dnssec_name_name(from),
	                  algorithm,
	                  iterations,
	                  salt_length,
	                  salt));
		status = ldns_dname_cat(ldns_rr_owner(nsec_rr), zone_name);
	        if(status != LDNS_STATUS_OK) {
	                ldns_rr_free(nsec_rr);
	                return NULL;
	        }
	} else {
		ldns_rr_set_owner(nsec_rr,
			ldns_rdf_clone(ldns_dnssec_name_name(from)));
	}
	ldns_nsec4_add_param_rdfs(nsec_rr,
	                          algorithm,
	                          flags,
	                          iterations,
	                          salt_length,
	                          salt);

	on_delegation_point = ldns_dnssec_rrsets_contains_type(
			from->rrsets, LDNS_RR_TYPE_NS)
		&& !ldns_dnssec_rrsets_contains_type(
			from->rrsets, LDNS_RR_TYPE_SOA);
	cur_rrsets = from->rrsets;
	while (cur_rrsets) {
		/* Do not include non-authoritative rrsets on the delegation point
		 * in the type bitmap. Potentionally not skipping insecure
		 * delegation should have been done earlier, in function
		 * ldns_dnssec_zone_create_nsec4s, or even earlier in:
		 * ldns_dnssec_zone_sign_nsec4_flg .
		 */
		if ((on_delegation_point && (
				cur_rrsets->type == LDNS_RR_TYPE_NS
			     || cur_rrsets->type == LDNS_RR_TYPE_DS))
			|| (!on_delegation_point &&
				cur_rrsets->type != LDNS_RR_TYPE_RRSIG)) {

			types[type_count] = cur_rrsets->type;
			type_count++;
		}
		cur_rrsets = cur_rrsets->next;
	}
	/* always add rrsig type if this is not an unsigned
	 * delegation
	 */
	if (type_count > 0 &&
	    !(type_count == 1 && types[0] == LDNS_RR_TYPE_NS)) {
		types[type_count] = LDNS_RR_TYPE_RRSIG;
		type_count++;
	}

	/* leave next rdata empty if they weren't precomputed yet */
	if (to && to->hashed_name && algorithm) {
		(void) ldns_rr_set_rdf(nsec_rr,
		                       ldns_rdf_clone(to->hashed_name),
		                       4);
	} else if (to && !algorithm) {
		(void) ldns_rr_set_rdf(nsec_rr,
			ldns_rdf_clone(ldns_dnssec_name_name(from)), 4);
	} else {
		(void) ldns_rr_set_rdf(nsec_rr, NULL, 4);
	}
	ldns_rr_push_rdf(nsec_rr,
	                 ldns_dnssec_create_nsec_bitmap(types,
	                 type_count,
	                 LDNS_RR_TYPE_NSEC4));
	return nsec_rr;
}


void
ldns_nsec4_add_param_rdfs(ldns_rr *rr,
					 uint8_t algorithm,
					 uint8_t flags,
					 uint16_t iterations,
					 uint8_t salt_length,
					 uint8_t *salt)
{
	ldns_nsec3_add_param_rdfs(rr, algorithm, flags, iterations,
		 salt_length, salt);
	return;
}

/* this will NOT return the NSEC4 completed, you will have to run the
   finalize function on the rrlist later! */
ldns_rr *
ldns_create_nsec4(ldns_rdf *cur_owner,
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
	uint16_t i_type;
	ldns_rr *nsec = NULL;
	ldns_rdf *hashed_owner = NULL;
	ldns_status status;
	ldns_rr_type i_type_list[1024];
	size_t type_count = 0;

	if (algorithm) {
		hashed_owner = ldns_nsec3_hash_name(cur_owner,
					 algorithm,
					 iterations,
					 salt_length,
					 salt);
		status = ldns_dname_cat(hashed_owner, cur_zone);
	        if(status != LDNS_STATUS_OK)
	                return NULL;
	} else {
		hashed_owner = ldns_rdf_clone(cur_owner);
	}

	nsec = ldns_rr_new_frm_type(LDNS_RR_TYPE_NSEC4);
        if(!nsec)
                return NULL;
	ldns_rr_set_type(nsec, LDNS_RR_TYPE_NSEC4);
	ldns_rr_set_owner(nsec, hashed_owner);
	ldns_nsec4_add_param_rdfs(nsec,
		 algorithm,
		 flags,
		 iterations,
		 salt_length,
		 salt);
	(void) ldns_rr_set_rdf(nsec, NULL, 4);


	for (i = 0; i < ldns_rr_list_rr_count(rrs); i++) {
		i_rr = ldns_rr_list_rr(rrs, i);
		if (ldns_rdf_compare(cur_owner,
						 ldns_rr_owner(i_rr)) == 0) {
			i_type = ldns_rr_get_type(i_rr);
			if (type_count == 0 || i_type_list[type_count-1] != i_type) {
				i_type_list[type_count] = i_type;
				type_count++;
			}
		}
	}

	/* add RRSIG anyway, but only if this is not an ENT or
	 * an unsigned delegation */
	if (!emptynonterminal && !rr_list_delegation_only(cur_zone, rrs)) {
		i_type_list[type_count] = LDNS_RR_TYPE_RRSIG;
		type_count++;
	}

	/* and SOA if owner == zone */
	if (ldns_dname_compare(cur_zone, cur_owner) == 0) {
		i_type_list[type_count] = LDNS_RR_TYPE_SOA;
		type_count++;
	}

	ldns_rr_push_rdf(nsec,
	  ldns_dnssec_create_nsec_bitmap(i_type_list,
		type_count, LDNS_RR_TYPE_NSEC4));

	return nsec;
}


uint8_t
ldns_nsec4_algorithm(const ldns_rr *nsec4_rr)
{
	if (nsec4_rr &&
	      (ldns_rr_get_type(nsec4_rr) == LDNS_RR_TYPE_NSEC4 ||
	       ldns_rr_get_type(nsec4_rr) == LDNS_RR_TYPE_NSEC4PARAM)
	    && ldns_rdf_size(ldns_rr_rdf(nsec4_rr, 0)) > 0
	    ) {
		return ldns_rdf2native_int8(ldns_rr_rdf(nsec4_rr, 0));
	}
	return 0;
}

uint8_t
ldns_nsec4_flags(const ldns_rr *nsec4_rr)
{
	if (nsec4_rr &&
	      (ldns_rr_get_type(nsec4_rr) == LDNS_RR_TYPE_NSEC4 ||
	       ldns_rr_get_type(nsec4_rr) == LDNS_RR_TYPE_NSEC4PARAM)
	    && ldns_rdf_size(ldns_rr_rdf(nsec4_rr, 1)) > 0
	    ) {
		return ldns_rdf2native_int8(ldns_rr_rdf(nsec4_rr, 1));
	}
	return 0;
}

bool
ldns_nsec4_optout(const ldns_rr *nsec4_rr)
{
	return (ldns_nsec4_flags(nsec4_rr) & LDNS_NSEC3_VARS_OPTOUT_MASK);
}

bool
ldns_nsec4_wildcard(const ldns_rr *nsec4_rr)
{
	return (ldns_nsec4_flags(nsec4_rr) & LDNS_NSEC4_VARS_WILDCARD_MASK);
}

uint16_t
ldns_nsec4_iterations(const ldns_rr *nsec4_rr)
{
	if (nsec4_rr &&
	      (ldns_rr_get_type(nsec4_rr) == LDNS_RR_TYPE_NSEC4 ||
	       ldns_rr_get_type(nsec4_rr) == LDNS_RR_TYPE_NSEC4PARAM)
	    && ldns_rdf_size(ldns_rr_rdf(nsec4_rr, 2)) > 0
	    ) {
		return ldns_rdf2native_int16(ldns_rr_rdf(nsec4_rr, 2));
	}
	return 0;
}

ldns_rdf *
ldns_nsec4_salt(const ldns_rr *nsec4_rr)
{
	if (nsec4_rr &&
	      (ldns_rr_get_type(nsec4_rr) == LDNS_RR_TYPE_NSEC4 ||
	       ldns_rr_get_type(nsec4_rr) == LDNS_RR_TYPE_NSEC4PARAM)
	    ) {
		return ldns_rr_rdf(nsec4_rr, 3);
	}
	return NULL;
}

uint8_t
ldns_nsec4_salt_length(const ldns_rr *nsec4_rr)
{
	ldns_rdf *salt_rdf = ldns_nsec4_salt(nsec4_rr);
	if (salt_rdf && ldns_rdf_size(salt_rdf) > 0) {
		return (uint8_t) ldns_rdf_data(salt_rdf)[0];
	}
	return 0;
}

/* allocs data, free with LDNS_FREE() */
uint8_t *
ldns_nsec4_salt_data(const ldns_rr *nsec4_rr)
{
	uint8_t salt_length;
	uint8_t *salt;

	ldns_rdf *salt_rdf = ldns_nsec4_salt(nsec4_rr);
	if (salt_rdf && ldns_rdf_size(salt_rdf) > 0) {
	    	salt_length = ldns_rdf_data(salt_rdf)[0];
		salt = LDNS_XMALLOC(uint8_t, salt_length);
                if(!salt) return NULL;
		memcpy(salt, &ldns_rdf_data(salt_rdf)[1], salt_length);
		return salt;
	}
	return NULL;
}

ldns_rdf *
ldns_nsec4_next_owner(const ldns_rr *nsec4_rr)
{
	if (!nsec4_rr || ldns_rr_get_type(nsec4_rr) != LDNS_RR_TYPE_NSEC4) {
		return NULL;
	} else {
		return ldns_rr_rdf(nsec4_rr, 4);
	}
}

ldns_rdf *
ldns_nsec4_bitmap(const ldns_rr *nsec4_rr)
{
	if (!nsec4_rr || ldns_rr_get_type(nsec4_rr) != LDNS_RR_TYPE_NSEC4) {
		return NULL;
	} else {
		return ldns_rr_rdf(nsec4_rr, 5);
	}
}

ldns_rdf *
ldns_nsec4_hash_name_frm_nsec4(const ldns_rr *nsec, ldns_rdf *name)
{
	uint8_t algorithm;
	uint16_t iterations;
	uint8_t salt_length;
	uint8_t *salt = 0;
	ldns_rdf* zone_name = NULL;
	ldns_rdf *hashed_owner = NULL;
	ldns_status status = LDNS_STATUS_OK;

	algorithm = ldns_nsec4_algorithm(nsec);
	if (algorithm) {
		salt_length = ldns_nsec4_salt_length(nsec);
		salt = ldns_nsec4_salt_data(nsec);
		iterations = ldns_nsec4_iterations(nsec);
		hashed_owner = ldns_nsec3_hash_name(name,
					 algorithm,
					 iterations,
					 salt_length,
					 salt);
		LDNS_FREE(salt);
		zone_name = ldns_dname_left_chop(ldns_rr_owner(nsec));
                status = ldns_dname_cat(hashed_owner, zone_name);
                if(status != LDNS_STATUS_OK) {
                        ldns_rdf_deep_free(hashed_owner);
                        ldns_rdf_deep_free(zone_name);
                        return NULL;
                }
	} else {
		return ldns_rdf_clone(name);
	}
	return hashed_owner;
}


/**
 * Find particular name.
 *
 */
ldns_dnssec_name*
ldns_nsec4_dnssec_name_find(ldns_dnssec_zone* zone, ldns_rdf* name,
	ldns_rbnode_t* start_node)
{
	ldns_rbnode_t* node;
	ldns_dnssec_name* dnssec_name;

	if (!zone || !zone->names || !name) {
		return NULL;
	}
	if (start_node) {
		node = ldns_rbtree_previous(start_node);
	} else {
		node = ldns_rbtree_last(zone->names);
	}
	while (node && node != LDNS_RBTREE_NULL) {
		dnssec_name = (ldns_dnssec_name *) node->data;
		if (ldns_dname_compare(ldns_dnssec_name_name(dnssec_name),
			name) == 0) {
			return dnssec_name;
		}
		node = ldns_rbtree_previous(node);
	}
	return NULL;
}


/**
 * Mark wildcard bits.
 *
 */
ldns_status
ldns_dnssec_zone_set_wildcard_bits(ldns_dnssec_zone* zone)
{
	ldns_rbnode_t*	node;
	ldns_dnssec_name* name;
	ldns_dnssec_name* closest_encloser;
	ldns_rdf*	owner;
	ldns_rdf*	parent;
	ldns_rdf*	flags_rdf;
	uint8_t		flags;

	if (!zone || !zone->names) {
		return LDNS_STATUS_NULL;
	}
	for (node = ldns_rbtree_first(zone->names); node != LDNS_RBTREE_NULL;
		node = ldns_rbtree_next(node)) {
		name = (ldns_dnssec_name *) node->data;
		owner = ldns_dnssec_name_name(name);
		if (ldns_dname_is_wildcard(owner)) {
			/* chop of left most asterisk label */
			parent = ldns_dname_left_chop(owner);
			/* look up closest encloser */
			closest_encloser = ldns_nsec4_dnssec_name_find(
				zone, parent, node);
			if (!closest_encloser) {
				return LDNS_STATUS_DNSSEC_CLOSEST_ENCLOSER_NOT_FOUND;
			}
			/* set wildcard bit */
			if (closest_encloser->nsec &&
			 	ldns_rr_get_type(closest_encloser->nsec) == LDNS_RR_TYPE_NSEC4) {
				flags = ldns_nsec4_flags(closest_encloser->nsec);
				flags = flags | LDNS_NSEC4_VARS_WILDCARD_MASK;
				flags_rdf = ldns_rr_set_rdf(closest_encloser->nsec,
					ldns_native2rdf_int8(LDNS_RDF_TYPE_INT8,
						flags), 1);
				if (flags_rdf) {
					ldns_rdf_deep_free(flags_rdf);
				}
			}
		}

	}
	return LDNS_STATUS_OK;
}


ldns_status
ldns_dnssec_chain_nsec4_list(ldns_rr_list *nsec4_rrs)
{
	size_t i;
	ldns_rdf* next_nsec_rdf;

	for (i = 0; i < ldns_rr_list_rr_count(nsec4_rrs); i++) {
		if (i == ldns_rr_list_rr_count(nsec4_rrs) - 1) {
			/* final nsec4 rr */
			next_nsec_rdf = ldns_rdf_clone(
				ldns_rr_owner(ldns_rr_list_rr(nsec4_rrs, 0)));
			(void)ldns_rr_set_rdf(ldns_rr_list_rr(nsec4_rrs, i),
				 next_nsec_rdf, 4);
		} else {
			next_nsec_rdf = ldns_rdf_clone(
				ldns_rr_owner(ldns_rr_list_rr(nsec4_rrs, i+1)));
			(void)ldns_rr_set_rdf(ldns_rr_list_rr(nsec4_rrs, i),
				 next_nsec_rdf, 4);
		}
	}
	return LDNS_STATUS_OK;
}

int
qsort_rr_compare_nsec4(const void *a, const void *b)
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
	return ldns_dname_compare(ldns_rr_owner(rr1), ldns_rr_owner(rr2));
}

void
ldns_rr_list_sort_nsec4(ldns_rr_list *unsorted)
{
	qsort(unsorted->_rrs,
	      ldns_rr_list_rr_count(unsorted),
	      sizeof(ldns_rr *),
	      qsort_rr_compare_nsec4);
}

#endif /* USE_NSEC4 */
