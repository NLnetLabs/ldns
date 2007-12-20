/*
 * special zone file structures and functions for better dnssec handling
 */

#include <ldns/config.h>

#include <ldns/ldns.h>

ldns_dnssec_rrs *
ldns_dnssec_rrs_new()
{
	ldns_dnssec_rrs *new_rrs;
	new_rrs = LDNS_MALLOC(ldns_dnssec_rrs);
	new_rrs->rr = NULL;
	new_rrs->next = NULL;
	return new_rrs;
}

void
ldns_dnssec_rrs_free(ldns_dnssec_rrs *rrs)
{
	if (rrs) {
		if (rrs->next) {
			ldns_dnssec_rrs_free(rrs->next);
		}
		LDNS_FREE(rrs);
	}
}

ldns_status
ldns_dnssec_rrs_add_rr(ldns_dnssec_rrs *rrs, ldns_rr *rr)
{
	int cmp;
	ldns_dnssec_rrs *new_rrs;
	if (!rrs || !rr) {
		return LDNS_STATUS_ERR;
	}

	/* this could be done more efficiently; name and type should already
	   be equal */
	cmp = ldns_rr_compare(rrs->rr,
					  rr);
	/* should we error on equal? */
	if (cmp <= 0) {
		if (rrs->next) {
			ldns_dnssec_rrs_add_rr(rrs->next, rr);
		} else {
			new_rrs = ldns_dnssec_rrs_new();
			new_rrs->rr = rr;
			rrs->next = new_rrs;
		}
	} else if (cmp > 0) {
		/* put the current old rr in the new next, put the new
		   rr in the current container */
		new_rrs = ldns_dnssec_rrs_new();
		new_rrs->rr = rrs->rr;
		new_rrs->next = rrs->next;
		rrs->rr = rr;
		rrs->next = new_rrs;
	}
	return LDNS_STATUS_OK;
}

void
ldns_dnssec_rrs_print(FILE *out, ldns_dnssec_rrs *rrs)
{
	if (!rrs) {
		fprintf(out, "<void>");
	} else {
		if (rrs->rr) {
			ldns_rr_print(out, rrs->rr);
		}
		if (rrs->next) {
			ldns_dnssec_rrs_print(out, rrs->next);
		}
	}
}

ldns_dnssec_rrsets *
ldns_dnssec_rrsets_new()
{
	ldns_dnssec_rrsets *new_rrsets;
	new_rrsets = LDNS_MALLOC(ldns_dnssec_rrsets);
	new_rrsets->rrs = NULL;
	new_rrsets->type = 0;
	new_rrsets->signatures = NULL;
	new_rrsets->next = NULL;
	return new_rrsets;
}

void
ldns_dnssec_rrsets_free(ldns_dnssec_rrsets *rrsets)
{
	if (rrsets) {
		if (rrsets->rrs) {
			ldns_dnssec_rrs_free(rrsets->rrs);
		}
		if (rrsets->next) {
			ldns_dnssec_rrsets_free(rrsets->next);
		}
		if (rrsets->signatures) {
			ldns_dnssec_rrs_free(rrsets->signatures);
		}
		LDNS_FREE(rrsets);
	}
}

ldns_rr_type
ldns_dnssec_rrsets_type(ldns_dnssec_rrsets *rrsets)
{
	if (rrsets) {
		return rrsets->type;
	} else {
		return 0;
	}
}

ldns_status
ldns_dnssec_rrsets_set_type(ldns_dnssec_rrsets *rrsets,
					   ldns_rr_type type)
{
	if (rrsets) {
		rrsets->type = type;
		return LDNS_STATUS_OK;
	}
	return LDNS_STATUS_ERR;
}


ldns_status
ldns_dnssec_rrsets_add_rr(ldns_dnssec_rrsets *rrsets, ldns_rr *rr)
{
	ldns_dnssec_rrsets *new_rrsets;
	ldns_rr_type rr_type;
	bool rrsig = false;
	ldns_status result = LDNS_STATUS_OK;

	if (!rrsets || !rr) {
		return LDNS_STATUS_ERR;
	}

	rr_type = ldns_rr_get_type(rr);

	if (rr_type == LDNS_RR_TYPE_RRSIG) {
		rrsig = true;
		rr_type = ldns_rdf2rr_type(ldns_rr_rrsig_typecovered(rr));
	}

	if (!rrsets->rrs && rrsets->type == 0) {
		rrsets->rrs = ldns_dnssec_rrs_new();
		rrsets->rrs->rr = rr;
		rrsets->type = ldns_rr_get_type(rr);
		return LDNS_STATUS_OK;
	}

	if (rr_type > ldns_dnssec_rrsets_type(rrsets)) {
		if (rrsets->next) {
			result = ldns_dnssec_rrsets_add_rr(rrsets->next, rr);
		} else {
			new_rrsets = ldns_dnssec_rrsets_new();
			new_rrsets->rrs = ldns_dnssec_rrs_new();
			new_rrsets->rrs->rr = rr;
			new_rrsets->type = ldns_rr_get_type(rr);
			rrsets->next = new_rrsets;
		}
	} else if (rr_type < ldns_dnssec_rrsets_type(rrsets)) {
		/* move the current one into the new next, 
		   replace field of current with data from new rr */
		new_rrsets = ldns_dnssec_rrsets_new();
		new_rrsets->rrs = rrsets->rrs;
		new_rrsets->type = rrsets->type;
		new_rrsets->signatures = rrsets->signatures;
		new_rrsets->next = rrsets->next;
		rrsets->rrs = ldns_dnssec_rrs_new();
		rrsets->rrs->rr = rr;
		rrsets->type = ldns_rr_get_type(rr);
		rrsets->next = new_rrsets;
	} else {
		/* equal, add to current rrsets */
		if (rrsig) {
			if (rrsets->signatures) {
				result = ldns_dnssec_rrs_add_rr(rrsets->signatures, rr);
			} else {
				rrsets->signatures = ldns_dnssec_rrs_new();
				rrsets->signatures->rr = rr;
			}
		} else {
			result = ldns_dnssec_rrs_add_rr(rrsets->rrs, rr);
		}
	}

	return result;
}

void
ldns_dnssec_rrsets_print(FILE *out, ldns_dnssec_rrsets *rrsets)
{
	if (!rrsets) {
		fprintf(out, "<void>\n");
	} else {
		if (rrsets->rrs) {
			ldns_dnssec_rrs_print(out, rrsets->rrs);
		}
		if (rrsets->signatures) {
			ldns_dnssec_rrs_print(out, rrsets->signatures);
		}
		if (rrsets->next) {
			ldns_dnssec_rrsets_print(out, rrsets->next);
		}
	}
}

ldns_dnssec_name *
ldns_dnssec_name_new()
{
	ldns_dnssec_name *new_name;

	new_name = LDNS_MALLOC(ldns_dnssec_name);
	if (!new_name) {
		return NULL;
	}

	new_name->balance = 0;
	new_name->left = NULL;
	new_name->right = NULL;
	new_name->up = NULL;

	new_name->rrsets = NULL;
	new_name->nsec = NULL;
	new_name->nsec_signatures = NULL;

	return new_name;
}

ldns_dnssec_name *
ldns_dnssec_name_new_frm_rr(ldns_rr *rr)
{
	ldns_dnssec_name *new_name = ldns_dnssec_name_new();

	new_name->name = ldns_rr_owner(rr);
	ldns_dnssec_name_add_rr_to_current(new_name, rr);

	return new_name;
}

void
ldns_dnssec_name_free(ldns_dnssec_name *name)
{
	if (name) {
		if (name->left) {
			ldns_dnssec_name_free(name->left);
		}
		if (name->right) {
			ldns_dnssec_name_free(name->right);
		}
		if (name->rrsets) {
			ldns_dnssec_rrsets_free(name->rrsets);
		}
		if (name->nsec_signatures) {
			ldns_dnssec_rrs_free(name->nsec_signatures);
		}
		LDNS_FREE(name);
	}
}

ldns_rdf *
ldns_dnssec_name_name(ldns_dnssec_name *name)
{
	if (name) {
		return name->name;
	}
	return NULL;
}

void
ldns_dnssec_name_set_name(ldns_dnssec_name *rrset,
						  ldns_rdf *dname)
{
	if (rrset && dname) {
		rrset->name = dname;
	}
}

ldns_rr *
ldns_dnssec_name_nsec(ldns_dnssec_name *rrset)
{
	if (rrset) {
		return rrset->nsec;
	}
	return NULL;
}

ldns_status
ldns_dnssec_name_set_nsec(ldns_dnssec_name *rrset, ldns_rr *nsec)
{
	if (rrset && nsec) {
		rrset->nsec = nsec;
		return LDNS_STATUS_OK;
	}
	return LDNS_STATUS_ERR;
}

ldns_dnssec_name *
ldns_dnssec_name_next(ldns_dnssec_name *name)
{
	ldns_dnssec_name *parent;
	ldns_dnssec_name *current;

	if (!name) {
		return NULL;
	}
	if (name->right) {
		current = name->right;
		while(current->left) {
			current = current->left;
		}
		return current;
	} else {
		/* if this is a right branch, the grandparent is the next, unless
		   the parent is also a right branch, etc */
		current = name;
		parent = current->up;
		while (parent) {
			if (parent->right == current) {
				current = parent;
				parent = parent->up;
			} else {
				return parent;
			}
		}
		return NULL;
	}
}

ldns_status
ldns_dnssec_name_add_rr_to_current(ldns_dnssec_name *name,
								 ldns_rr *rr)
{
	ldns_dnssec_rrsets *new_rrsets;
	ldns_status result = LDNS_STATUS_OK;

	if (!name || !rr) {
		return LDNS_STATUS_ERR;
	}
	if (name->rrsets) {
		result = ldns_dnssec_rrsets_add_rr(name->rrsets, rr);
	} else {
		new_rrsets = ldns_dnssec_rrsets_new();
		result = ldns_dnssec_rrsets_add_rr(new_rrsets, rr);
		name->rrsets = new_rrsets;
	}
	return result;
}

ldns_status
ldns_dnssec_name_add_rr(ldns_dnssec_name *name,
						ldns_rr *rr)
{
	ldns_dnssec_name *new_name;
	int cmp;
	ldns_status result = LDNS_STATUS_OK;
	ldns_rdf *name_name;
	bool hashed_name = false;

	/* special handling for NSEC3 and NSECX covering RRSIGS */
	ldns_rr_type rr_type = ldns_rr_get_type(rr);
	ldns_rr_type typecovered = 0;

	if (!name || !rr) {
		return LDNS_STATUS_ERR;
	}

	rr_type = ldns_rr_get_type(rr);

	if (rr_type == LDNS_RR_TYPE_RRSIG) {
		typecovered = ldns_rdf2rr_type(ldns_rr_rrsig_typecovered(rr));
	}

	if (rr_type == LDNS_RR_TYPE_NSEC3 ||
	    typecovered == LDNS_RR_TYPE_NSEC3) {
		name_name = ldns_nsec3_hash_name_frm_nsec3(rr,
										   ldns_dnssec_name_name(name));
		hashed_name = true;
	} else {
		name_name = ldns_dnssec_name_name(name);
	}

	cmp = ldns_dname_compare(ldns_rr_owner(rr),
					     name_name);

	if (cmp > 0) {
		if (name->right) {
			result = ldns_dnssec_name_add_rr(name->right, rr);
		} else {
			new_name = ldns_dnssec_name_new();
			new_name->name = ldns_rr_owner(rr);
			new_name->up = name;
			result = ldns_dnssec_name_add_rr_to_current(new_name, rr);
			name->right = new_name;
		}
		name->balance++;
	} else if (cmp < 0) {
		if (name->left) {
			ldns_dnssec_name_add_rr(name->left, rr);
		} else {
			new_name = ldns_dnssec_name_new();
			new_name->name = ldns_rr_owner(rr);
			new_name->up = name;
			result = ldns_dnssec_name_add_rr_to_current(new_name, rr);
			name->left = new_name;
		}
		name->balance--;
	} else {
		if (rr_type == LDNS_RR_TYPE_NSEC ||
		    rr_type == LDNS_RR_TYPE_NSEC3) {
			/* XX check if is already set (and error?) */
			name->nsec = rr;
		} else if (typecovered == LDNS_RR_TYPE_NSEC ||
				 typecovered == LDNS_RR_TYPE_NSEC3) {
			if (name->nsec_signatures) {
				ldns_dnssec_rrs_add_rr(name->nsec_signatures, rr);
			} else {
				name->nsec_signatures = ldns_dnssec_rrs_new();
				name->nsec_signatures->rr = rr;
			}
		} else {
			result = ldns_dnssec_name_add_rr_to_current(name, rr);
		}
	}

	if (hashed_name) {
		ldns_rdf_free(name_name);
	}

	return result;
}

void
ldns_dnssec_name_print(FILE *out, ldns_dnssec_name *name, bool single)
{
	if (name) {
		if (!single && name->left) {
			ldns_dnssec_name_print(out, name->left, single);
		}
		if(name->rrsets) {
			ldns_dnssec_rrsets_print(out, name->rrsets);
		}
		if(name->nsec) {
			ldns_rr_print(out, name->nsec);
		}
		if (name->nsec_signatures) {
			ldns_dnssec_rrs_print(out, name->nsec_signatures);
		}
		if (!single && name->right) {
			ldns_dnssec_name_print(out, name->right, single);
		}
	} else {
		fprintf(out, "<void>\n");
	}
}

ldns_dnssec_zone *
ldns_dnssec_zone_new()
{
	ldns_dnssec_zone *zone = LDNS_MALLOC(ldns_dnssec_zone);
	zone->soa = NULL;
	zone->names = NULL;

	return zone;
}

void
ldns_dnssec_zone_free(ldns_dnssec_zone *zone)
{
	if (zone) {
		if (zone->soa) {
			ldns_dnssec_name_free(zone->soa);
		}
		if (zone->names) {
			ldns_dnssec_name_free(zone->names);
		}
		LDNS_FREE(zone);
	}
}

ldns_status
ldns_dnssec_zone_add_rr(ldns_dnssec_zone *zone, ldns_rr *rr)
{
	ldns_status result = LDNS_STATUS_OK;

	if (!zone || !rr) {
		return LDNS_STATUS_ERR;
	}

	if (zone->names) {
		result = ldns_dnssec_name_add_rr(zone->names, rr);
	} else {
		zone->names = ldns_dnssec_name_new_frm_rr(rr);
		if (!zone->names) {
			result = LDNS_STATUS_ERR;
		}
	}

	if (result != LDNS_STATUS_OK) {
		fprintf(stderr, "error adding rr: ");
		ldns_rr_print(stderr, rr);
	}

	return result;
}

void
ldns_dnssec_zone_print(FILE *out, ldns_dnssec_zone *zone)
{
	if (zone) {
		if (zone->soa) {
			ldns_dnssec_name_print(out, zone->soa, false);
		}
		if (zone->names) {
			ldns_dnssec_name_print(out, zone->names, false);
		}
	}
}

