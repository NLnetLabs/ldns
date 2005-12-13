/* zone.c
 *
 * Functions for ldns_zone structure
 * a Net::DNS like library for C
 *
 * (c) NLnet Labs, 2005
 * See the file LICENSE for the license
 */
#include <ldns/config.h>

#include <ldns/dns.h>

#include <strings.h>
#include <limits.h>

ldns_rr *
ldns_zone_soa(ldns_zone *z)
{
        return z->_soa;
}

uint16_t
ldns_zone_rr_count(ldns_zone *z)
{
	return ldns_rr_list_rr_count(z->_rrs);
}

void
ldns_zone_set_soa(ldns_zone *z, ldns_rr *soa)
{
	z->_soa = soa;
}

ldns_rr_list *
ldns_zone_rrs(ldns_zone *z)
{
	return z->_rrs;
}

void
ldns_zone_set_rrs(ldns_zone *z, ldns_rr_list *rrlist)
{
	z->_rrs = rrlist;
}

bool
ldns_zone_push_rr_list(ldns_zone *z, ldns_rr_list *list)
{
	return ldns_rr_list_cat(ldns_zone_rrs(z), list);

}

bool
ldns_zone_push_rr(ldns_zone *z, ldns_rr *rr)
{
	return ldns_rr_list_push_rr(
			ldns_zone_rrs(z), rr);
}

/* this will be an EXPENSIVE op with our zone structure */
ldns_rr_list *
ldns_zone_glue_rr_list(ldns_zone *z)
{
	/* when do we find glue? It means we find an IP address
	 * (AAAA/A) for a nameserver listed in the zone
	 *
	 * Alg used here:
	 * first find all the zonecuts (NS records)
	 * find all the AAAA or A records (can be done it the 
	 * above loop).
	 *
	 * Check if the aaaa/a list are subdomains under the
	 * NS domains. If yes -> glue, if no -> not glue
	 */

	ldns_rr_list *zone_cuts;
	ldns_rr_list *addr;
	ldns_rr_list *glue;
	ldns_rr *r, *ns, *a;
	ldns_rdf *dname_a, *dname_ns, *ns_owner;
	uint16_t i,j;

	zone_cuts = ldns_rr_list_new();
	addr = ldns_rr_list_new();
	glue = ldns_rr_list_new();

	for(i = 0; i < ldns_zone_rr_count(z); i++) {
		r = ldns_rr_list_rr(ldns_zone_rrs(z), i);
		if (ldns_rr_get_type(r) == LDNS_RR_TYPE_A ||
				ldns_rr_get_type(r) == LDNS_RR_TYPE_AAAA) {
			/* possibly glue */
			ldns_rr_list_push_rr(addr, r);
			continue;
		}
		if (ldns_rr_get_type(r) == LDNS_RR_TYPE_NS) {
			/* multiple zones will end up here -
			 * for now; not a problem
			 */
			/* don't add NS records for the current zone itself */
			if (ldns_rdf_compare(ldns_rr_owner(r), ldns_rr_owner(ldns_zone_soa(z))) != 0) {
				ldns_rr_list_push_rr(zone_cuts, r);
			}
			continue;
		}
	}

	/* will sorting make it quicker ?? */
	for(i = 0; i < ldns_rr_list_rr_count(zone_cuts); i++) {
		ns = ldns_rr_list_rr(zone_cuts, i);
		ns_owner = ldns_rr_owner(ns);
		dname_ns = ldns_rr_ns_nsdname(ns);
		for(j = 0; j < ldns_rr_list_rr_count(addr); j++) {
			a = ldns_rr_list_rr(addr, j);
			dname_a = ldns_rr_owner(a);
			
			if (ldns_dname_is_subdomain(dname_a, ns_owner) &&
			    ldns_rdf_compare(dname_ns, dname_a) == 0
			) {
				/* GLUE! */
				ldns_rr_list_push_rr(glue, a);
				break;
			}
		}
	}
	if (ldns_rr_list_rr_count(glue) == 0) {
		return NULL;
	} else {
		return glue;
	}
}

ldns_zone *
ldns_zone_new(void)
{
	ldns_zone *z;

	z = LDNS_MALLOC(ldns_zone);
	if (!z) {
		return NULL;
	}

	z->_rrs = ldns_rr_list_new();
	ldns_zone_set_soa(z, NULL);
	return z;
}

/* we regocnize:
 * $TTL, $ORIGIN
 */
ldns_zone *
ldns_zone_new_frm_fp(FILE *fp, ldns_rdf *origin, uint16_t ttl, ldns_rr_class c)
{
	return ldns_zone_new_frm_fp_l(fp, origin, ttl, c, NULL);
}

ldns_zone *
ldns_zone_new_frm_fp_l(FILE *fp, ldns_rdf *origin, uint16_t ttl, ldns_rr_class c, int *line_nr)
{
	ldns_zone *newzone;
	ldns_rr *rr;
	uint16_t my_ttl = ttl;
	ldns_rr_class my_class = c;
	ldns_rr *last_rr = NULL;
	ldns_rdf *my_origin = NULL;
	ldns_rdf *my_prev;
	uint8_t i;

	newzone = ldns_zone_new();
	my_origin = origin;
	my_ttl    = ttl;
	my_class  = c;
	
	/* read until we got a soa, all crap above is discarded 
	 * except $directives
	 */

	if (origin) {
		my_origin = ldns_rdf_clone(origin);
		/* also set the prev */
		my_prev   = ldns_rdf_clone(origin);
	}
	
	i = 0;
	do {
		rr = ldns_rr_new_frm_fp_l(fp, &my_ttl, &my_origin, &my_prev, line_nr);
		i++;
	} while (!rr && i <= 9);

	if (i > 9) {
		/* there is a lot of crap here, bail out before somebody gets
		 * hurt */
		if (rr) {
			ldns_rr_free(rr);
		}
		if (my_origin) {
			ldns_rdf_free(my_origin);
		}
		ldns_zone_deep_free(newzone);
		return NULL;
	}

	if (ldns_rr_get_type(rr) != LDNS_RR_TYPE_SOA) {
		/* first rr MUST be the soa */
		ldns_rr_free(rr);
		if (my_origin) {
			ldns_rdf_free(my_origin);
		}
		ldns_zone_deep_free(newzone);
		return NULL;
	}

	ldns_zone_set_soa(newzone, rr);

	if (!my_origin) {
		my_origin = ldns_rdf_clone(ldns_rr_owner(rr));
	}

	while(!feof(fp)) {
		rr = ldns_rr_new_frm_fp_l(fp, &my_ttl, &my_origin, &my_prev, line_nr);
		if (rr) {
			last_rr = rr;
			if (!ldns_zone_push_rr(newzone, rr)) {
				dprintf("%s", "error pushing rr\n");
				if (my_origin) {
					ldns_rdf_free(my_origin);
				}
				ldns_zone_deep_free(newzone);
				return NULL;
			}

			/*my_origin = ldns_rr_owner(rr);*/
			my_ttl    = ldns_rr_ttl(rr);
			my_class  = ldns_rr_get_class(rr);
			
		} else {
			/* hmz if $ORIGIN was read there is no RR either */
			/* we need to add a feedbacking function */
			/*
			fprintf(stderr, "Error in file, unable to read RR");
			if (line_nr) {
				fprintf(stderr, " at line %d.\n", *line_nr);
			} else {
				fprintf(stderr, ".");
			}

			fprintf(stderr, "Last rr that was parsed:\n");
			ldns_rr_print(stderr, last_rr);
			dprintf("%s", "\n");
			*/
		}
	}
	if (my_origin) {
		ldns_rdf_deep_free(my_origin);
	}
	return newzone;
}

void
ldns_zone_sort_oct(ldns_zone *zone)
{
	ldns_rr_list *zrr;
	assert(zone != NULL);

	zrr = ldns_zone_rrs(zone);
	ldns_rr_list_sort_oct(zrr);
}

void
ldns_zone_sort(ldns_zone *zone)
{
	ldns_rr_list *zrr;
	assert(zone != NULL);

	zrr = ldns_zone_rrs(zone);
	ldns_rr_list_sort(zrr);
}

#if 0
/**
 * ixfr function. Work on a ldns_zone and remove and add
 * the rrs from the rrlist
 * \param[in] z the zone to work on
 * \param[in] del rr_list to remove from the zone
 * \param[in] add rr_list to add to the zone
 * \return Tja, wat zouden we eens returnen TODO
 */
void
ldns_zone_ixfr_del_add(ldns_zone *z, ldns_rr_list *del, ldns_rr_list *add)
{
	
}
#endif

void
ldns_zone_free(ldns_zone *zone) {
	ldns_rr_list_free(zone->_rrs);
	LDNS_FREE(zone);
}

void
ldns_zone_deep_free(ldns_zone *zone) {
	ldns_rr_free(zone->_soa);
	ldns_rr_list_deep_free(zone->_rrs);
	LDNS_FREE(zone);
}
