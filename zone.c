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

bool
ldns_zone_rr_is_glue(ldns_zone *z, ldns_rr *rr)
{
	z = z;
	rr = rr;

	return false;
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
	ldns_zone *newzone;
	ldns_rr *rr;
	ldns_rdf *my_origin = origin;
	uint16_t my_ttl = ttl;
	ldns_rr_class my_class = c;

	uint8_t i;

	newzone = ldns_zone_new();
	my_origin = origin;
	my_ttl    = ttl;
	my_class  = c;
	
	/* read until we got a soa, all crap above is discarded 
	 * except $directives
	 */

	i = 0;
	do {
		rr = ldns_rr_new_frm_fp(fp, my_ttl, my_origin);
		i++;
	} while (!rr && i <= 9);

	if (i > 9) {
		/* there is a lot of crap here, bail out before somebody gets
		 * hurt */
		if (rr) {
			ldns_rr_free(rr);
		}
		return NULL;
	}

	if (ldns_rr_get_type(rr) != LDNS_RR_TYPE_SOA) {
		/* first rr MUST be the soa */
		ldns_rr_free(rr);
		return NULL;
	}

	ldns_zone_set_soa(newzone, rr);

	while(!feof(fp)) {
		rr = ldns_rr_new_frm_fp(fp, my_ttl, my_origin);
		if (rr) {
			if (!ldns_zone_push_rr(newzone, rr)) {
				printf("error pushing rr\n");
				return NULL;
			}

			/*my_origin = ldns_rr_owner(rr);*/
			my_ttl    = ldns_rr_ttl(rr);
			my_class  = ldns_rr_get_class(rr);
			
		} else {
			fprintf(stderr, "Error in file, unable to read RR\n");
		}
	}
	return newzone;
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
