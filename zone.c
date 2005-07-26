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

/* we don't want state, so we have to give it as arguments */
/* we regocnize:
 * $TTL, $ORIGIN
 */
ldns_zone *
ldns_zone_new_frm_fp(FILE *fp, ldns_rdf **origin, uint16_t *ttl, ldns_rr_class *c)
{
#if 0
	ldns_zone *newzone;
	ldns_rr *rr;
#endif

	/* read until we got a soa, all crap above is discarded 
	 * except $directives
	 */

	fp = fp;
	origin = origin;
	ttl = ttl;
	c = c;

	/* re-order stuff with rrsets */
	return NULL;
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
