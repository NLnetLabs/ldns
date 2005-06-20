/* zone.c
 *
 * access functions for ldns_zone
 * a Net::DNS like library for C
*
 * (c) NLnet Labs, 2004
 * See the file LICENSE for the license
 */
#include <ldns/config.h>

#include <ldns/dns.h>

#include <strings.h>
#include <limits.h>

/**
 * \param[in] z the zone to read from
 * \return the soa record in the zone
 */
ldns_rr *
ldns_zone_soa(ldns_zone *z)
{
        return z->_soa;
}

/**
 * \param[in] z the zone to put the new soa in
 * \param[in] soa the soa to set
 */
void
ldns_zone_set_soa(ldns_zone *z, ldns_rr *soa)
{
	z->_soa = soa;
}

/**
 * \param[in] z the zone to read from
 * \return the rrs from this zone
 */
ldns_rr_list *
ldns_zone_rrs(ldns_zone *z)
{
	return z->_rrs;
}

/**
 * \param[in] z the zone to put the new soa in
 * \param[in] rrlist the rrlist to use
 */
void
ldns_zone_set_rrs(ldns_zone *z, ldns_rr_list *rrlist)
{
	z->_rrs = rrlist;
}
