/**
 * zone.h
 *
 * zone definitions
 *  - what is it
 *  - get_glue function
 *  - search etc
 *
 * a Net::DNS like library for C
 *
 * (c) NLnet Labs, 2004, 2005
 *
 * See the file LICENSE for the license
 */

#ifndef _LDNS_ZONE_H
#define _LDNS_ZONE_H

#include <ldns/common.h>
#include <ldns/rdata.h>
#include <ldns/rr.h>
#include <ldns/error.h>

/** 
 * Zone type
 *
 * basicly a list of RR's with some
 * extra information which comes from the SOA RR
 */
struct ldns_struct_zone
{
	/** the soa defines a zone */
	ldns_rr 	*_soa;
	/* basicly a zone is a list of rr's */
	ldns_rr_list 	*_rrs;
	/* we could change this to be a b-tree etc etc todo */
};
typedef struct ldns_struct_zone ldns_zone;	
	

/**
 * \param[in] z the zone to read from
 * \return the soa record in the zone
 */
ldns_rr * ldns_zone_soa(ldns_zone *z);

/**
 * \param[in] z the zone to put the new soa in
 * \param[in] soa the soa to set
 */
void ldns_zone_set_soa(ldns_zone *z, ldns_rr *soa);

/**
 * \param[in] z the zone to read from
 * \return the rrs from this zone
 */
ldns_rr_list * ldns_zone_rrs(ldns_zone *z);

/**
 * \param[in] z the zone to put the new soa in
 * \param[in] rrlist the rrlist to use
 */
void ldns_zone_set_rrs(ldns_zone *z, ldns_rr_list *rrlist);

/**
 * push an rrlist to a zone structure. This function use pointer
 * copying, so the rr_list structure inside z is modified!
 * \param[in] z the zone to add to
 * \param[in] list the list to add
 * \return a true on succes otherwise falsed
 */
bool ldns_zone_push_rr_list(ldns_zone *z, ldns_rr_list *list);

/**
 * push an singkle rr to a zone structure. This function use pointer
 * copying, so the rr_list structure inside z is modified!
 * \param[in] z the zone to add to
 * \param[in] rr the rr to add
 * \return a true on succes otherwise falsed
 */
bool ldns_zone_push_rr(ldns_zone *z, ldns_rr *rr);

/**
 * find out if the rr is glue inside zone z
 * \param[in] z the zone to look for glue
 * \param[in] rr the rr to test
 * \return true if rr is glue, otherwise false
 */
bool ldns_zone_rr_is_glue(ldns_zone *z, ldns_rr *rr);

#endif /* LDNS_ZONE_H */
