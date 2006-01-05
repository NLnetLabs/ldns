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
 * (c) NLnet Labs, 2005-2006
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
 * create a new ldns_zone structure
 * \return a pointer to a ldns_zone structure
 */
ldns_zone * ldns_zone_new(void);

/**
 * Return the soa record of a zone
 * \param[in] z the zone to read from
 * \return the soa record in the zone
 */
ldns_rr * ldns_zone_soa(ldns_zone *z);

/**
 * Returns the number of resource records in the zone, NOT counting the SOA record
 * \param[in] z the zone to read from
 * \return the number of rr's in the zone
 */
uint16_t ldns_zone_rr_count(ldns_zone *z);

/**
 * Set the zone's soa record
 * \param[in] z the zone to put the new soa in
 * \param[in] soa the soa to set
 */
void ldns_zone_set_soa(ldns_zone *z, ldns_rr *soa);

/**
 * Get a list of a zone's content. Note that the SOA
 * isn't included in this list. You need to get the 
 * with ldns_zone_soa.
 * \param[in] z the zone to read from
 * \return the rrs from this zone
 */
ldns_rr_list * ldns_zone_rrs(ldns_zone *z);

/**
 * Set the zone's contents
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
 * Retrieve all resource records from the zone that are glue
 * records. The resulting list does *not* contain clones from the rrs
 *
 * \param[in] z the zone to look for glue
 * \return the rr_list with the glue
 */
ldns_rr_list *ldns_zone_glue_rr_list(ldns_zone *z);

/**
 * Create a new zone from a file
 * \param[in] *fp the filepointer to use
 * \param[in] *origin the zones' origin
 * \param[in] ttl default ttl to use
 * \param[in] c default class to use (IN)
 *
 * \return a pointer to a new zone structure
 */
ldns_zone *
ldns_zone_new_frm_fp(FILE *fp, ldns_rdf *origin, uint16_t ttl, ldns_rr_class c);

/**
 * Create a new zone from a file, keep track of the line numbering
 * \param[in] *fp the filepointer to use
 * \param[in] *origin the zones' origin
 * \param[in] ttl default ttl to use
 * \param[in] c default class to use (IN)
 * \param[out] line_nr used for error msg, to get to the line number
 *
 * \return a pointer to a new zone structure
 */
ldns_zone *
ldns_zone_new_frm_fp_l(FILE *fp, ldns_rdf *origin, uint16_t ttl, ldns_rr_class c, int *line_nr);

/**
 * Frees the allocated memory for the zone, and the rr_list structure in it
 * \param[in] zone the zone to free
 */
void ldns_zone_free(ldns_zone *zone);

/**
 * Frees the allocated memory for the zone, the soa rr in it, 
 * and the rr_list structure in it, including the rr's in that. etc.
 * \param[in] zone the zone to free
 */
void ldns_zone_deep_free(ldns_zone *zone);

/**
 * Sort the rrs in a zone on OWNER CLASS TYPE
 * \param[in] zone the zone to sort
 */
void ldns_zone_sort_oct(ldns_zone *zone);

/**
 * Just sort the rrs in a zone.
 * \param[in] zone the zone to sort
 */
void ldns_zone_sort(ldns_zone *zone);

#endif /* LDNS_ZONE_H */
