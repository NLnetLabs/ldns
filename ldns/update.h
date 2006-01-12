/*
 * update.h
 *
 * Functions for RFC 2136 Dynamic Update
 *
 * Copyright (c) 2005-2006, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 */

#ifndef LDNS_UPDATE_H
#define LDNS_UPDATE_H

#include <ldns/resolver.h>

/**
 * create an update packet from zone name, class and the rr lists
 * \param[in] zone name of the zone
 * \param[in] class zone class
 * \param[in] pr_rrlist list of Prerequisite Section RRs
 * \param[in] up_rrlist list of Updates Section RRs
 * \param[in] ad_rrlist list of Additional Data Section RRs (currently unused)
 * \return the new packet
 */
ldns_pkt *ldns_update_pkt_new(ldns_rdf *zone_rdf, ldns_rr_class clas, ldns_rr_list *pr_rrlist, ldns_rr_list *up_rrlist, ldns_rr_list *ad_rrlist);

/**
 * add tsig credentials to
 * a packet from a resolver
 * \param[in] p packet to copy to
 * \param[in] r resolver to copy from
 *
 * \return status wether successfull or not
 */
ldns_status ldns_update_pkt_tsig_add(ldns_pkt *p, ldns_resolver *r);

/* access functions */
uint16_t ldns_update_zocount(const ldns_pkt *);
uint16_t ldns_update_prcount(const ldns_pkt *);
uint16_t ldns_update_upcount(const ldns_pkt *);
uint16_t ldns_update_adcount(const ldns_pkt *);
void ldns_update_set_zocount(ldns_pkt *, uint16_t);
void ldns_update_set_prcount(ldns_pkt *, uint16_t);
void ldns_update_set_upcount(ldns_pkt *, uint16_t);
void ldns_update_set_adcount(ldns_pkt *, uint16_t);

ldns_status ldns_update_soa_mname(ldns_rdf *zone, ldns_resolver *r, ldns_rr_class class, ldns_rdf **mname);
ldns_status ldns_update_soa_zone_mname(const char *fqdn, ldns_resolver *r, ldns_rr_class class, ldns_rdf **zone_rdf, ldns_rdf **mname_rdf);


#endif  /* LDNS_UPDATE_H */
