/*
 * update.h
 *
 * Functions for RFC 2136 Dynamic Update
 *
 * Copyright (c) 2005, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 */

#ifndef _LDNS_UPDATE_H
#define _LDNS_UPDATE_H

ldns_pkt	*ldns_update_pkt_new(ldns_rdf *, ldns_rr_class, ldns_rr_list *,
    ldns_rr_list *, ldns_rr_list *);
ldns_status	ldns_update_pkt_tsig_add(ldns_pkt *, ldns_resolver *);
ldns_resolver	*ldns_update_resolver_new(const char *, const char *,
    ldns_rr_class, ldns_tsig_credentials *, ldns_rdf **);

uint16_t ldns_update_get_zo(const ldns_pkt *);
uint16_t ldns_update_get_pr(const ldns_pkt *);
uint16_t ldns_update_get_up(const ldns_pkt *);
uint16_t ldns_update_get_ad(const ldns_pkt *);

void ldns_update_set_zo(ldns_pkt *, u_int16_t);
void ldns_update_set_pr(ldns_pkt *, u_int16_t);
void ldns_update_set_up(ldns_pkt *, u_int16_t);
void ldns_update_set_ad(ldns_pkt *, u_int16_t);

#endif  /* !_LDNS_UPDATE_H */
