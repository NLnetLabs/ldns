/*
 * higher.h
 *
 * Specify some higher level functions that would
 * be usefull to would be developers
 *
 * a Net::DNS like library for C
 *
 * (c) NLnet Labs, 2004
 *
 * See the file LICENSE for the license
 */

#include <ldns/resolver.h>
#include <ldns/rdata.h>
#include <ldns/rr.h>
#include <ldns/host2str.h>

/**
 * Ask the resolver about name
 * and return all address records
 */
ldns_rr_list *
ldns_get_rr_list_addr_by_name(ldns_resolver *r, ldns_rdf *name, ldns_rr_class c, uint16_t flags);

/**
 * ask the resolver about the address
 * and return the name
 *
 */
ldns_rr_list *
ldns_get_rr_list_name_by_addr(ldns_resolver *r, ldns_rdf *addr, ldns_rr_class c, uint16_t flags);
