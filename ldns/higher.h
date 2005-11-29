/*
 * higher.h
 *
 * Specify some higher level functions that would
 * be usefull to would be developers
 *
 * a Net::DNS like library for C
 *
 * (c) NLnet Labs, 2004, 2005
 *
 * See the file LICENSE for the license
 */

#ifndef _LDNS_HIGHER_H
#define _LDNS_HIGHER_H

#include <ldns/resolver.h>
#include <ldns/rdata.h>
#include <ldns/rr.h>
#include <ldns/host2str.h>
#include <ldns/tsig.h>

/**
 * Ask the resolver about name
 * and return all address records
 * \param[in] r the resolver to use
 * \param[in] name the name to look for
 * \param[in] c the class to use
 * \param[in] flags give some optional flags to the query
 */
ldns_rr_list *ldns_get_rr_list_addr_by_name(ldns_resolver *r, ldns_rdf *name, ldns_rr_class c, uint16_t flags);

/**
 * ask the resolver about the address
 * and return the name
 * \param[in] r the resolver to use
 * \param[in] addr the addr to look for
 * \param[in] c the class to use
 * \param[in] flags give some optional flags to the query
 */
ldns_rr_list *ldns_get_rr_list_name_by_addr(ldns_resolver *r, ldns_rdf *addr, ldns_rr_class c, uint16_t flags);

/**
 * wade through fp (a /etc/hosts like file)
 * and return a rr_list containing all the 
 * defined hosts in there
 * \param[in] fp the file pointer to use
 * \return ldns_rr_list * with the names
 */
ldns_rr_list *ldns_get_rr_list_hosts_frm_fp(FILE *fp);

/**
 * wade through fp (a /etc/hosts like file)
 * and return a rr_list containing all the 
 * defined hosts in there
 * \param[in] fp the file pointer to use
 * \param[in] line_nr pointer to an integer containing the current line number (for debugging purposes)
 * \return ldns_rr_list * with the names
 */
ldns_rr_list *ldns_get_rr_list_hosts_frm_fp_l(FILE *fp, int *line_nr);

/**
 * wade through fp (a /etc/hosts like file)
 * and return a rr_list containing all the 
 * defined hosts in there
 * \param[in] filename the filename to use (NULL for /etc/hosts)
 * \return ldns_rr_list * with the names
 */
ldns_rr_list *ldns_get_rr_list_hosts_frm_file(char *filename);

/**
 * This function is a wrapper function for ldns_get_rr_list_name_by_addr
 * and ldns_get_rr_list_addr_by_name. It's name is from the getaddrinfo() 
 * library call. It tries to mimic that call, but without the lowlevel
 * stuff.
 * \param[in] res The resolver. If this value is NULL then a resolver will
 * be created by ldns_getaddrinfo.
 * \param[in] node the name or ip address to look up
 * \param[in] c the class to look in
 * \param[out] list put the found RR's in this list
 * \return the number of RR found.
 */
uint16_t ldns_getaddrinfo(ldns_resolver *res, ldns_rdf *node, ldns_rr_class c, ldns_rr_list **list);

/**
 * 
 */
ldns_rr_list *ldns_getaddrinfo_secure();

/**
 * Check if t is enumerated in the nsec type rdata
 * \param[in] nsec the NSEC Record to look in
 * \param[in] t the type to check for
 * \return true when t is found, otherwise return false
 */
bool ldns_nsec_type_check(ldns_rr *nsec, ldns_rr_type t);

/*
 * Send a "simple" update for an A or an AAAA RR.
 * \param[in] fqdn the update RR owner
 * \param[in] zone the zone to update, if set to NULL, try to figure it out
 * \param[in] ipaddr the address to add, if set to NULL, remove any A/AAAA RRs
 * \param[in] ttl the update RR TTL
 * \param[in] tsig_cred credentials for TSIG-protected update messages
 */
ldns_status ldns_update_send_simple_addr(const char *fqdn, const char *zone,
    const char *ipaddr, u_int16_t tll, ldns_tsig_credentials *tsig_cred);

#endif /* _LDNS_HIGHER_H */

