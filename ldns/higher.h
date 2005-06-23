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
#endif /* _LDNS_HIGHER_H */

