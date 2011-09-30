/*
 * dnssec_nsec4.h -- defines for the Domain Name System (SEC) (DNSSEC)
 *
 * Copyright (c) 2011, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 * A bunch of defines that are used in the DNS
 */

/**
 * \file dnssec_nsec4.h
 *
 * This module contains base functions for DNSSEC operations, specific for
 * NSEC4.
 *
 * Since those functions heavily rely op cryptographic operations,
 * this module is dependent on openssl.
 *
 */


#ifndef LDNS_DNSSEC_NSEC4_H
#define LDNS_DNSSEC_NSEC4_H

#include <ldns/common.h>
#if LDNS_BUILD_CONFIG_HAVE_SSL
#include <openssl/ssl.h>
#include <openssl/evp.h>
#endif /* LDNS_BUILD_CONFIG_HAVE_SSL */
#include <ldns/packet.h>
#include <ldns/keys.h>
#include <ldns/zone.h>
#include <ldns/resolver.h>
#include <ldns/dnssec_zone.h>

#ifdef __cplusplus
extern "C" {
#endif

#if LDNS_BUILD_CONFIG_USE_NSEC4
#define LDNS_NSEC4_MAX_ITERATIONS 65535


/**
 * Returns the dname of the closest (provable) encloser
 */
ldns_rdf *
ldns_dnssec_nsec4_closest_encloser(ldns_rdf *qname,
                                                        ldns_rr_type qtype,
                                                        ldns_rr_list *nsec4s);

/**
 * Creates NSEC4.
 */
ldns_rr *
ldns_dnssec_create_nsec4(ldns_dnssec_name *from,
					ldns_dnssec_name *to,
					ldns_rdf *zone_name,
					uint8_t algorithm,
					uint8_t flags,
					uint16_t iterations,
					uint8_t salt_length,
					uint8_t *salt);
/**
 * Sets all the NSEC4 options. The rr to set them in must be initialized with _new() and
 * type LDNS_RR_TYPE_NSEC4
 * \param[in] *rr The RR to set the values in
 * \param[in] algorithm The NSEC4 hash algorithm
 * \param[in] flags The flags field
 * \param[in] iterations The number of hash iterations
 * \param[in] salt_length The length of the salt in bytes
 * \param[in] salt The salt bytes
 */
void ldns_nsec4_add_param_rdfs(ldns_rr *rr,
						 uint8_t algorithm,
						 uint8_t flags,
						 uint16_t iterations,
						 uint8_t salt_length,
						 uint8_t *salt);

/* this will NOT return the NSEC4 completed, you will have to run the
   finalize function on the rrlist later! */
ldns_rr *
ldns_create_nsec4(ldns_rdf *cur_owner,
                  ldns_rdf *cur_zone,
                  ldns_rr_list *rrs,
                  uint8_t algorithm,
                  uint8_t flags,
                  uint16_t iterations,
                  uint8_t salt_length,
                  uint8_t *salt,
                  bool emptynonterminal);

/**
 * Returns the hash algorithm used in the given NSEC4 RR
 * \param[in] *nsec4_rr The RR to read from
 * \return The algorithm identifier, or 0 on error
 */
uint8_t ldns_nsec4_algorithm(const ldns_rr *nsec4_rr);

/**
 * Returns flags field
 */
uint8_t ldns_nsec4_flags(const ldns_rr *nsec4_rr);

/**
 * Returns true if the opt-out flag has been set in the given NSEC4 RR
 * \param[in] *nsec4_rr The RR to read from
 * \return true if the RR has type NSEC4 and the opt-out bit has been set, false otherwise
 */
bool ldns_nsec4_optout(const ldns_rr *nsec4_rr);

/**
 * Returns true if the wildcard flag has been set in the given NSEC4 RR
 * \param[in] *nsec4_rr The RR to read from
 * \return true if the RR has type NSEC4 and the wildcard bit has been set, false otherwise
 */
bool ldns_nsec4_wildcard(const ldns_rr *nsec4_rr);

/**
 * Returns the number of hash iterations used in the given NSEC4 RR
 * \param[in] *nsec4_rr The RR to read from
 * \return The number of iterations
 */
uint16_t ldns_nsec4_iterations(const ldns_rr *nsec4_rr);

/**
 * Returns the salt used in the given NSEC4 RR
 * \param[in] *nsec4_rr The RR to read from
 * \return The salt rdf, or NULL on error
 */
ldns_rdf *ldns_nsec4_salt(const ldns_rr *nsec4_rr);

/**
 * Returns the length of the salt used in the given NSEC4 RR
 * \param[in] *nsec4_rr The RR to read from
 * \return The length of the salt in bytes
 */
uint8_t ldns_nsec4_salt_length(const ldns_rr *nsec4_rr);

/**
 * Returns the salt bytes used in the given NSEC4 RR
 * \param[in] *nsec4_rr The RR to read from
 * \return The salt in bytes, this is alloced, so you need to free it
 */
uint8_t *ldns_nsec4_salt_data(const ldns_rr *nsec4_rr);

/**
 * Returns the first label of the next ownername in the NSEC4 chain (ie. without the domain)
 * \param[in] nsec4_rr The RR to read from
 * \return The first label of the next owner name in the NSEC4 chain, or NULL on error 
 */
ldns_rdf *ldns_nsec4_next_owner(const ldns_rr *nsec4_rr);

/**
 * Returns the bitmap specifying the covered types of the given NSEC4 RR
 * \param[in] *nsec4_rr The RR to read from
 * \return The covered type bitmap rdf
 */
ldns_rdf *ldns_nsec4_bitmap(const ldns_rr *nsec4_rr);

/**
 * Calculates the hashed name using the parameters of the given NSEC4 RR
 * \param[in] *nsec The RR to use the parameters from
 * \param[in] *name The owner name to calculate the hash for 
 * \return The hashed owner name rdf, without the domain name
 */
ldns_rdf *ldns_nsec4_hash_name_frm_nsec4(const ldns_rr *nsec, ldns_rdf *name);

/**
 * Find particular name.
 * \param[in] zone dnssec zone
 * \param[in] name name to find
 * \param[in] start_node node to start searching for
 * \return ldns_dnssec_name* the name if found
 *
 */
ldns_dnssec_name*
ldns_nsec4_dnssec_name_find(ldns_dnssec_zone* zone, ldns_rdf* name,
        ldns_rbnode_t* start_node);


/**
 * Mark wildcard bits.
 * \param[in] zone dnssec zone
 * \return ldns_status status
 *
 */
ldns_status ldns_dnssec_zone_set_wildcard_bits(ldns_dnssec_zone* zone);

/**
 * chains NSEC4 list
 */
ldns_status
ldns_dnssec_chain_nsec4_list(ldns_rr_list *nsec4_rrs);

/**
 * compare for NSEC4 sort
 */
int
qsort_rr_compare_nsec4(const void *a, const void *b);

/**
 * sort NSEC4 list
 */
void
ldns_rr_list_sort_nsec4(ldns_rr_list *unsorted);

#endif /* LDNS_BUILD_CONFIG_USE_NSEC4 */

#ifdef __cplusplus
}
#endif

#endif /* LDNS_DNSSEC_NSEC4_H */
