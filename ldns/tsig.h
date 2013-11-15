/*
 * tsig.h -- defines for TSIG [RFC2845]
 *
 * Copyright (c) 2005-2008, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 */

#ifndef LDNS_TSIG_H
#define LDNS_TSIG_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 *
 * Defines functions for TSIG usage
 */


/**
 * Contains credentials for TSIG
*/
typedef struct ldns_tsig_credentials_struct
{
    char *algorithm;
    char *keyname;
    char *keydata;
    /* XXX More eventually. */
} ldns_tsig_credentials;


/**
 * Contains parameters for CGA
*/
typedef struct ldns_cga_parameters_struct
{
    char modifier[16];
    unsigned char subnet_prefix[8];
    unsigned char collision_count;
		int public_key_len;
    char *public_key;
		int extension_fields_len;
    char *extension_fields;
} ldns_cga_parameters;


char *ldns_tsig_algorithm(ldns_tsig_credentials *);
char *ldns_tsig_keyname(ldns_tsig_credentials *);
char *ldns_tsig_keydata(ldns_tsig_credentials *);
char *ldns_tsig_keyname_clone(ldns_tsig_credentials *);
char *ldns_tsig_keydata_clone(ldns_tsig_credentials *);

/**
 * verifies the tsig rr for the given packet and key.
 * The wire must be given too because tsig does not sign normalized packets.
 * \param[in] pkt the packet to verify
 * \param[in] wire needed to verify the mac
 * \param[in] wire_size size of wire
 * \param[in] key_name the name of the shared key
 * \param[in] key_data the key in base 64 format
 * \param[in] mac original mac
 * \return true if tsig is correct, false if not, or if tsig is not set
 */
bool ldns_pkt_tsig_verify(ldns_pkt *pkt, uint8_t *wire, size_t wire_size, const char *key_name, const char *key_data, ldns_rdf *mac);

/**
 * verifies the tsig rr for the given packet and key.
 * The wire must be given too because tsig does not sign normalized packets.
 * \param[in] pkt the packet to verify
 * \param[in] wire needed to verify the mac
 * \param[in] wire_size size of wire
 * \param[in] key_name the name of the shared key
 * \param[in] key_data the key in base 64 format
 * \param[in] mac original mac
 * \return LDNS_STATUS_OK if tsig is correct, error status otherwise
 */
ldns_status ldns_pkt_tsig_verify_ws(ldns_pkt *pkt, uint8_t *wire, size_t wire_size, const char *key_name, const char *key_data, ldns_rdf *mac);

/**
 * verifies the tsig rr for the given packet and key.
 * The wire must be given too because tsig does not sign normalized packets.
 * \param[in] pkt the packet to verify
 * \param[in] wire needed to verify the mac
 * \param[in] wire_size size of wire
 * \param[in] key_name the name of the shared key
 * \param[in] key_data the key in base 64 format
 * \param[in] mac original mac
 * \param[in] tsig_timers_only must be zero for the first packet and positive for subsequent packets. If zero, all digest
   components are used to verify the _mac. If non-zero, only the TSIG timers are used to verify the mac.
 * \return true if tsig is correct, false if not, or if tsig is not set
 */
bool ldns_pkt_tsig_verify_next(ldns_pkt *pkt, uint8_t *wire, size_t wire_size, const char *key_name, const char *key_data, ldns_rdf *mac,
    int tsig_timers_only);

/**
 * creates a tsig rr for the given packet and key.
 * \param[in] pkt the packet to sign
 * \param[in] key_name the name of the shared key
 * \param[in] key_data the key in base 64 format
 * \param[in] fudge seconds of error permitted in time signed
 * \param[in] algorithm_name the name of the algorithm used
 * \param[in] query_mac is added to the digest if not NULL (so NULL is for signing queries, not NULL is for signing answers)
 * \return status (OK if success)
 */
ldns_status ldns_pkt_tsig_sign(ldns_pkt *pkt, const char *key_name, const char *key_data, uint16_t fudge,
    const char *algorithm_name, ldns_rdf *query_mac);

/**
 * creates a tsig rr for the given packet and key.
 * \param[in] pkt the packet to sign
 * \param[in] key_name the name of the shared key
 * \param[in] key_data the key in base 64 format
 * \param[in] fudge seconds of error permitted in time signed
 * \param[in] algorithm_name the name of the algorithm used
 * \param[in] query_mac is added to the digest if not NULL (so NULL is for signing queries, not NULL is for signing answers)
 * \param[in] tsig_timers_only must be zero for the first packet and positive for subsequent packets. If zero, all digest
   components are used to create the query_mac. If non-zero, only the TSIG timers are used to create the query_mac.
 * \return status (OK if success)
 */
ldns_status ldns_pkt_tsig_sign_next(ldns_pkt *pkt, const char *key_name, const char *key_data, uint16_t fudge,
    const char *algorithm_name, ldns_rdf *query_mac, int tsig_timers_only);

/**
 * concatenates cga parameters.
 * \param[out] buffer the output buffer (should be NULL pointer, will be dynamically allocated)
 * \param[out] len the buffer length (should be pointer to int)
 * \param[in] param the cga parameters
 * \return status (OK if success)
 */
ldns_status ldns_concat_cga_parameters(unsigned char *buffer, int *len, ldns_cga_parameters *param);

/**
 * performes cga verification [RFC3972].
 * \param[in] ns the sockaddr_in6 struct containing the ip address of the remote name server
 * \param[in] param the cga parameters
 * \return status (OK if success)
 */
ldns_status ldns_cga_verify(struct sockaddr_in6 *ns, ldns_cga_parameters *param);

#ifdef __cplusplus
}
#endif

#endif /* LDNS_TSIG_H */
