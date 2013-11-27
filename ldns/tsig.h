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


#define CT_LEN_SIZE          1
#define CT_ALGO_NAME_SIZE    2
#define CT_TYPE_SIZE         2
#define CT_IP_TAG_SIZE       16
#define CT_PARAM_LEN_SIZE    1
#define CT_MODIFIER_SIZE     CT_IP_TAG_SIZE
#define CT_PREFIX_SIZE       8
#define CT_COLL_COUNT_SIZE   1
#define CT_SIG_LEN_SIZE      1
#define CT_OLD_PK_LEN_SIZE   1
#define CT_OLD_SIG_LEN_SIZE  1


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
 * Contains RDFs for fields in CGA-TSIG other data
*/
typedef struct ldns_cga_rdfs_struct
{
		ldns_rdf *algo_name;
		ldns_rdf *type;
		ldns_rdf *ip_tag;
		ldns_rdf *modifier;
		ldns_rdf *prefix;
		ldns_rdf *coll_count;
		ldns_rdf *pub_key;     // the complete encoded SubjectPublicKeyInfo block
		ldns_rdf *ext_fields;
		ldns_rdf *sig;
		ldns_rdf *old_pub_key;
		ldns_rdf *old_sig;
} ldns_cga_rdfs;


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
 * \param[in] ns structure with the IP of the queried remote resolver (for CGA-TSIG)
 * \param[in] ns_len size of ns (for CGA-TSIG)
 * \return LDNS_STATUS_OK if tsig is correct, error status otherwise
 */
ldns_status ldns_pkt_tsig_verify_2(ldns_pkt *pkt, uint8_t *wire, size_t wire_size, const char *key_name, const char *key_data, ldns_rdf *mac,
    const struct sockaddr_storage *ns, size_t ns_len);

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
 * verifies the tsig rr for the given packet and key.
 * The wire must be given too because tsig does not sign normalized packets.
 * \param[in] pkt the packet to verify
 * \param[in] wire needed to verify the mac
 * \param[in] wire_size size of wire
 * \param[in] key_name the name of the shared key
 * \param[in] key_data the key in base 64 format
 * \param[in] mac original mac
 * \param[in] ns structure with the IP of the queried remote resolver (for CGA-TSIG)
 * \param[in] ns_len size of ns (for CGA-TSIG)
 * \param[in] tsig_timers_only must be zero for the first packet and positive for subsequent packets. If zero, all digest
   components are used to verify the _mac. If non-zero, only the TSIG timers are used to verify the mac.
 * \return LDNS_STATUS_OK if tsig is correct, error status otherwise
 */
ldns_status ldns_pkt_tsig_verify_next_2(ldns_pkt *pkt, uint8_t *wire, size_t wire_size, const char *key_name, const char *key_data, ldns_rdf *mac,
    const struct sockaddr_storage *ns, size_t ns_len, int tsig_timers_only);

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
 * \param[in] pvt_key the private key (for CGA-TSIG)
 * \param[in] pub_key the associated public key (for CGA-TSIG)
 * \param[in] old_pvt_key the old private key (NULL if not applicable; for CGA-TSIG)
 * \param[in] old_pub_key the associated old public key (NULL if not applicable; for CGA-TSIG)
 * \param[in] fudge seconds of error permitted in time signed
 * \param[in] algorithm_name the name of the algorithm used
 * \param[in] query_mac is added to the digest if not NULL (so NULL is for signing queries, not NULL is for signing answers)
 * \param[in] ip_tag the IP tag (NULL if not applicable; for CGA-TSIG)
 * \param[in] modifier the CGA modifier (for CGA-TSIG)
 * \param[in] prefix the network prefix of the host's IPv6 address (for CGA-TSIG)
 * \param[in] coll_count the CGA collision count (for CGA-TSIG)
 * \param[in] request_only do not sign but only request the resolver to sign (for CGA-TSIG)
 * \return status (OK if success)
 */
ldns_status ldns_pkt_tsig_sign_2(ldns_pkt *pkt, const char *key_name, const char *key_data,
    RSA *pvt_key, RSA *pub_key, RSA *old_pvt_key, RSA *old_pub_key,
    uint16_t fudge, const char *algorithm_name, ldns_rdf *query_mac, uint8_t *ip_tag,
    uint8_t *modifier, uint8_t *prefix, size_t coll_count, int request_only);

/**
 * creates a tsig rr for the given packet and key.
 * \param[in] pkt the packet to sign
 * \param[in] key_name the name of the shared key
 * \param[in] key_data the key in base 64 format (in PEM format for CGA-TSIG), must be null-terminated
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
 * creates a tsig rr for the given packet and key.
 * \param[in] pkt the packet to sign
 * \param[in] key_name the name of the shared key
 * \param[in] key_data the key in base 64 format
 * \param[in] pvt_key the private key (for CGA-TSIG)
 * \param[in] pub_key the associated public key (for CGA-TSIG)
 * \param[in] old_pvt_key the old private key (NULL if not applicable; for CGA-TSIG)
 * \param[in] old_pub_key the associated old public key (NULL if not applicable; for CGA-TSIG)
 * \param[in] fudge seconds of error permitted in time signed
 * \param[in] algorithm_name the name of the algorithm used
 * \param[in] query_mac is added to the digest if not NULL (so NULL is for signing queries, not NULL is for signing answers)
 * \param[in] ip_tag the IP tag (NULL if not applicable; for CGA-TSIG)
 * \param[in] modifier the CGA modifier (for CGA-TSIG)
 * \param[in] prefix the network prefix of the host's IPv6 address (for CGA-TSIG)
 * \param[in] coll_count the CGA collision count (for CGA-TSIG)
 * \param[in] request_only do not sign but only request the resolver to sign (for CGA-TSIG)
 * \param[in] tsig_timers_only must be zero for the first packet and positive for subsequent packets. If zero, all digest
   components are used to create the query_mac. If non-zero, only the TSIG timers are used to create the query_mac.
 * \return status (OK if success)
 */
ldns_status ldns_pkt_tsig_sign_next_2(ldns_pkt *pkt, const char *key_name, const char *key_data,
    RSA *pvt_key, RSA *pub_key, RSA *old_pvt_key, RSA *old_pub_key,
    uint16_t fudge, const char *algorithm_name, ldns_rdf *query_mac, uint8_t *ip_tag,
    uint8_t *modifier, uint8_t *prefix, uint8_t coll_count, int request_only, int tsig_timers_only);

#ifdef __cplusplus
}
#endif

#endif /* LDNS_TSIG_H */
