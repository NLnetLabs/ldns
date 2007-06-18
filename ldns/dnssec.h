/*
 * dnssec.h -- defines for the Domain Name System (SEC) (DNSSEC)
 *
 * Copyright (c) 2005-2006, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 * A bunch of defines that are used in the DNS
 */

/**
 * \file dnssec.h
 *
 * This module contains functions for DNSSEC operations (RFC4033 t/m RFC4035).
 * 
 * Since those functions heavily rely op cryptographic operations, this module is
 * dependent on openssl.
 * 
 */
 

#ifndef LDNS_DNSSEC_H
#define LDNS_DNSSEC_H

#ifdef HAVE_SSL
#include <openssl/ssl.h>
#include <openssl/evp.h>
#endif /* HAVE_SSL */
#include <ldns/common.h>
#include <ldns/packet.h>
#include <ldns/keys.h>
#include <ldns/zone.h>
#include <ldns/resolver.h>

#define LDNS_MAX_KEYLEN		2048
#define LDNS_DNSSEC_KEYPROTO	3
/* default time before sigs expire */
#define LDNS_DEFAULT_EXP_TIME	2419200 /* 4 weeks */

typedef struct ldns_dnssec_data_chain_struct ldns_dnssec_data_chain;
/**
 * Chain structure that contains all DNSSEC data needed to
 * verify an rrset
 */
struct ldns_dnssec_data_chain_struct {
  ldns_rr_list *rrset;
  ldns_rr_list *signatures;
  ldns_rr_type parent_type;
  ldns_dnssec_data_chain *parent;
};

/**
 * Creates a new dnssec_chain structure
 * \return ldns_dnssec_data_chain *
 */
ldns_dnssec_data_chain *ldns_dnssec_data_chain_new();

/**
 * Frees a dnssec_data_chain structure
 *
 * \param[in] *chain The chain to free
 */
void ldns_dnssec_data_chain_free(ldns_dnssec_data_chain *chain);

/**
 * Frees a dnssec_data_chain structure, and all data contained therein
 *
 * \param[in] *chain The dnssec_data_chain to free
 */
void ldns_dnssec_data_chain_deep_free(ldns_dnssec_data_chain *chain);

/**
 * Prints the dnssec_data_chain to the given file stream
 * 
 * \param[in] *out The file stream to print to
 * \param[in] *chain The dnssec_data_chain to print
 */
void ldns_dnssec_data_chain_print(FILE *out, const ldns_dnssec_data_chain *chain);


#define LDNS_DNSSEC_TRUST_TREE_MAX_PARENTS 10

/**
 * Tree structure that contains the relation of DNSSEC data, and their cryptographic
 * status.
 *
 * This tree is derived from a data_chain, and can be used to look whether there is a
 * connection between an RRSET and a trusted key. The tree only contains pointers to
 * the data_chain, and therefore one should *never* free() the data_chain when there is
 * still a trust tree derived from that chain.
 *
 * Example tree:
 *     key   key    key
 *       \    |    /
 *        \   |   /
 *         \  |  /
 *            ds
 *            |
 *           key
 *            |
 *           key
 *            |
 *            rr
 *
 * For each signature there is a parent; if the parent pointer is null, it
 * couldn't be found and there was no denial; otherwise is a tree which
 * contains either a DNSKEY, a DS, or a NSEC rr;
 */
typedef struct ldns_dnssec_trust_tree_struct ldns_dnssec_trust_tree;
struct ldns_dnssec_trust_tree_struct {
  ldns_rr *rr;
  ldns_dnssec_trust_tree *parents[LDNS_DNSSEC_TRUST_TREE_MAX_PARENTS];
  ldns_status parent_status[LDNS_DNSSEC_TRUST_TREE_MAX_PARENTS];
  /** for debugging, add signatures too (you might want those if they 
     contain errors) */
  ldns_rr *parent_signature[LDNS_DNSSEC_TRUST_TREE_MAX_PARENTS];
  size_t parent_count;
};

/**
 * Creates a new (empty) dnssec_trust_tree structure
 *
 * \return ldns_dnssec_trust_tree *
 */
ldns_dnssec_trust_tree *ldns_dnssec_trust_tree_new();
/**
 * Frees the dnssec_trust_tree recursively
 * There is no deep free; all data in the trust tree consists of pointers
 * to a data_chain
 *
 * \param[in] tree The tree to free
 */
void ldns_dnssec_trust_tree_free(ldns_dnssec_trust_tree *tree);

/**
 * Prints the dnssec_trust_tree structure to the given file stream
 * Each line is prepended by 2*tabs spaces
 * If a link status is not LDNS_STATUS_OK; the status and relevant signatures are printed too
 *
 * \param[in] *out The file stream to print to
 * \param[in] tree The trust tree to print
 * \param[in] tabs Prepend each line with tabs*2 spaces
 */
void ldns_dnssec_trust_tree_print(FILE *out, ldns_dnssec_trust_tree *tree, size_t tabs);

/**
 * Generates a dnssec_trust_ttree for the given rr from the given data_chain
 * Don't free the data_chain before you are done with this tree
 *
 * \param[in] *data_chain The chain to derive the trust tree from
 * \param[in] *rr The RR this tree will be about
 * \return ldns_dnssec_trust_tree *
 */
ldns_dnssec_trust_tree *ldns_dnssec_derive_trust_tree(ldns_dnssec_data_chain *data_chain, ldns_rr *rr);

/**
 * Adds a trust tree as a parent for the given trust tree
 *
 * \param[in] tree The tree to add the parent to
 * \param[in] parent_tree The parent tree to add
 * \param[in] parent_signature The RRSIG relevant to this parent/child connection
 * \param[in] parent_status The DNSSEC status for this parent, child and RRSIG
 * \return LDNS_STATUS_OK if the addition succeeds, error otherwise
 */
ldns_status
ldns_dnssec_trust_tree_add_parent(ldns_dnssec_trust_tree *tree,
                                  const ldns_dnssec_trust_tree *parent,
                                  const ldns_rr *parent_signature,
                                  const ldns_status parent_status);

/**
 * Returns OK if there is a trusted path in the tree to one of the DNSKEY or DS RRs in the
 * given list
 *
 * \param *tree The trust tree so search
 * \param *keys A ldns_rr_list of DNSKEY and DS rrs to look for
 * \return LDNS_STATUS_OK if there is a trusted path to one of the keys, or the *first* error encountered
 *         if there were no paths
 */
ldns_status ldns_dnssec_trust_tree_contains_keys(ldns_dnssec_trust_tree *tree, ldns_rr_list *keys);


/**
 * the data set will be cloned
 * the pkt is optional, can contain the original packet (and hence the sigs and maybe the key)
 */
ldns_dnssec_data_chain *ldns_dnssec_build_data_chain(ldns_resolver *res, const uint16_t qflags, const ldns_rr_list *data_set, const ldns_pkt *pkt);


/** 
 * calculates a keytag of a key for use in DNSSEC.
 *
 * \param[in] key the key as an RR to use for the calc.
 * \return the keytag
 */
uint16_t ldns_calc_keytag(const ldns_rr *key);

/**
 * Verifies a list of signatures for one rrset.
 *
 * \param[in] rrset the rrset to verify
 * \param[in] rrsig a list of signatures to check
 * \param[in] keys a list of keys to check with
 * \param[out] good_keys  if this is a (initialized) list, the keys from keys that validate one of the signatures are added to it
 * \return status LDNS_STATUS_OK if there is at least one correct key
 */
ldns_status ldns_verify(ldns_rr_list *rrset, ldns_rr_list *rrsig, const ldns_rr_list *keys, ldns_rr_list *good_keys);	

/**
 * Verifies the already processed data in the buffers
 * This function should probably not be used directly.
 *
 * \param[in] rawsig_buf Buffer containing signature data to use
 * \param[in] verify_buf Buffer containing data to verify
 * \param[in] key_buf Buffer containing key data to use
 * \param[in] algo Signing algorithm
 * \return status LDNS_STATUS_OK if the data verifies. Error if not.
 */
ldns_status ldns_verify_rrsig_buffers(ldns_buffer *rawsig_buf, ldns_buffer *verify_buf, ldns_buffer *key_buf, uint8_t algo);

/**
 * Verifies an rrsig. All keys in the keyset are tried.
 * \param[in] rrset the rrset to check
 * \param[in] rrsig the signature of the rrset
 * \param[in] keys the keys to try
 * \param[out] good_keys  if this is a (initialized) list, the keys from keys that validate one of the signatures are added to it
 * \return a list of keys which validate the rrsig + rrset. Return NULL when none of the keys validate.
 */
ldns_status ldns_verify_rrsig_keylist(ldns_rr_list *rrset, ldns_rr *rrsig, const ldns_rr_list *keys, ldns_rr_list *good_keys);

/**
 * verify an rrsig with 1 key
 * \param[in] rrset the rrset
 * \param[in] rrsig the rrsig to verify
 * \param[in] key the key to use
 * \return status message wether verification succeeded.
 */
ldns_status ldns_verify_rrsig(ldns_rr_list *rrset, ldns_rr *rrsig, ldns_rr *key);

/**
 * verifies a buffer with signature data for a buffer with rrset data 
 * with an EVP_PKEY
 *
 * \param[in] sig the signature data
 * \param[in] rrset the rrset data, sorted and processed for verification
 * \param[in] key the EVP key structure
 * \param[in] digest_type The digest type of the signature
 */
#ifdef HAVE_SSL
ldns_status ldns_verify_rrsig_evp(ldns_buffer *sig, ldns_buffer *rrset, EVP_PKEY *key, const EVP_MD *digest_type);
#endif

/**
 * verifies a buffer with signature data (DSA) for a buffer with rrset data 
 * with a buffer with key data.
 *
 * \param[in] sig the signature data
 * \param[in] rrset the rrset data, sorted and processed for verification
 * \param[in] key the key data
 */
ldns_status ldns_verify_rrsig_dsa(ldns_buffer *sig, ldns_buffer *rrset, ldns_buffer *key);
/**
 * verifies a buffer with signature data (RSASHA1) for a buffer with rrset data 
 * with a buffer with key data.
 *
 * \param[in] sig the signature data
 * \param[in] rrset the rrset data, sorted and processed for verification
 * \param[in] key the key data
 */
ldns_status ldns_verify_rrsig_rsasha1(ldns_buffer *sig, ldns_buffer *rrset, ldns_buffer *key);
/**
 * verifies a buffer with signature data (RSAMD5) for a buffer with rrset data 
 * with a buffer with key data.
 *
 * \param[in] sig the signature data
 * \param[in] rrset the rrset data, sorted and processed for verification
 * \param[in] key the key data
 */
ldns_status ldns_verify_rrsig_rsamd5(ldns_buffer *sig, ldns_buffer *rrset, ldns_buffer *key);

#ifdef HAVE_SSL
/**
 * converts a buffer holding key material to a DSA key in openssl.
 *
 * \param[in] key the key to convert
 * \return a DSA * structure with the key material
 */
DSA *ldns_key_buf2dsa(ldns_buffer *key);
#endif /* HAVE_SSL */

#ifdef HAVE_SSL
/**
 * converts a buffer holding key material to a RSA key in openssl.
 *
 * \param[in] key the key to convert
 * \return a RSA * structure with the key material
 */
RSA *ldns_key_buf2rsa(ldns_buffer *key);
#endif /* HAVE_SSL */

/** 
 * returns a new DS rr that represents the given key rr.
 *
 * \param[in] *key the key to convert
 * \param[in] h the hash to use LDNS_SHA1/LDNS_SHA256
 * \return ldns_rr* a new rr pointer to a DS
 */
ldns_rr *ldns_key_rr2ds(const ldns_rr *key, ldns_hash h);

/* sign functions */

/**
 * Sign an rrset
 * \param[in] rrset the rrset
 * \param[in] keys the keys to use
 * \return a rr_list with the signatures
 */
ldns_rr_list *ldns_sign_public(ldns_rr_list *rrset, ldns_key_list *keys);

#ifdef HAVE_SSL
/**
 * Sign a buffer with the DSA key (hash with SHA1)
 * \param[in] to_sign buffer with the data
 * \param[in] key the key to use
 * \return a ldns_rdf with the signed data
 */
ldns_rdf *ldns_sign_public_dsa(ldns_buffer *to_sign, DSA *key);
ldns_rdf *ldns_sign_public_evp(ldns_buffer *to_sign, EVP_PKEY *key, const EVP_MD *digest_type);
/**
 * Sign a buffer with the RSA key (hash with MD5)
 * \param[in] to_sign buffer with the data
 * \param[in] key the key to use
 * \return a ldns_rdf with the signed data
 */
ldns_rdf *ldns_sign_public_rsamd5(ldns_buffer *to_sign, RSA *key);
/**
 * Sign a buffer with the RSA key (hash with SHA1)
 * \param[in] to_sign buffer with the data
 * \param[in] key the key to use
 * \return a ldns_rdf with the signed data
 */
ldns_rdf *ldns_sign_public_rsasha1(ldns_buffer *to_sign, RSA *key);
#endif /* HAVE_SSL */

/**
 * Create a NSEC record
 * \param[in] cur_owner the current owner which should be taken as the starting point
 * \param[in] next_owner the rrlist which the nsec rr should point to 
 * \param[in] rrs all rrs from the zone, to find all RR types of cur_owner in
 * \return a ldns_rr with the nsec record in it
 */
ldns_rr * ldns_create_nsec(ldns_rdf *cur_owner, ldns_rdf *next_owner, ldns_rr_list *rrs);

/**
 * Checks coverage of NSEC RR type bitmap
 * \param[in] nsec_bitmap The NSEC bitmap rdata field to check
 * \param[in] type The type to check
 * \return true if the NSEC RR covers the type
 */
bool ldns_nsec_bitmap_covers_type(const ldns_rdf *nsec_bitmap, ldns_rr_type type);

/**
 * Checks coverage of NSEC RR name span
 * Remember that nsec and name must both be in canonical form (ie use
 * \ref ldns_rr2canonical and \ref ldns_dname2canonical prior to calling this
 * function)
 *
 * \param[in] nsec The NSEC RR to check
 * \param[in] name The owner dname to check
 * \return true if the NSEC RR covers the owner name
 */
bool ldns_nsec_covers_name(const ldns_rr *nsec, const ldns_rdf *name);

/**
 * verify a packet 
 * \param[in] p the packet
 * \param[in] t the rr set type to check
 * \param[in] o the rr set name to ckeck
 * \param[in] k list of keys
 * \param[in] s list of sigs (may be null)
 * \param[out] good_keys keys which validated the packet
 * \return status 
 * 
 */
ldns_status ldns_pkt_verify(ldns_pkt *p, ldns_rr_type t, ldns_rdf *o, ldns_rr_list *k, ldns_rr_list *s, ldns_rr_list *good_keys);

/**
 * signs the given zone with the given new zone
 * returns a newly allocated signed zone
 * extra arguments will come later (expiration etc.)
 *
 * \param[in] zone the zone to sign
 * \param[in] key_list the list of keys to sign the zone with
 * \return the signed zone
 */
ldns_zone *ldns_zone_sign(const ldns_zone *zone, ldns_key_list *key_list);

/**
 * Initialize the random function. This calls OpenSSL
 * \param[in] fd a file providing entropy data
 * \param[in] bytes number of bytes for the seed
 * \return LDNS_STATUS_OK if init succeeds
 */
ldns_status ldns_init_random(FILE *fd, uint16_t bytes);

/**
 * Tries to build an authentication chain from the given keys down to the queried domain.
 *
 * If we find a valid trust path, return the valid keys for the domain.
 * 
 * \param[in] res the current resolver
 * \param[in] domain the domain we want valid keys for
 * \param[in] keys the current set of trusted keys
 * \param[out] status pointer to the status variable where the result code will be stored
 * \return the set of trusted keys for the domain, or NULL if no trust path could be built.
 */
ldns_rr_list *
ldns_fetch_valid_domain_keys(const ldns_resolver * res, const ldns_rdf * domain, const ldns_rr_list * keys, ldns_status *status);

/**
 * Validates the DNSKEY RRset for the given domain using the provided trusted keys.
 *
 * \param[in] res the current resolver
 * \param[in] domain the domain we want valid keys for
 * \param[in] keys the current set of trusted keys
 * \return the set of trusted keys for the domain, or NULL if the RRSET could not be validated
 */
ldns_rr_list *
ldns_validate_domain_dnskey (const ldns_resolver * res, const ldns_rdf * domain, const ldns_rr_list * keys);

/**
 * Validates the DS RRset for the given domain using the provided trusted keys.
 *
 * \param[in] res the current resolver
 * \param[in] domain the domain we want valid keys for
 * \param[in] keys the current set of trusted keys
 * \return the set of trusted keys for the domain, or NULL if the RRSET could not be validated
 */
ldns_rr_list *
ldns_validate_domain_ds (const ldns_resolver * res, const ldns_rdf * domain, const ldns_rr_list * keys);

/**
 * Verifies a list of signatures for one RRset using a valid trust path.
 *
 * \param[in] res the current resolver
 * \param[in] rrset the rrset to verify
 * \param[in] rrsigs a list of signatures to check
 * \param[out] validating_keys  if this is a (initialized) list, the keys from keys that validate one of the signatures are added to it
 * \return status LDNS_STATUS_OK if there is at least one correct key
 */
ldns_status
ldns_verify_trusted(ldns_resolver * res, ldns_rr_list * rrset, ldns_rr_list * rrsigs, ldns_rr_list * validating_keys);


#endif /* LDNS_DNSSEC_H */
