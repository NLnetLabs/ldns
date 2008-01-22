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
#include <ldns/dnssec_zone.h>

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
 * Returns the first RRSIG rr that corresponds to the rrset with the given name and type
 * TODO: may be more, use all sigs...
 */
ldns_rr *ldns_dnssec_get_rrsig_for_name_and_type(const ldns_rdf *name, const ldns_rr_type type, const ldns_rr_list *rrs);

/**
 * Returns the DNSKEY that corresponds to the given RRSIG rr from the list, if
 * any
 *
 * \param[in] rrsig The rrsig to find the DNSKEY for
 * \param[in] rrs The rr list to find the key in
 * \return The DNSKEY that corresponds to the given RRSIG, or NULL if it was
 *         not found.
 */
ldns_rr *ldns_dnssec_get_dnskey_for_rrsig(const ldns_rr *rrsig, const ldns_rr_list *rrs);

/**
 * Returns the rdata field that contains the bitmap of the covered types of
 * the given NSEC record
 *
 * \param[in] nsec The nsec to get the covered type bitmap of
 * \return An ldns_rdf containing the bitmap, or NULL on error
 */
ldns_rdf *ldns_nsec_get_bitmap(ldns_rr *nsec);

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
  /* the complete rrset this rr was in */
  ldns_rr_list *rrset;
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


size_t ldns_dnssec_trust_tree_depth(ldns_dnssec_trust_tree *tree);


/**
 * Prints the dnssec_trust_tree structure to the given file stream
 * Each line is prepended by 2*tabs spaces
 * If a link status is not LDNS_STATUS_OK; the status and relevant signatures are printed too
 *
 * \param[in] *out The file stream to print to
 * \param[in] tree The trust tree to print
 * \param[in] tabs Prepend each line with tabs*2 spaces
 * \param[in] extended If true, add little explanation lines to the output
 */
void ldns_dnssec_trust_tree_print(FILE *out, ldns_dnssec_trust_tree *tree, size_t tabs, bool extended);

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
 * \param[in] *tree The tree to add the parent to
 * \param[in] *parent The parent tree to add
 * \param[in] *parent_signature The RRSIG relevant to this parent/child connection
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
ldns_dnssec_data_chain *ldns_dnssec_build_data_chain(ldns_resolver *res, const uint16_t qflags, const ldns_rr_list *data_set, const ldns_pkt *pkt, ldns_rr *orig_rr);


#define LDNS_NSEC3_MAX_ITERATIONS 65535

/** 
 * calculates a keytag of a key for use in DNSSEC.
 *
 * \param[in] key the key as an RR to use for the calc.
 * \return the keytag
 */
uint16_t ldns_calc_keytag(const ldns_rr *key);

/**
 * Calculates keytag of DNSSEC key, operates on wireformat rdata.
 * \param[in] key the key as uncompressed wireformat rdata.
 * \param[in] keysize length of key data.
 * \return the keytag
 */
uint16_t ldns_calc_keytag_raw(uint8_t* key, size_t keysize);

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
 * Like ldns_verify_rrsig_buffers, but uses raw data.
 * \param[in] sig signature data to use
 * \param[in] siglen length of signature data to use
 * \param[in] verify_buf Buffer containing data to verify
 * \param[in] key key data to use
 * \param[in] keylen length of key data to use
 * \param[in] algo Signing algorithm
 * \return status LDNS_STATUS_OK if the data verifies. Error if not.
 */
ldns_status ldns_verify_rrsig_buffers_raw(unsigned char* sig, size_t siglen, 
	ldns_buffer *verify_buf, unsigned char* key, size_t keylen, 
	uint8_t algo);

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
 * Like ldns_verify_rrsig_evp, but uses raw signature data.
 * \param[in] sig the signature data, wireformat uncompressed
 * \param[in] siglen length of the signature data
 * \param[in] rrset the rrset data, sorted and processed for verification
 * \param[in] key the EVP key structure
 * \param[in] digest_type The digest type of the signature
 */
#ifdef HAVE_SSL
ldns_status ldns_verify_rrsig_evp_raw(unsigned char *sig, size_t siglen,
	ldns_buffer *rrset, EVP_PKEY *key, const EVP_MD *digest_type);
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
/**
 * Like ldns_verify_rrsig_dsa, but uses raw signature and key data.
 * \param[in] sig raw uncompressed wireformat signature data
 * \param[in] siglen length of signature data
 * \param[in] rrset ldns buffer with prepared rrset data.
 * \param[in] key raw uncompressed wireformat key data
 * \param[in] keylen length of key data
 */
ldns_status ldns_verify_rrsig_dsa_raw(unsigned char* sig, size_t siglen,
	ldns_buffer* rrset, unsigned char* key, size_t keylen);
/**
 * Like ldns_verify_rrsig_rsasha1, but uses raw signature and key data.
 * \param[in] sig raw uncompressed wireformat signature data
 * \param[in] siglen length of signature data
 * \param[in] rrset ldns buffer with prepared rrset data.
 * \param[in] key raw uncompressed wireformat key data
 * \param[in] keylen length of key data
 */
ldns_status ldns_verify_rrsig_rsasha1_raw(unsigned char* sig, size_t siglen,
	ldns_buffer* rrset, unsigned char* key, size_t keylen);
/**
 * Like ldns_verify_rrsig_rsasha256, but uses raw signature and key data.
 * \param[in] sig raw uncompressed wireformat signature data
 * \param[in] siglen length of signature data
 * \param[in] rrset ldns buffer with prepared rrset data.
 * \param[in] key raw uncompressed wireformat key data
 * \param[in] keylen length of key data
 */
ldns_status ldns_verify_rrsig_rsasha256_raw(unsigned char* sig, size_t siglen,
	ldns_buffer* rrset, unsigned char* key, size_t keylen);
/**
 * Like ldns_verify_rrsig_rsasha512, but uses raw signature and key data.
 * \param[in] sig raw uncompressed wireformat signature data
 * \param[in] siglen length of signature data
 * \param[in] rrset ldns buffer with prepared rrset data.
 * \param[in] key raw uncompressed wireformat key data
 * \param[in] keylen length of key data
 */
ldns_status ldns_verify_rrsig_rsasha512_raw(unsigned char* sig, size_t siglen,
	ldns_buffer* rrset, unsigned char* key, size_t keylen);
/**
 * Like ldns_verify_rrsig_rsamd5, but uses raw signature and key data.
 * \param[in] sig raw uncompressed wireformat signature data
 * \param[in] siglen length of signature data
 * \param[in] rrset ldns buffer with prepared rrset data.
 * \param[in] key raw uncompressed wireformat key data
 * \param[in] keylen length of key data
 */
ldns_status ldns_verify_rrsig_rsamd5_raw(unsigned char* sig, size_t siglen,
	ldns_buffer* rrset, unsigned char* key, size_t keylen);

#ifdef HAVE_SSL
/**
 * converts a buffer holding key material to a DSA key in openssl.
 *
 * \param[in] key the key to convert
 * \return a DSA * structure with the key material
 */
DSA *ldns_key_buf2dsa(ldns_buffer *key);
/**
 * Like ldns_key_buf2dsa, but uses raw buffer.
 * \param[in] key the uncompressed wireformat of the key.
 * \param[in] len length of key data
 * \return a DSA * structure with the key material
 */
DSA *ldns_key_buf2dsa_raw(unsigned char* key, size_t len);
#endif /* HAVE_SSL */

#ifdef HAVE_SSL
/**
 * converts a buffer holding key material to a RSA key in openssl.
 *
 * \param[in] key the key to convert
 * \return a RSA * structure with the key material
 */
RSA *ldns_key_buf2rsa(ldns_buffer *key);
/**
 * Like ldns_key_buf2rsa, but uses raw buffer.
 * \param[in] key the uncompressed wireformat of the key.
 * \param[in] len length of key data
 * \return a RSA * structure with the key material
 */
RSA *ldns_key_buf2rsa_raw(unsigned char* key, size_t len);
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
 * Checks coverage of NSEC(3) RR name span
 * Remember that nsec and name must both be in canonical form (ie use
 * \ref ldns_rr2canonical and \ref ldns_dname2canonical prior to calling this
 * function)
 *
 * \param[in] nsec The NSEC RR to check
 * \param[in] name The owner dname to check, if the nsec record is a NSEC3 record, this should be the hashed name
 * \return true if the NSEC RR covers the owner name
 */
bool ldns_nsec_covers_name(const ldns_rr *nsec, const ldns_rdf *name);

/**
 * Returns the hash algorithm used in the given NSEC3 RR
 * \param[in] *nsec3_rr The RR to read from
 * \return The algorithm identifier, or 0 on error
 */
uint8_t ldns_nsec3_algorithm(const ldns_rr *nsec3_rr);

/**
 * Returns the number of hash iterations used in the given NSEC3 RR
 * \param[in] *nsec3_rr The RR to read from
 * \return The number of iterations
 */
uint16_t ldns_nsec3_iterations(const ldns_rr *nsec3_rr);

/**
 * Returns the salt used in the given NSEC3 RR
 * \param[in] *nsec3_rr The RR to read from
 * \return The salt rdf, or NULL on error
 */
ldns_rdf *ldns_nsec3_salt(const ldns_rr *nsec3_rr);

/**
 * Returns the length of the salt used in the given NSEC3 RR
 * \param[in] *nsec3_rr The RR to read from
 * \return The length of the salt in bytes
 */
uint8_t ldns_nsec3_salt_length(const ldns_rr *nsec3_rr);

/**
 * Returns the salt bytes used in the given NSEC3 RR
 * \param[in] *nsec3_rr The RR to read from
 * \return The salt in bytes, this is alloced, so you need to free it
 */
uint8_t *ldns_nsec3_salt_data(const ldns_rr *nsec3_rr);

/**
 * Returns true if the opt-out flag has been set in the given NSEC3 RR
 * \param[in] *nsec3_rr The RR to read from
 * \return true if the RR has type NSEC3 and the opt-out bit has been set, false otherwise
 */
bool ldns_nsec3_optout(const ldns_rr *nsec3_rr);

/**
 * Returns the first label of the next ownername in the NSEC3 chain (ie. without the domain)
 * \param[in] nsec3_rr The RR to read from
 * \return The first label of the next owner name in the NSEC3 chain, or NULL on error 
 */
ldns_rdf *ldns_nsec3_next_owner(const ldns_rr *nsec3_rr);

/**
 * Sets all the NSEC3 options. The rr to set them in must be initialized with _new() and
 * type LDNS_RR_TYPE_NSEC3
 * \param[in] *rr The RR to set the values in
 * \param[in] algorithm The NSEC3 hash algorithm 
 * \param[in] flags The flags field 
 * \param[in] iterations The number of hash iterations
 * \param[in] salt_length The length of the salt in bytes 
 * \param[in] salt The salt bytes
 */
void ldns_nsec3_add_param_rdfs(ldns_rr *rr, uint8_t algorithm, uint8_t flags, uint16_t iterations, uint8_t salt_length, uint8_t *salt);


/**
 * Returns the bitmap specifying the covered types of the given NSEC3 RR
 * \param[in] *nsec3_rr The RR to read from
 * \return The covered type bitmap rdf
 */
ldns_rdf *ldns_nsec3_bitmap(const ldns_rr *nsec3_rr);

/**
 * Calculates the hashed name using the parameters of the given NSEC3 RR
 * \param[in] *nsec The RR to use the parameters from
 * \param[in] *name The owner name to calculate the hash for 
 * \return The hashed owner name rdf, without the domain name
 */
ldns_rdf *ldns_nsec3_hash_name_frm_nsec3(const ldns_rr *nsec, ldns_rdf *name);

/**
 * Calculates the hashed name using the given parameters
 * \param[in] *name The owner name to calculate the hash for 
 * \param[in] algorithm The hash algorithm to use
 * \param[in] iterations The number of hash iterations to use
 * \param[in] salt_length The length of the salt in bytes
 * \param[in] salt The salt to use
 * \return The hashed owner name rdf, without the domain name
 */
ldns_rdf *ldns_nsec3_hash_name(ldns_rdf *name, uint8_t algorithm, uint16_t iterations, uint8_t salt_length, uint8_t *salt);


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
ldns_status ldns_dnssec_zone_sign(ldns_dnssec_zone *zone, ldns_rr_list *new_rrs, ldns_key_list *key_list, ldns_rr_type nsec_type);
ldns_status ldns_dnssec_zone_sign_nsec3(ldns_dnssec_zone *zone,
					   ldns_rr_list *new_rrs,
					   ldns_key_list *key_list,
					   uint8_t algorithm,
					   uint8_t flags,
					   uint16_t iterations,
					   uint8_t salt_length,
					   uint8_t *salt);
ldns_zone *ldns_zone_sign(const ldns_zone *zone, ldns_key_list *key_list);
ldns_zone *ldns_zone_sign_nsec3(ldns_zone *zone, ldns_key_list *key_list, uint8_t algorithm, uint8_t flags, uint16_t iterations, uint8_t salt_length, uint8_t *salt);
 
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
