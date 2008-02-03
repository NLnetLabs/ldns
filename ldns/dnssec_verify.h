/** dnssec_verify */

#ifndef LDNS_DNSSEC_VERIFY_H
#define LDNS_DNSSEC_VERIFY_H

#include <ldns/dnssec.h>

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
	ldns_pkt_rcode packet_rcode;
	ldns_rr_type packet_qtype;
	bool packet_nodata;
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


#endif

