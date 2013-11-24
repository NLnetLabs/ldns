/*
 * tsig.c
 *
 * contains the functions needed for TSIG [RFC2845]
 * and CGA-TSIG [draft-rafiee-intarea-cga-tsig-06]
 *
 * (c) 2005-2006 NLnet Labs
 * See the file LICENSE for the license
 */

#include <ldns/config.h>

#include <ldns/ldns.h>

#include <strings.h>

#ifdef HAVE_SSL
#include <openssl/hmac.h>
#include <openssl/md5.h>
#endif /* HAVE_SSL */

char *
ldns_tsig_algorithm(ldns_tsig_credentials *tc)
{
	return tc->algorithm;
}

char *
ldns_tsig_keyname(ldns_tsig_credentials *tc)
{
	return tc->keyname;
}

char *
ldns_tsig_keydata(ldns_tsig_credentials *tc)
{
	return tc->keydata;
}

char *
ldns_tsig_keyname_clone(ldns_tsig_credentials *tc)
{
	return strdup(tc->keyname);
}

char *
ldns_tsig_keydata_clone(ldns_tsig_credentials *tc)
{
	return strdup(tc->keydata);
}

/*
 *  Makes an exact copy of the wire, but with the tsig rr removed
 */
static uint8_t *
ldns_tsig_prepare_pkt_wire(uint8_t *wire, size_t wire_len, size_t *result_len)
{
	uint8_t *wire2 = NULL;
	uint16_t qd_count;
	uint16_t an_count;
	uint16_t ns_count;
	uint16_t ar_count;
	ldns_rr *rr;

	size_t pos;
	uint16_t i;

	ldns_status status;

	if(wire_len < LDNS_HEADER_SIZE) {
		return NULL;
	}
	/* fake parse the wire */
	qd_count = LDNS_QDCOUNT(wire);
	an_count = LDNS_ANCOUNT(wire);
	ns_count = LDNS_NSCOUNT(wire);
	ar_count = LDNS_ARCOUNT(wire);

	if (ar_count > 0) {
		ar_count--;
	} else {
		return NULL;
	}

	pos = LDNS_HEADER_SIZE;

	for (i = 0; i < qd_count; i++) {
		status = ldns_wire2rr(&rr, wire, wire_len, &pos, LDNS_SECTION_QUESTION);
		if (status != LDNS_STATUS_OK) {
			return NULL;
		}
		ldns_rr_free(rr);
	}

	for (i = 0; i < an_count; i++) {
		status = ldns_wire2rr(&rr, wire, wire_len, &pos, LDNS_SECTION_ANSWER);
		if (status != LDNS_STATUS_OK) {
			return NULL;
		}
		ldns_rr_free(rr);
	}

	for (i = 0; i < ns_count; i++) {
		status = ldns_wire2rr(&rr, wire, wire_len, &pos, LDNS_SECTION_AUTHORITY);
		if (status != LDNS_STATUS_OK) {
			return NULL;
		}
		ldns_rr_free(rr);
	}

	for (i = 0; i < ar_count; i++) {
		status = ldns_wire2rr(&rr, wire, wire_len, &pos,
				LDNS_SECTION_ADDITIONAL);
		if (status != LDNS_STATUS_OK) {
			return NULL;
		}
		ldns_rr_free(rr);
	}

	*result_len = pos;
	wire2 = LDNS_XMALLOC(uint8_t, *result_len);
	if(!wire2) {
		*result_len = 0; // =bugfix?
		return NULL;
	}
	memcpy(wire2, wire, *result_len);

	ldns_write_uint16(wire2 + LDNS_ARCOUNT_OFF, ar_count);

	return wire2;
}

#ifdef HAVE_SSL
static const EVP_MD *
ldns_digest_function(char *name)
{
	/* these are the mandatory algorithms from RFC4635 */
	/* The optional algorithms are not yet implemented */
	if (strcasecmp(name, "hmac-sha256.") == 0) {
#ifdef HAVE_EVP_SHA256
		return EVP_sha256();
#else
		return NULL;
#endif
	} else if (strcasecmp(name, "hmac-sha1.") == 0) {
		return EVP_sha1();
	} else if (strcasecmp(name, "hmac-md5.sig-alg.reg.int.") == 0) {
		return EVP_md5();
	} else {
		return NULL;
	}
}
#endif

#ifdef HAVE_SSL
static ldns_status
ldns_tsig_mac_new(ldns_rdf **tsig_mac, uint8_t *pkt_wire, size_t pkt_wire_size,
		const char *key_data, ldns_rdf *key_name_rdf, ldns_rdf *fudge_rdf,
		ldns_rdf *algorithm_rdf, ldns_rdf *time_signed_rdf, ldns_rdf *error_rdf,
		ldns_rdf *other_data_rdf, ldns_rdf *orig_mac_rdf, int tsig_timers_only)
{
	ldns_status status;
	char *wireformat;
	int wiresize;
	unsigned char *mac_bytes = NULL;
	unsigned char *key_bytes = NULL;
	int key_size;
	const EVP_MD *digester;
	char *algorithm_name = NULL;
	unsigned int md_len = EVP_MAX_MD_SIZE;
	ldns_rdf *result = NULL;
	ldns_buffer *data_buffer = NULL;
	ldns_rdf *canonical_key_name_rdf = NULL;
	ldns_rdf *canonical_algorithm_rdf = NULL;
	
	if (key_name_rdf == NULL || algorithm_rdf == NULL) {
		return LDNS_STATUS_NULL;
	}
	canonical_key_name_rdf  = ldns_rdf_clone(key_name_rdf);
	if (canonical_key_name_rdf == NULL) {
		return LDNS_STATUS_MEM_ERR;
	}
	canonical_algorithm_rdf = ldns_rdf_clone(algorithm_rdf);
	if (canonical_algorithm_rdf == NULL) {
		ldns_rdf_deep_free(canonical_key_name_rdf);
		return LDNS_STATUS_MEM_ERR;
	}
	/*
	 * prepare the digestable information
	 */
	data_buffer = ldns_buffer_new(LDNS_MAX_PACKETLEN);
	if (!data_buffer) {
		status = LDNS_STATUS_MEM_ERR;
		goto clean;
	}
	/* if orig_mac is not NULL, add it too */
	if (orig_mac_rdf) {
		(void) ldns_rdf2buffer_wire(data_buffer, orig_mac_rdf);
 	}
	ldns_buffer_write(data_buffer, pkt_wire, pkt_wire_size);
	if (!tsig_timers_only) {
		ldns_dname2canonical(canonical_key_name_rdf);
		(void)ldns_rdf2buffer_wire(data_buffer, 
				canonical_key_name_rdf);
		ldns_buffer_write_u16(data_buffer, LDNS_RR_CLASS_ANY);
		ldns_buffer_write_u32(data_buffer, 0);
		ldns_dname2canonical(canonical_algorithm_rdf);
		(void)ldns_rdf2buffer_wire(data_buffer, 
				canonical_algorithm_rdf);
	}
	(void)ldns_rdf2buffer_wire(data_buffer, time_signed_rdf);
	(void)ldns_rdf2buffer_wire(data_buffer, fudge_rdf);
	if (!tsig_timers_only) {
		(void)ldns_rdf2buffer_wire(data_buffer, error_rdf);
		(void)ldns_rdf2buffer_wire(data_buffer, other_data_rdf);
	}

	wireformat = (char *) data_buffer->_data;
	wiresize = (int) ldns_buffer_position(data_buffer);

	algorithm_name = ldns_rdf2str(algorithm_rdf);
	if(!algorithm_name) {
		status = LDNS_STATUS_MEM_ERR;
		goto clean;
	}

	/* prepare the key */
	key_bytes = LDNS_XMALLOC(unsigned char,
			ldns_b64_pton_calculate_size(strlen(key_data)));
	if(!key_bytes) {
		status = LDNS_STATUS_MEM_ERR;
		goto clean;
	}
	key_size = ldns_b64_pton(key_data, key_bytes,
	ldns_b64_pton_calculate_size(strlen(key_data)));
	if (key_size < 0) {
		status = LDNS_STATUS_INVALID_B64;
		goto clean;
	}
	/* hmac it */
	/* 2 spare bytes for the length */
	mac_bytes = LDNS_XMALLOC(unsigned char, md_len+2);
	if(!mac_bytes) {
		status = LDNS_STATUS_MEM_ERR;
		goto clean;
	}
	memset(mac_bytes, 0, md_len+2);

	digester = ldns_digest_function(algorithm_name);

	if (digester) {
		(void) HMAC(digester, key_bytes, key_size, (void *)wireformat,
		            (size_t) wiresize, mac_bytes + 2, &md_len);

		ldns_write_uint16(mac_bytes, md_len);
		result = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_INT16_DATA, md_len + 2,
				mac_bytes);
	} else {
		status = LDNS_STATUS_CRYPTO_UNKNOWN_ALGO;
		goto clean;
	}
	*tsig_mac = result;
	status = LDNS_STATUS_OK;
  clean:
	LDNS_FREE(mac_bytes);
	LDNS_FREE(key_bytes);
	LDNS_FREE(algorithm_name);
	ldns_buffer_free(data_buffer);
	ldns_rdf_deep_free(canonical_algorithm_rdf);
	ldns_rdf_deep_free(canonical_key_name_rdf);
	return status;
}
#endif /*  HAVE_SSL */


/**
 * frees the ldns_cga_rdfs structure and its components.
 * \param[in] rdfs pointer to the ldns_cga_rdfs structure
 */
static void
ldns_cga_rdfs_deep_free(ldns_cga_rdfs *rdfs)
{
	if (!rdfs) {
		return;
	}

	ldns_rdf_deep_free(rdfs->algo_name);
	ldns_rdf_deep_free(rdfs->type);
	ldns_rdf_deep_free(rdfs->ip_tag);
	ldns_rdf_deep_free(rdfs->modifier);
	ldns_rdf_deep_free(rdfs->prefix);
	ldns_rdf_deep_free(rdfs->coll_count);
	ldns_rdf_deep_free(rdfs->pub_key);
	ldns_rdf_deep_free(rdfs->ext_fields);
	ldns_rdf_deep_free(rdfs->sig);
	ldns_rdf_deep_free(rdfs->old_pub_key);
	ldns_rdf_deep_free(rdfs->old_sig);
	LDNS_FREE(rdfs);
}

/**
 * checks if a number of bytes are available.
 * \param[in] pos the current position
 * \param[in] count the number of bytes
 * \param[in] size the size of the buffer
 * \return boolean int indicating if it is available
 */
static int
ldns_cga_available(size_t pos, int32_t count, uint8_t size)
{
	if (count < 0) {
		return 0;
	}

	return (pos + (size_t)count <= (size_t)size);
}

/**
 * easily create RDFs from CGA-TSIG data fields.
 * \param[in] rdfs the ldns_cga_rdfs structure
 * \param[in] rdf pointer to the relevant field in rdfs
 * \param[in] data the data
 * \param[in] len the length of data (NULL if not variable)
 * \return status (OK if success)
 */
ldns_status
ldns_cga_rdf_new(ldns_cga_rdfs *rdfs, ldns_rdf **rdf, const void *data, size_t *len)
{
	ldns_rdf_type type;
	size_t size;

	if (rdf == &(rdfs->algo_name)) {
		type = LDNS_RDF_TYPE_INT16;
		size = CT_ALGO_NAME_SIZE;
	} else if (rdf == &(rdfs->type)) {
		type = LDNS_RDF_TYPE_INT16;
		size = CT_TYPE_SIZE;
	} else if (rdf == &(rdfs->ip_tag)) {
		type = LDNS_RDF_TYPE_UNKNOWN;
		size = CT_IP_TAG_SIZE;
	} else if (rdf == &(rdfs->modifier)) {
		type = LDNS_RDF_TYPE_UNKNOWN;
		size = CT_MODIFIER_SIZE;
	} else if (rdf == &(rdfs->prefix)) {
		type = LDNS_RDF_TYPE_UNKNOWN;
		size = CT_PREFIX_SIZE;
	} else if (rdf == &(rdfs->coll_count)) {
		type = LDNS_RDF_TYPE_INT8;
		size = CT_COLL_COUNT_SIZE;
	} else if (rdf == &(rdfs->pub_key)
	        || rdf == &(rdfs->ext_fields)
	        || rdf == &(rdfs->sig)
	        || rdf == &(rdfs->old_pub_key)
	        || rdf == &(rdfs->old_sig)) {
		if (!len) {
			return LDNS_STATUS_NULL;
		}
		type = LDNS_RDF_TYPE_UNKNOWN;
		size = *len;
	} else {
		return LDNS_STATUS_INVALID_POINTER;
	}

	*rdf = ldns_rdf_new_frm_data(type, size, data);

	if (!*rdf) {
		return LDNS_STATUS_MEM_ERR;
	}

	return LDNS_STATUS_OK;
}

/**
 * copies the CGA-TSIG data fields to RDFs, assuming it is at front of Other Data.
 * \param[in] other_data_rdf pointer to the Other Data RDF
 * \param[out] rdfs the output ldns_cga_rdfs structure (will be allocated)
 * \param[out] pubk the parsed RSA public key (will be allocated)
 * \param[out] opubk the parsed old RSA public key (will be allocated, or NULL if none)
 * \return status (OK if success)
 */
static ldns_status
ldns_cga_od2rdf(ldns_rdf *other_data_rdf, ldns_cga_rdfs *rdfs, RSA *pubk, RSA *opubk)
{
	uint8_t other_len, cga_tsig_len, param_len, sig_len, old_pubk_len, old_sig_len;
	uint16_t pubk_len;
	int32_t ext_len;
	uint8_t *data, *pubkp;
	uint32_t pos = 0;
	ldns_status status;

	if (!other_data_rdf) {
		return LDNS_STATUS_NULL;
	}

	other_len = (uint32_t)ldns_rdf_size(other_data_rdf);

	/* first 2 bytes encode other data's length */
	if (other_len <= 2) {
		return LDNS_STATUS_CRYPTO_TSIG_BOGUS;
	}

	/* point to the first byte of the real other data */
	data = ldns_rdf_data(other_data_rdf) + 2;
	other_len -= 2;

	/* get cga-tsig len */
	if (!ldns_cga_available(pos, CT_LEN_SIZE, other_len)) {
		return LDNS_STATUS_CRYPTO_TSIG_BOGUS;
	}

	assert(CT_LEN_SIZE == 1);

	cga_tsig_len = data[pos];

	/* check size constraints */
	if (cga_tsig_len + CT_LEN_SIZE > other_len) {
		return LDNS_STATUS_CRYPTO_TSIG_BOGUS;
	}

	/* return if no CGA-TSIG data */
	if (cga_tsig_len == 0) {
		return LDNS_STATUS_NO_DATA;
	}

	/* point to the first byte of the real CGA-TSIG data */
	data = data + CT_LEN_SIZE;
	pos = 0;

	/* allocate structure holding the RDFs */
	rdfs = LDNS_MALLOC(ldns_cga_rdfs);

	if (!rdfs) {
		return LDNS_STATUS_MEM_ERR;
	}

	/* get algorithm name */
	if (!ldns_cga_available(pos, CT_ALGO_NAME_SIZE, cga_tsig_len)) {
		LDNS_FREE(rdfs);
		return LDNS_STATUS_CRYPTO_TSIG_BOGUS;
	}

	status = ldns_cga_rdf_new(rdfs, &(rdfs->algo_name), data + pos, NULL);

	if (status != LDNS_STATUS_OK) {
		LDNS_FREE(rdfs);
		return status;
	}

	if (ldns_rdf2native_int16(rdfs->algo_name) != 0) {
		ldns_cga_rdfs_deep_free(rdfs);
		return LDNS_STATUS_CRYPTO_UNKNOWN_ALGO;
	}

	pos += CT_ALGO_NAME_SIZE;

	/* get type */
	if (!ldns_cga_available(pos, CT_TYPE_SIZE, cga_tsig_len)) {
		ldns_cga_rdfs_deep_free(rdfs);
		return LDNS_STATUS_CRYPTO_TSIG_BOGUS;
	}

	status = ldns_cga_rdf_new(rdfs, &(rdfs->type), data + pos, NULL);

	if (status != LDNS_STATUS_OK) {
		ldns_cga_rdfs_deep_free(rdfs);
		return status;
	}

	if (ldns_rdf2native_int16(rdfs->type) != 1) {
		ldns_cga_rdfs_deep_free(rdfs);
		return LDNS_STATUS_CRYPTO_UNKNOWN_ALGO;
	}

	pos += CT_TYPE_SIZE;

	/* get IP tag */
	if (!ldns_cga_available(pos, CT_IP_TAG_SIZE, cga_tsig_len)) {
		ldns_cga_rdfs_deep_free(rdfs);
		return LDNS_STATUS_CRYPTO_TSIG_BOGUS;
	}

	status = ldns_cga_rdf_new(rdfs, &(rdfs->ip_tag), data + pos, NULL);

	if (status != LDNS_STATUS_OK) {
		ldns_cga_rdfs_deep_free(rdfs);
		return status;
	}

	pos += CT_IP_TAG_SIZE;

	/* get param len */
	if (!ldns_cga_available(pos, CT_PARAM_LEN_SIZE, cga_tsig_len)) {
		ldns_cga_rdfs_deep_free(rdfs);
		return LDNS_STATUS_CRYPTO_TSIG_BOGUS;
	}

	assert(CT_PARAM_LEN_SIZE == 1);

	param_len = data[pos];

	pos += CT_PARAM_LEN_SIZE;

	// expect parameters (i.e. param_len > 0)
	if (param_len == 0 || !ldns_cga_available(pos, param_len, cga_tsig_len)) {
		ldns_cga_rdfs_deep_free(rdfs);
		return LDNS_STATUS_CRYPTO_TSIG_BOGUS;
	}

	/* get modifier */
	if (!ldns_cga_available(pos, CT_MODIFIER_SIZE, cga_tsig_len)) {
		ldns_cga_rdfs_deep_free(rdfs);
		return LDNS_STATUS_CRYPTO_TSIG_BOGUS;
	}

	status = ldns_cga_rdf_new(rdfs, &(rdfs->modifier), data + pos, NULL);

	if (status != LDNS_STATUS_OK) {
		ldns_cga_rdfs_deep_free(rdfs);
		return status;
	}

	pos += CT_MODIFIER_SIZE;

	/* get subnet prefix */
	if (!ldns_cga_available(pos, CT_PREFIX_SIZE, cga_tsig_len)) {
		ldns_cga_rdfs_deep_free(rdfs);
		return LDNS_STATUS_CRYPTO_TSIG_BOGUS;
	}

	status = ldns_cga_rdf_new(rdfs, &(rdfs->prefix), data + pos, NULL);

	if (status != LDNS_STATUS_OK) {
		ldns_cga_rdfs_deep_free(rdfs);
		return status;
	}

	pos += CT_PREFIX_SIZE;

	/* get collision count */
	if (!ldns_cga_available(pos, CT_COLL_COUNT_SIZE, cga_tsig_len)) {
		ldns_cga_rdfs_deep_free(rdfs);
		return LDNS_STATUS_CRYPTO_TSIG_BOGUS;
	}

	status = ldns_cga_rdf_new(rdfs, &(rdfs->coll_count), data + pos, NULL);

	if (status != LDNS_STATUS_OK) {
		ldns_cga_rdfs_deep_free(rdfs);
		return status;
	}

	pos += CT_COLL_COUNT_SIZE;

	/* get public key */
	ext_len = param_len - CT_MODIFIER_SIZE - CT_PREFIX_SIZE - CT_COLL_COUNT_SIZE; // max length

	// expect a public key by default (i.e. ext_len > 0)
	if (ext_len <= 0 || !ldns_cga_available(pos, ext_len, cga_tsig_len)) {
		ldns_cga_rdfs_deep_free(rdfs);
		return LDNS_STATUS_CRYPTO_TSIG_BOGUS;
	}

	// 1.2.840.113549.1.1.1 = 2A 86 48 86 F7 0D 01 01 01 (RSA ID)

	pubkp = data + pos;

	pubk = d2i_RSA_PUBKEY(NULL, (const unsigned char**)&pubkp, ext_len);

	if (!pubk) {
		ldns_cga_rdfs_deep_free(rdfs);
		return LDNS_STATUS_ERR;
	}

	pubk_len = (uint16_t)(pubkp - (data + pos));

	status = ldns_cga_rdf_new(rdfs, &(rdfs->pub_key), data + pos, (size_t*)&pubk_len);

	if (status != LDNS_STATUS_OK) {
		ldns_cga_rdfs_deep_free(rdfs);
		RSA_free(pubk);
		return status;
	}

	pos += pubk_len;

	/* get extension fields (if any) */
	ext_len -= pubk_len;

	if (ext_len > 0) {
		status = ldns_cga_rdf_new(rdfs, &(rdfs->ext_fields), data + pos, (size_t*)&ext_len);

		if (status != LDNS_STATUS_OK) {
			ldns_cga_rdfs_deep_free(rdfs);
			RSA_free(pubk);
			return status;
		}

		pos += ext_len;
	} else {
		rdfs->ext_fields = NULL;
	}

	/* get signature len */
	if (!ldns_cga_available(pos, CT_SIG_LEN_SIZE, cga_tsig_len)) {
		ldns_cga_rdfs_deep_free(rdfs);
		RSA_free(pubk);
		return LDNS_STATUS_CRYPTO_TSIG_BOGUS;
	}

	assert(CT_SIG_LEN_SIZE == 1);

	sig_len = data[pos];

	pos += CT_SIG_LEN_SIZE;

	/* get signature */
	// expect a signature (i.e. sig_len > 0)
	if (sig_len == 0 || !ldns_cga_available(pos, sig_len, cga_tsig_len)) {
		ldns_cga_rdfs_deep_free(rdfs);
		RSA_free(pubk);
		return LDNS_STATUS_CRYPTO_TSIG_BOGUS;
	}

	status = ldns_cga_rdf_new(rdfs, &(rdfs->sig), data + pos, (size_t*)&sig_len);

	if (status != LDNS_STATUS_OK) {
		ldns_cga_rdfs_deep_free(rdfs);
		RSA_free(pubk);
		return status;
	}

	pos += sig_len;

	/* get old public key len */
	if (!ldns_cga_available(pos, CT_OLD_PK_LEN_SIZE, cga_tsig_len)) {
		ldns_cga_rdfs_deep_free(rdfs);
		RSA_free(pubk);
		return LDNS_STATUS_CRYPTO_TSIG_BOGUS;
	}

	assert(CT_OLD_PK_LEN_SIZE == 1);

	old_pubk_len = data[pos];

	pos += CT_OLD_PK_LEN_SIZE;

	/* get old public key (if any) */
	if (old_pubk_len > 0) {
		if (!ldns_cga_available(pos, old_pubk_len, cga_tsig_len)) {
			ldns_cga_rdfs_deep_free(rdfs);
			RSA_free(pubk);
			return LDNS_STATUS_CRYPTO_TSIG_BOGUS;
		}

		pubkp = data + pos;

		opubk = d2i_RSA_PUBKEY(NULL, (const unsigned char**)&pubkp, old_pubk_len);

		if (!opubk) {
			ldns_cga_rdfs_deep_free(rdfs);
			RSA_free(pubk);
			return LDNS_STATUS_ERR;
		}

		if ((uint16_t)(pubkp - (data + pos)) != (uint16_t)old_pubk_len) {
			ldns_cga_rdfs_deep_free(rdfs);
			RSA_free(pubk);
			RSA_free(opubk);
			return LDNS_STATUS_CRYPTO_TSIG_BOGUS;
		}

		status = ldns_cga_rdf_new(rdfs, &(rdfs->old_pub_key), data + pos, (size_t*)&old_pubk_len);

		if (status != LDNS_STATUS_OK) {
			ldns_cga_rdfs_deep_free(rdfs);
			RSA_free(pubk);
			RSA_free(opubk);
			return status;
		}

		pos += old_pubk_len;
	} else {
		rdfs->old_pub_key = NULL;
		opubk = NULL;
	}

	/* get old signature len */
	if (!ldns_cga_available(pos, CT_OLD_SIG_LEN_SIZE, cga_tsig_len)) {
		ldns_cga_rdfs_deep_free(rdfs);
		RSA_free(pubk);
		RSA_free(opubk);
		return LDNS_STATUS_CRYPTO_TSIG_BOGUS;
	}

	assert(CT_OLD_SIG_LEN_SIZE == 1);

	old_sig_len = data[pos];

	pos += CT_OLD_SIG_LEN_SIZE;

	/* get old signature (if any) */
	if (old_sig_len > 0) {
		if (!ldns_cga_available(pos, old_sig_len, cga_tsig_len)) {
			ldns_cga_rdfs_deep_free(rdfs);
			RSA_free(pubk);
			RSA_free(opubk);
			return LDNS_STATUS_CRYPTO_TSIG_BOGUS;
		}

		status = ldns_cga_rdf_new(rdfs, &(rdfs->old_sig), data + pos, (size_t*)&old_sig_len);

		if (status != LDNS_STATUS_OK) {
			ldns_cga_rdfs_deep_free(rdfs);
			RSA_free(pubk);
			RSA_free(opubk);
			return status;
		}

		pos += old_sig_len;
	} else {
		rdfs->old_sig = NULL;
	}

	/* check size constraints */
	if (ldns_cga_available(pos, 1, cga_tsig_len)) {
			ldns_cga_rdfs_deep_free(rdfs);
			RSA_free(pubk);
			RSA_free(opubk);
			return LDNS_STATUS_CRYPTO_TSIG_BOGUS;
	}

	return LDNS_STATUS_OK;
}

/**
 * concatenates data fields.
 * \param[in] rdfs an array of pointers to the to-be-concatenated RDFs in order
 * \param[in] num the number of elements contained by rdfs
 * \param[out] buffer the output buffer (will be allocated)
 * \return status (OK if success)
 */
static ldns_status
ldns_tsig_concat_data(ldns_rdf **rdfs, uint8_t num, ldns_buffer *buffer)
{
	uint8_t i;
	uint32_t size = 0;

	if (!rdfs) {
		return LDNS_STATUS_NULL;
	}

	for (i = 0; i < num; i++) {
		if (rdfs[i]) {
			size += ldns_rdf_size(rdfs[i]);
		}
	}

	buffer = ldns_buffer_new(size);

	if (!buffer) {
		return LDNS_STATUS_MEM_ERR;
	}

	for (i = 0; i < num; i++) {
		if (rdfs[i] && ldns_rdf_size(rdfs[i]) > 0) {
			ldns_buffer_write(buffer, ldns_rdf_data(rdfs[i]), ldns_rdf_size(rdfs[i]));
		}
	}

	return LDNS_STATUS_OK;
}


/**
 * concatenates the fields that are input for the CGA signature creation and
 * verification operations (not to be confused with the CGA verification, see
 * the ldns_cga_verify() function).
 * \param[in] pkt_wire the wire without TSIG RR (message to be signed)
 * \param[in] pkt_wire_size the wire size
 * \param[in] time_signed_rdf the time signed field (all other fields defined
 *            by TSIG should probably be included too)
 * \param[in] rdfs the CGA-TSIG fields from Other Data that are to be included
 * \param[out] buffer the output buffer (will be allocated)
 * \return status (OK if success)
 */
static ldns_status
ldns_cga_concat_msg(uint8_t *pkt_wire, size_t pkt_wire_size,
		ldns_rdf *time_signed_rdf, ldns_cga_rdfs *rdfs, ldns_buffer *buffer)
{
	ldns_status status;
	ldns_rdf *wire_rdf;

	if (!pkt_wire || !time_signed_rdf || !rdfs) {
		return LDNS_STATUS_NULL;
	}

	/* temporarily encapsulate the wire in an RDF */
	wire_rdf = ldns_rdf_new(LDNS_RDF_TYPE_UNKNOWN, pkt_wire_size, pkt_wire);

	if (!wire_rdf) {
		return LDNS_STATUS_MEM_ERR;
	}

	// NOTE: no 128-bit type tag defined for CGA-TSIG

	// extension fields not mentioned in draft (but should probably be included,
	// if the parameters should be included at all; it does not conform to CGA,
  // but it propably does conform to TSIG since they are part of Other Data)
	ldns_rdf* cmpts_rdfs[7] = {rdfs->modifier,
	                           rdfs->prefix,
	                           rdfs->coll_count,
	                           rdfs->pub_key,
	                           wire_rdf,
	                           rdfs->ip_tag,
	                           time_signed_rdf};

	/* concatenate the input */
	status = ldns_tsig_concat_data(cmpts_rdfs, 7, buffer);

	if (status != LDNS_STATUS_OK) {
		buffer = NULL; // buffer has not been allocated yet
	}

	ldns_rdf_free(wire_rdf);

	return status; 
}


/**
 * copies the CGA-TSIG data fields into the Other Data RDF.
 * \param[in] rdfs the input ldns_cga_rdfs structure
 * \param[out] other_data_rdf the resulting Other Data RDF (will be allocated)
 * \return status (OK if success)
 */
static ldns_status
ldns_cga_rdf2od(ldns_cga_rdfs *rdfs, ldns_rdf *other_data_rdf)
{
	uint8_t cga_tsig_len, param_len, sig_len;
	uint8_t old_pubk_len = 0;
	uint8_t old_sig_len = 0;
	ldns_rdf *ctl_rdf, *pl_rdf, *sl_rdf, *opkl_rdf, *osl_rdf;
	ldns_buffer *buffer = NULL;
	ldns_status status = LDNS_STATUS_OK;

	/* calculate lengths */
	param_len = CT_MODIFIER_SIZE + CT_PREFIX_SIZE + CT_COLL_COUNT_SIZE
	            + ldns_rdf_size(rdfs->pub_key);
	sig_len = ldns_rdf_size(rdfs->sig);
	cga_tsig_len = CT_ALGO_NAME_SIZE + CT_TYPE_SIZE + CT_IP_TAG_SIZE + CT_PARAM_LEN_SIZE
  	             + param_len + CT_SIG_LEN_SIZE + sig_len + CT_OLD_PK_LEN_SIZE
	               + CT_OLD_SIG_LEN_SIZE;

	if (rdfs->old_pub_key) {
		old_pubk_len = ldns_rdf_size(rdfs->old_pub_key);
		cga_tsig_len += old_pubk_len;
	}
	             
	if (rdfs->old_sig) {
		old_sig_len = ldns_rdf_size(rdfs->old_sig);
		cga_tsig_len += old_sig_len;
	}

	/* temporarily encapsulate the length fields in RDFs */
	ctl_rdf = ldns_rdf_new(LDNS_RDF_TYPE_INT8, CT_LEN_SIZE, &cga_tsig_len);
	pl_rdf = ldns_rdf_new(LDNS_RDF_TYPE_INT8, CT_PARAM_LEN_SIZE, &param_len);
	sl_rdf = ldns_rdf_new(LDNS_RDF_TYPE_INT8, CT_SIG_LEN_SIZE, &sig_len);
	opkl_rdf = ldns_rdf_new(LDNS_RDF_TYPE_INT8, CT_OLD_PK_LEN_SIZE, &old_pubk_len);
	osl_rdf = ldns_rdf_new(LDNS_RDF_TYPE_INT8, CT_OLD_SIG_LEN_SIZE, &old_sig_len);

	if (!ctl_rdf || !pl_rdf || !sl_rdf || !opkl_rdf || !osl_rdf) {
		status = LDNS_STATUS_MEM_ERR;
		goto clean;
	}

	ldns_rdf* cmpts_rdfs[16] = {ctl_rdf,
	                            rdfs->algo_name,
	                            rdfs->type,
	                            rdfs->ip_tag,
	                            pl_rdf,
	                            rdfs->modifier,
	                            rdfs->prefix,
	                            rdfs->coll_count,
	                            rdfs->pub_key,
	                            rdfs->ext_fields,
	                            sl_rdf,
	                            rdfs->sig,
	                            opkl_rdf,
	                            rdfs->old_pub_key,
	                            osl_rdf,
	                            rdfs->old_sig};

	/* concatenate the fields */
	status = ldns_tsig_concat_data(cmpts_rdfs, 16, buffer);

	if (status != LDNS_STATUS_OK) {
		goto clean;
	}

	/* create the Other Data RDF */
	other_data_rdf = ldns_native2rdf_int16_data(ldns_buffer_capacity(buffer), ldns_buffer_begin(buffer));

	ldns_buffer_free(buffer);

	if (!other_data_rdf) {
		status = LDNS_STATUS_MEM_ERR;
	}

	clean:
	ldns_rdf_free(ctl_rdf);
	ldns_rdf_free(pl_rdf);
	ldns_rdf_free(sl_rdf);
	ldns_rdf_free(opkl_rdf);
	ldns_rdf_free(osl_rdf);

	return status; 
}

/**
 * performes CGA verification of an IPv6 address [RFC3972].
 * \param[in] ns the sockaddr_in6 struct containing the IP address of the remote name server
 * \param[in] param the cga parameters
 * \return status (OK if success)
 */
static ldns_status
ldns_cga_verify(struct sockaddr_in6 *ns, ldns_cga_rdfs *rdfs)
{
	ldns_status status = LDNS_STATUS_OK;
	ldns_buffer *concat = NULL;
	unsigned char hash[LDNS_SHA1_DIGEST_LENGTH], id[8];
	uint16_t i;
	unsigned char sec;

	if (!ns || !rdfs) {
		return LDNS_STATUS_NULL;
	}

	ldns_rdf* param_rdfs[5] = {rdfs->modifier,
	                           rdfs->prefix,
	                           rdfs->coll_count,
	                           rdfs->pub_key,
	                           rdfs->ext_fields};

	assert(ldns_rdf_get_type(rdfs->coll_count) == LDNS_RDF_TYPE_INT8);

	/* collision count must be 0, 1 or 2 */
	if (ldns_rdf2native_int8(rdfs->coll_count) > 2) {
		return LDNS_STATUS_CRYPTO_TSIG_BOGUS;
	}

	assert(ldns_rdf_size(rdfs->prefix) == 8);

	/* subnet prefix must match */
	if (memcmp(&ns->sin6_addr, ldns_rdf_data(rdfs->prefix), 8) != 0) {
		return LDNS_STATUS_CRYPTO_TSIG_BOGUS;
	}

	/* generate hash1 */
	status = ldns_tsig_concat_data(param_rdfs, 5, concat);

	if (status != LDNS_STATUS_OK) {
		return status; // we can return safely, concat has not been allocated yet
	}

	(void)ldns_sha1(ldns_buffer_begin(concat), ldns_buffer_capacity(concat), hash);
	memcpy(id, &ns->sin6_addr + 8, 8);

	/* extract the sec parameter */
	sec = id[0] >> 5;

	/* hash1 (first 8 octets) must match the interface ID of the address,
	 * ignoring bits 0, 1, 2, 6 and 7 of the first byte */
	hash[0] &= 0x1c;
	id[0] &= 0x1c;

	if (memcmp(hash, id, 8) != 0) {
		status = LDNS_STATUS_CRYPTO_TSIG_BOGUS;
		goto clean;
	}

	/* generate hash2 */
	memset(ldns_buffer_at(concat, 16), 0, 9);

	(void)ldns_sha1(ldns_buffer_begin(concat), ldns_buffer_capacity(concat), hash);

	/* 2*sec leftmost bytes of hash2 must be zero */
	sec *= 2;

	for (i = 0; i < sec; i++) {
		if (hash[i++] != 0 || hash[i] != 0) {
			status = LDNS_STATUS_CRYPTO_TSIG_BOGUS;
			goto clean;
		}
	}

	clean:
	ldns_buffer_free(concat);
	return status;
}


#ifdef HAVE_SSL
bool
ldns_pkt_tsig_verify(ldns_pkt *pkt, uint8_t *wire, size_t wirelen, const char *key_name,
	const char *key_data, ldns_rdf *orig_mac_rdf)
{
	if (!ldns_pkt_tsig_verify_next_2(pkt, wire, wirelen, key_name, key_data, orig_mac_rdf, NULL, 0, 0)
			!= LDNS_STATUS_OK) {
		return false;
	}
	return true;
}

ldns_status
ldns_pkt_tsig_verify_2(ldns_pkt *pkt, uint8_t *wire, size_t wirelen, const char *key_name,
	const char *key_data, ldns_rdf *orig_mac_rdf, const struct sockaddr_storage *ns_out, size_t ns_out_len)
{
	return ldns_pkt_tsig_verify_next_2(pkt, wire, wirelen, key_name, key_data, orig_mac_rdf, ns_out, ns_out_len, 0);
}


bool
ldns_pkt_tsig_verify_next(ldns_pkt *pkt, uint8_t *wire, size_t wirelen, const char* key_name,
	const char *key_data, ldns_rdf *orig_mac_rdf, int tsig_timers_only)
{
	if (ldns_pkt_tsig_verify_next_2(pkt, wire, wirelen, key_name, key_data, orig_mac_rdf, NULL, 0, tsig_timers_only)
			!= LDNS_STATUS_OK) {
		return false;
	}
	return true;
}

ldns_status
ldns_pkt_tsig_verify_next_2(ldns_pkt *pkt, uint8_t *wire, size_t wirelen, const char* key_name,
	const char *key_data, ldns_rdf *orig_mac_rdf, const struct sockaddr_storage *ns_out, size_t ns_out_len,
	int tsig_timers_only)
{
	ldns_rdf *fudge_rdf;
	ldns_rdf *algorithm_rdf;
	ldns_rdf *time_signed_rdf;
	ldns_rdf *orig_id_rdf;
	ldns_rdf *error_rdf;
	ldns_rdf *other_data_rdf;
	ldns_rdf *pkt_mac_rdf;
	ldns_rdf *my_mac_rdf;
	ldns_rdf *key_name_rdf = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, key_name);
	uint16_t pkt_id, orig_pkt_id;
	ldns_status status;
	struct sockaddr_storage *ns_in;
	size_t ns_in_len;
	struct sockaddr_in6 *out_in6, *in_in6;
	unsigned char hash[LDNS_SHA1_DIGEST_LENGTH];
	ldns_buffer *concat = NULL;
	ldns_cga_rdfs *cga_rdfs = NULL;
	RSA *pubk = NULL;
	RSA *opubk = NULL;

	uint8_t *prepared_wire = NULL;
	size_t prepared_wire_size = 0;
	char *algorithm_name = NULL;

	// save pointer to the packet's tsig rr
	ldns_rr *orig_tsig = ldns_pkt_tsig(pkt);

	if (!orig_tsig) {
		ldns_rdf_deep_free(key_name_rdf);
		return LDNS_STATUS_MEM_ERR;
	}

	if (ldns_rr_rd_count(orig_tsig) <= 6) {
		ldns_rdf_deep_free(key_name_rdf);
		return LDNS_STATUS_CRYPTO_TSIG_BOGUS;
	}	// get the contents of the rdata fields
	algorithm_rdf = ldns_rr_rdf(orig_tsig, 0);
	time_signed_rdf = ldns_rr_rdf(orig_tsig, 1); // NOTE: not being checked?
	fudge_rdf = ldns_rr_rdf(orig_tsig, 2);
	pkt_mac_rdf = ldns_rr_rdf(orig_tsig, 3);
	orig_id_rdf = ldns_rr_rdf(orig_tsig, 4);
	error_rdf = ldns_rr_rdf(orig_tsig, 5);
	other_data_rdf = ldns_rr_rdf(orig_tsig, 6);

	algorithm_name = ldns_rdf2str(algorithm_rdf);
	if(!algorithm_name) {
		ldns_rdf_deep_free(key_name_rdf);
		return LDNS_STATUS_MEM_ERR;
	}

	/* remove temporarily */
	ldns_pkt_set_tsig(pkt, NULL);
	/* temporarily change the id to the original id */
	pkt_id = ldns_pkt_id(pkt);
	orig_pkt_id = ldns_rdf2native_int16(orig_id_rdf);
	ldns_pkt_set_id(pkt, orig_pkt_id);

	// copy the wire, but with the tsig rr removed (NOTE: check if is NULL?)
	prepared_wire = ldns_tsig_prepare_pkt_wire(wire, wirelen, &prepared_wire_size);

	if (strcasecmp(algorithm_name, "cga-tsig.") == 0) {
		// NOTE: is the resolver's source IP address in ns implicitly the same?
		// answerfrom(pkt)

		/* 1. IP check (3) */
		if (!ns_out) {
			status = LDNS_STATUS_CRYPTO_TSIG_ERR;
			goto clean;
		}

		ns_in = ldns_rdf2native_sockaddr_storage(ldns_pkt_answerfrom(pkt), 0, &ns_in_len);

		if (!ns_in || ns_out_len != ns_in_len) {
			status = LDNS_STATUS_CRYPTO_TSIG_ERR;
			goto clean;
		}

#ifndef S_SPLINT_S
		if ((ns_in->ss_family != AF_INET6) || (ns_out->ss_family != AF_INET6)) {
			LDNS_FREE(ns_in);
			status = LDNS_STATUS_CRYPTO_TSIG_ERR;
			goto clean;
		}
#endif

		out_in6 = (struct sockaddr_in6*)ns_out;
		in_in6 = (struct sockaddr_in6*)ns_in;

		if (memcmp(&out_in6->sin6_addr, &in_in6->sin6_addr, LDNS_IP6ADDRLEN) != 0) {
			LDNS_FREE(ns_in);
			status = LDNS_STATUS_CRYPTO_TSIG_ERR;
			goto clean;
		}

		LDNS_FREE(ns_in);

		/* extract CGA-TSIG data fields */
		status = ldns_cga_od2rdf(other_data_rdf, cga_rdfs, pubk, opubk);

		if (status != LDNS_STATUS_OK) {
			status = LDNS_STATUS_CRYPTO_TSIG_BOGUS; // better to check for server error
			goto clean;
		}

		/* 2. CGA check (1) */
		status = ldns_cga_verify(out_in6, cga_rdfs);

		if (status != LDNS_STATUS_OK) {
			goto clean;
		}

		/* 3. signature check (4) */
		status = ldns_cga_concat_msg(prepared_wire, prepared_wire_size,
				time_signed_rdf, cga_rdfs, concat);

		if (status != LDNS_STATUS_OK) {
			goto clean;
		}

		(void)ldns_sha1(ldns_buffer_begin(concat), ldns_buffer_capacity(concat), hash);

		if (!RSA_verify(NID_sha1, hash, LDNS_SHA1_DIGEST_LENGTH,
				ldns_rdf_data(cga_rdfs->sig), ldns_rdf_size(cga_rdfs->sig), pubk)) {
			status = LDNS_STATUS_CRYPTO_TSIG_BOGUS;
			goto clean;
		} else {
			status = LDNS_STATUS_OK;
		}

		/* 4. old public key/signature steps go here */

	} else {
		// calculate the mac
		status = ldns_tsig_mac_new(&my_mac_rdf, prepared_wire, prepared_wire_size,
				key_data, key_name_rdf, fudge_rdf, algorithm_rdf,
				time_signed_rdf, error_rdf, other_data_rdf, orig_mac_rdf, tsig_timers_only);

		if (status != LDNS_STATUS_OK) {
			goto clean;
		}

		// compare the macs
		if (ldns_rdf_compare(pkt_mac_rdf, my_mac_rdf) == 0) {
			ldns_rdf_deep_free(my_mac_rdf);
			status = LDNS_STATUS_OK;
		} else {
			ldns_rdf_deep_free(my_mac_rdf);
			status = LDNS_STATUS_CRYPTO_TSIG_BOGUS;
			goto clean;
		}
	}

	clean:
	LDNS_FREE(prepared_wire);
	ldns_rdf_deep_free(key_name_rdf);

	/* Put back the values */
	/* NOTE: pkt has not been used in the meantime, remove this? */
	ldns_pkt_set_tsig(pkt, orig_tsig);
	ldns_pkt_set_id(pkt, pkt_id);

	ldns_cga_rdfs_deep_free(cga_rdfs);
	RSA_free(pubk);
	RSA_free(opubk);

	ldns_buffer_free(concat);

	return status;
}
#endif /* HAVE_SSL */

#ifdef HAVE_SSL
ldns_status
ldns_pkt_tsig_sign(ldns_pkt *pkt, const char *key_name, const char *key_data,
	uint16_t fudge, const char *algorithm_name, ldns_rdf *query_mac)
{
	return ldns_pkt_tsig_sign_next_2(pkt, key_name, key_data, NULL, NULL, NULL, NULL,
			fudge, algorithm_name, query_mac, NULL, NULL, NULL, 0, 0);
}

ldns_status
ldns_pkt_tsig_sign_2(ldns_pkt *pkt, const char *key_name, const char *key_data,
	RSA *pvt_key, RSA *pub_key, RSA *old_pvt_key, RSA *old_pub_key,
	uint16_t fudge, const char *algorithm_name, ldns_rdf *query_mac, uint8_t *ip_tag,
	uint8_t *modifier, uint8_t *prefix, size_t coll_count)
{
	return ldns_pkt_tsig_sign_next_2(pkt, key_name, key_data, pvt_key, pub_key, old_pvt_key, old_pub_key,
			fudge, algorithm_name, query_mac, ip_tag, modifier, prefix, coll_count, 0);
}

ldns_status
ldns_pkt_tsig_sign_next(ldns_pkt *pkt, const char *key_name, const char *key_data,
	uint16_t fudge, const char *algorithm_name, ldns_rdf *query_mac, int tsig_timers_only)
{
	return ldns_pkt_tsig_sign_next_2(pkt, key_name, key_data, NULL, NULL, NULL, NULL,
			fudge, algorithm_name, query_mac, NULL, NULL, NULL, 0, tsig_timers_only);
}

ldns_status
ldns_pkt_tsig_sign_next_2(ldns_pkt *pkt, const char *key_name, const char *key_data,
	RSA *pvt_key, RSA *pub_key, RSA *old_pvt_key, RSA *old_pub_key,
	uint16_t fudge, const char *algorithm_name, ldns_rdf *query_mac, uint8_t *ip_tag,
	uint8_t *modifier, uint8_t *prefix, uint8_t coll_count, int tsig_timers_only)
{
	ldns_rr *tsig_rr;
	ldns_rdf *key_name_rdf = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, key_name);
	ldns_rdf *fudge_rdf = NULL;
	ldns_rdf *orig_id_rdf = NULL;
	ldns_rdf *algorithm_rdf;
	ldns_rdf *error_rdf = NULL;
	ldns_rdf *mac_rdf = NULL;
	ldns_rdf *other_data_rdf = NULL;

	ldns_status status = LDNS_STATUS_OK;

	uint8_t *pkt_wire = NULL;
	size_t pkt_wire_len;

	struct timeval tv_time_signed;
	uint8_t *time_signed = NULL;
	ldns_rdf *time_signed_rdf = NULL;

	unsigned char hash[LDNS_SHA1_DIGEST_LENGTH];
	ldns_buffer *concat = NULL;
	ldns_cga_rdfs *cga_rdfs = NULL;
	unsigned char *pubk_buf = NULL;
	unsigned char *sig_buf = NULL;
	int pubk_len = 0;
	unsigned int sig_len = 0;

	// suppress compile warning
	RSA_free(old_pvt_key);
	old_pvt_key = NULL;
	//

	algorithm_rdf = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, algorithm_name);
	if(!key_name_rdf || !algorithm_rdf) {
		status = LDNS_STATUS_MEM_ERR;
		goto clean;
	}

	/* eww don't have create tsigtime rdf yet :( */
	/* bleh :p */
	if (gettimeofday(&tv_time_signed, NULL) == 0) {
		time_signed = LDNS_XMALLOC(uint8_t, 6);
		if(!time_signed) {
			status = LDNS_STATUS_MEM_ERR;
			goto clean;
		}
		ldns_write_uint64_as_uint48(time_signed,
				(uint64_t)tv_time_signed.tv_sec);
	} else {
		status = LDNS_STATUS_INTERNAL_ERR;
		goto clean;
	}

	time_signed_rdf = ldns_rdf_new(LDNS_RDF_TYPE_TSIGTIME, 6, time_signed);
	if(!time_signed_rdf) {
		LDNS_FREE(time_signed);
		status = LDNS_STATUS_MEM_ERR;
		goto clean;
	}

	fudge_rdf = ldns_native2rdf_int16(LDNS_RDF_TYPE_INT16, fudge);

	orig_id_rdf = ldns_native2rdf_int16(LDNS_RDF_TYPE_INT16, ldns_pkt_id(pkt));

	error_rdf = ldns_native2rdf_int16(LDNS_RDF_TYPE_INT16, 0);

	if(!fudge_rdf || !orig_id_rdf || !error_rdf) {
		status = LDNS_STATUS_MEM_ERR;
		goto clean;
	}

	if (ldns_pkt2wire(&pkt_wire, pkt, &pkt_wire_len) != LDNS_STATUS_OK) {
		status = LDNS_STATUS_ERR;
		goto clean;
	}

	if (strcasecmp(algorithm_name, "cga-tsig.") == 0) {
		if (!pvt_key || !pub_key || !ip_tag || !modifier || !prefix) {
			status = LDNS_STATUS_CRYPTO_TSIG_ERR;
			goto clean;
		}
/*
		bp = BIO_new(BIO_s_mem());

		if (!bp) {
			status = LDNS_STATUS_MEM_ERR;
			goto clean;
		}

		if (BIO_puts(key_data) <= 0) {
			status = LDNS_STATUS_CRYPTO_TSIG_ERR;
			goto clean;
		}

		pvtk = PEM_read_bio_RSAPrivateKey(bp, NULL, NULL, NULL);

		if (!pvtk) {
			status = LDNS_STATUS_CRYPTO_TSIG_ERR;
			goto clean;
		}
*/

		/* allocate structure holding the RDFs */
		cga_rdfs = LDNS_MALLOC(ldns_cga_rdfs);

		if (!cga_rdfs) {
			status = LDNS_STATUS_MEM_ERR;
			goto clean;
		}

		/* initialize */
		cga_rdfs->algo_name = NULL;
		cga_rdfs->type = NULL;

		/* set IP tag */
		status = ldns_cga_rdf_new(cga_rdfs, &(cga_rdfs->ip_tag),
				ip_tag, NULL);

		if (status != LDNS_STATUS_OK) {
			goto clean;
		}

		/* set modifier */
		status = ldns_cga_rdf_new(cga_rdfs, &(cga_rdfs->modifier),
				modifier, NULL);

		if (status != LDNS_STATUS_OK) {
			goto clean;
		}

		/* set prefix */
		status = ldns_cga_rdf_new(cga_rdfs, &(cga_rdfs->prefix),
				prefix, NULL);

		if (status != LDNS_STATUS_OK) {
			goto clean;
		}

		/* set collision count */
		status = ldns_cga_rdf_new(cga_rdfs, &(cga_rdfs->coll_count),
				&coll_count, NULL);

		if (status != LDNS_STATUS_OK) {
			goto clean;
		}

		/* convert public key */
		pubk_len = i2d_RSA_PUBKEY(pub_key, &pubk_buf);

		if (pubk_len <= 0) {
			status = LDNS_STATUS_CRYPTO_TSIG_ERR;
			goto clean;
		}

		/* set public key */
		status = ldns_cga_rdf_new(cga_rdfs, &(cga_rdfs->pub_key),
				pubk_buf, (size_t*)&pubk_len);

		if (status != LDNS_STATUS_OK) {
			goto clean;
		}

		/* initialize */
		cga_rdfs->ext_fields = NULL;
		cga_rdfs->sig = NULL;

		if (old_pub_key) {
			free(pubk_buf);
			pubk_buf = NULL;

			/* convert old public key (assuming it is also a SubjectPublicKeyInfo structure) */
			pubk_len = i2d_RSA_PUBKEY(old_pub_key, &pubk_buf);

			if (pubk_len <= 0) {
				status = LDNS_STATUS_CRYPTO_TSIG_ERR;
				goto clean;
			}

			/* set old public key */
			status = ldns_cga_rdf_new(cga_rdfs, &(cga_rdfs->old_pub_key),
					pubk_buf, (size_t*)&pubk_len);

			if (status != LDNS_STATUS_OK) {
				goto clean;
			}
		} else {
			cga_rdfs->old_pub_key = NULL;
		}

		/* initialize */
		cga_rdfs->old_sig = NULL;

		/* concatenate the message and the fields */
		status = ldns_cga_concat_msg(pkt_wire, pkt_wire_len,
				time_signed_rdf, cga_rdfs, concat);

		if (status != LDNS_STATUS_OK) {
			goto clean;
		}

		/* digest the concatenation */
		(void)ldns_sha1(ldns_buffer_begin(concat), ldns_buffer_capacity(concat), hash);

		/* sign */
		sig_buf = LDNS_XMALLOC(unsigned char, RSA_size(pvt_key));

		if (!sig_buf) {
			status = LDNS_STATUS_MEM_ERR;
			goto clean;
		}

		if (!RSA_sign(NID_sha1, hash, LDNS_SHA1_DIGEST_LENGTH,
				sig_buf, &sig_len, pvt_key)) {
			LDNS_FREE(sig_buf);
			status = LDNS_STATUS_CRYPTO_TSIG_BOGUS;
			goto clean;
		} else {
			status = LDNS_STATUS_OK;
		}

		/* set signature */
		status = ldns_cga_rdf_new(cga_rdfs, &(cga_rdfs->sig),
				sig_buf, (size_t*)&sig_len);

		LDNS_FREE(sig_buf);

		if (status != LDNS_STATUS_OK) {
			goto clean;
		}

		/* create Other Data RDF */
		status = ldns_cga_rdf2od(cga_rdfs, other_data_rdf);

		if (status != LDNS_STATUS_OK) {
			goto clean;
		}

		/* create empty mac RDF */
		mac_rdf = ldns_native2rdf_int16_data(0, NULL);
	} else {
		other_data_rdf = ldns_native2rdf_int16_data(0, NULL);

		if(!other_data_rdf) {
			status = LDNS_STATUS_MEM_ERR;
			goto clean;
		}

		status = ldns_tsig_mac_new(&mac_rdf, pkt_wire, pkt_wire_len,
				key_data, key_name_rdf, fudge_rdf, algorithm_rdf,
				time_signed_rdf, error_rdf, other_data_rdf, query_mac, tsig_timers_only);
	}

	if (!mac_rdf) {
		goto clean;
	}

	LDNS_FREE(pkt_wire);

	/* Create the TSIG RR */
	tsig_rr = ldns_rr_new();
	if(!tsig_rr) {
		status = LDNS_STATUS_MEM_ERR;
		goto clean;
	}
	ldns_rr_set_owner(tsig_rr, key_name_rdf);
	ldns_rr_set_class(tsig_rr, LDNS_RR_CLASS_ANY);
	ldns_rr_set_type(tsig_rr, LDNS_RR_TYPE_TSIG);
	ldns_rr_set_ttl(tsig_rr, 0);

	ldns_rr_push_rdf(tsig_rr, algorithm_rdf);
	ldns_rr_push_rdf(tsig_rr, time_signed_rdf);
	ldns_rr_push_rdf(tsig_rr, fudge_rdf);
	ldns_rr_push_rdf(tsig_rr, mac_rdf);
	ldns_rr_push_rdf(tsig_rr, orig_id_rdf);
	ldns_rr_push_rdf(tsig_rr, error_rdf);
	ldns_rr_push_rdf(tsig_rr, other_data_rdf);

	ldns_pkt_set_tsig(pkt, tsig_rr);

	goto end;

  clean:
	LDNS_FREE(pkt_wire);
	ldns_rdf_free(key_name_rdf);
	ldns_rdf_free(algorithm_rdf);
	ldns_rdf_free(time_signed_rdf); // should be deep_free?
	ldns_rdf_free(fudge_rdf);
	ldns_rdf_free(orig_id_rdf);
	ldns_rdf_free(error_rdf);
	ldns_rdf_free(other_data_rdf);

	end:
	ldns_cga_rdfs_deep_free(cga_rdfs);
	free(pubk_buf);
	return status;
}
#endif /* HAVE_SSL */
