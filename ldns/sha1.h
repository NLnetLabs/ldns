#ifndef LDNS_SHA1_H
#define LDNS_SHA1_H
 
#define LDNS_SHA1_BLOCK_LENGTH               64
#define LDNS_SHA1_DIGEST_LENGTH              20

typedef struct {
        u_int32_t       state[5];
        u_int64_t       count;
        unsigned char   buffer[LDNS_SHA1_BLOCK_LENGTH];
} ldns_sha1_ctx;
  
void ldns_sha1_init(ldns_sha1_ctx * context);
void ldns_sha1_transform(u_int32_t state[5], const unsigned char buffer[LDNS_SHA1_BLOCK_LENGTH]);
void ldns_sha1_update(ldns_sha1_ctx *context, const unsigned char *data, unsigned int len);
void ldns_sha1_final(unsigned char digest[LDNS_SHA1_DIGEST_LENGTH], ldns_sha1_ctx *context);

/**
 * Convenience function to digest a fixed block of data at once.
 * This function will allocate LDNS_SHA1_DIGEST_LENGTH of data,
 * which needs to be freed (with a simple free()) by the caller
 *
 * \param[in] data the data to digest
 * \param[in] data_len the length of data in bytes
 * \return the SHA1 digest of the given data
 */
unsigned char *ldns_sha1(unsigned char *data, unsigned int data_len);
#endif /* LDNS_SHA1_H */
