/*
 * edns.h
 *
 *
 * a Net::DNS like library for C
 *
 * (c) NLnet Labs, 2004-2022
 *
 * See the file LICENSE for the license
 */

#ifndef LDNS_EDNS_H
#define LDNS_EDNS_H

#include <ldns/common.h>

#ifdef __cplusplus
extern "C" {
#endif



/**
 * EDNS option codes
 */
enum ldns_enum_edns_option
{
    LDNS_EDNS_LLQ = 1, /* http://files.dns-sd.org/draft-sekar-dns-llq.txt */
    LDNS_EDNS_UL = 2, /* http://files.dns-sd.org/draft-sekar-dns-ul.txt */
    LDNS_EDNS_NSID = 3, /* RFC5001 */
    /* 4 draft-cheshire-edns0-owner-option */
    LDNS_EDNS_DAU = 5, /* RFC6975 */
    LDNS_EDNS_DHU = 6, /* RFC6975 */
    LDNS_EDNS_N3U = 7, /* RFC6975 */
    LDNS_EDNS_CLIENT_SUBNET = 8, /* RFC7871 */
    LDNS_EDNS_KEEPALIVE = 11, /* draft-ietf-dnsop-edns-tcp-keepalive*/
    LDNS_EDNS_PADDING = 12, /* RFC7830 */
    LDNS_EDNS_EDE = 15, /* RFC8914 */
    LDNS_EDNS_CLIENT_TAG = 16 /* draft-bellis-dnsop-edns-tags-01 */
};
typedef enum ldns_enum_edns_option ldns_edns_option_code;

/**
 * 
 * An EDNS option is structed as follows:
                   +0 (MSB)                            +1 (LSB)
       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    0: |                          OPTION-CODE                          |
       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    2: |                         OPTION-LENGTH                         |
       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    4: |                                                               |
       /                          OPTION-DATA                          /
       /                                                               /
       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 *
 * 
 * @TODO write this
 */
struct ldns_struct_edns_option {
        ldns_edns_option_code _code;
        size_t                _size;
        void                 *_data;
};
typedef struct ldns_struct_edns_option ldns_edns_option;


/* 
 * 
 * @TODO write this
 */
struct ldns_struct_edns_option_list
{
    size_t _option_count;
    size_t _rr_capacity; // ???
    ldns_rr **_options;
};
typedef struct ldns_struct_edns_option_list edns_option_list;

/*
 * Access functions 
 * do this as functions to get type checking
 */

/**
 * returns the size of the EDNS data.
 * \param[in] *edns the EDNS struct to read from
 * \return uint16_t with the size
 */
size_t ldns_edns_get_size(const ldns_edns_option *edns);

/**
 * returns the size of the EDNS data.
 * \param[in] *edns the EDNS struct to read from
 * \return uint16_t with the size
 */
ldns_edns_option_code ldns_edns_get_code(const ldns_edns_option *edns);

/**
 * returns the EDNS option data.
 * \param[in] *edns the rdf to read from
 * \return uint8_t* pointer to the rdf's data
 */
uint8_t *ldns_edns_get_data(const ldns_edns_option *edns);


/**
 * allocates a new EDNS structure and fills it.
 * This function DOES NOT copy the contents from
 * the buffer, unlike ldns_rdf_new_frm_data()
 * \param[in] type type of the rdf
 * \param[in] size size of the buffer
 * \param[in] data pointer to the buffer to be copied
 * \return the new rdf structure or NULL on failure
 */
ldns_edns_option *ldns_edns_new(ldns_edns_option_code code, size_t size, void *data);

#ifdef __cplusplus
}
#endif

#endif /* LDNS_EDNS_H */