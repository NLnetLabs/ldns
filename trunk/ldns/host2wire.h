
#ifndef _LDNS_HOST2WIRE_H
#define _LDNS_HOST2WIRE_H

#include <ldns/common.h>
#include <ldns/error.h>
#include <ldns/rr.h>
#include <ldns/rdata.h>
#include <ldns/packet.h>
#include <ldns/buffer.h>
#include <ctype.h>

#include "util.h"

ldns_status ldns_rdf2buffer_wire(ldns_buffer *, const ldns_rdf *);
ldns_status ldns_rr2buffer_wire(ldns_buffer *, const ldns_rr *, int);

/**
 * Converts a rrsig to wireformat BUT EXCLUDE the rrsig rdata
 * This is needed in DNSSEC verification
 * \param[out] output buffer to append the result to
 * \param[in] sigrr signature rr to operate on
 * \return ldns_status
 */
ldns_status ldns_rrsig2buffer_wire(ldns_buffer *output, ldns_rr *sigrr);

/**
 * Converts an rr's rdata to wireformat, while excluding
 * the ownername and all the crap before the rdata.
 * This is needed in DNSSEC keytag calculation, the ds
 * calcalution from the key and maybe elsewhere.
 *
 * \param[out] *output buffer where to put the result
 * \param[in] *rr rr to operate on
 * \return ldns_status
 */
ldns_status ldns_rr_rdata2buffer_wire(ldns_buffer *output, ldns_rr *rr);

/**
 * Copies the packet data to the buffer in wire format
 * \param[out] *output buffer to append the result to
 * \param[in] *pkt packet to convert
 * \return ldns_status
 */
ldns_status ldns_pkt2buffer_wire(ldns_buffer *output, const ldns_pkt *pkt);


ldns_status ldns_rr_list2buffer_wire(ldns_buffer *, ldns_rr_list *);

/**
 * Allocates an array of uint8_t at dest, and puts the wireformat of the
 * given rdf in that array. The result_size value contains the
 * length of the array, if it succeeds, and 0 otherwise (in which case
 * the function also returns NULL)
 *
 * \param[out] dest pointer to the array of bytes to be created
 * \param[in] rdf the rdata field to convert
 * \param[out] size the size of the converted result
 */
ldns_status ldns_rdf2wire(uint8_t **dest, const ldns_rdf *rdf, size_t *size);

/**
 * Allocates an array of uint8_t at dest, and puts the wireformat of the
 * given rr in that array. The result_size value contains the
 * length of the array, if it succeeds, and 0 otherwise (in which case
 * the function also returns NULL)
 *
 * If the section argument is LDNS_SECTION_QUESTION, data like ttl and rdata
 * are not put into the result
 *
 * \param[out] dest pointer to the array of bytes to be created
 * \param[in] rr the rr to convert
 * \param[out] size the size of the converted result
 */
ldns_status ldns_rr2wire(uint8_t **dest, const ldns_rr *rr, int, size_t *size);

/**
 * Allocates an array of uint8_t at dest, and puts the wireformat of the
 * given packet in that array. The result_size value contains the
 * length of the array, if it succeeds, and 0 otherwise (in which case
 * the function also returns NULL)
 */
ldns_status ldns_pkt2wire(uint8_t **dest, const ldns_pkt *, size_t *);

#endif
