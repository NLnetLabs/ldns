#include <ldns/rdata.h>

#ifndef _LDNS_WIRE2HOST_H
#define _LDNS_WIRE2HOST_H

#include <ldns/common.h>
#include <ldns/error.h>
#include <ldns/rr.h>
#include <ldns/packet.h>


/**
 * Converts the data on the uint8_t bytearray (in wire format) to a DNS packet
 * The packet structure must be initialized with ldns_pkt_new().
 * 
 * @param packet pointer to the structure to hold the packet
 * @param data pointer to the buffer with the data
 * @param len the length of the data buffer (in bytes)
 * @return LDNS_STATUS_OK if everything succeeds, error otherwise
 */
ldns_status ldns_wire2pkt(ldns_pkt **packet, const uint8_t *data, size_t len);

/**
 * Converts the data on the uint8_t bytearray (in wire format) to a DNS 
 * rdata field
 * The rdf structure must be initialized with ldns_rdf_new().
 * The length of the wiredata of this rdf is added to the *pos value.
 *
 * @param rdf pointer to the structure to hold the rdata value
 * @param data pointer to the buffer with the data
 * @param len the length of the data buffer (in bytes)
 * @param pos the position of the rdf in the buffer (ie. the number of bytes 
 *            from the start of the buffer)
 * @return LDNS_STATUS_OK if everything succeeds, error otherwise
 */
ldns_status ldns_wire2dname(ldns_rdf **dname, const uint8_t *wire, size_t max, 
                       size_t *pos);

/**
 * Converts the data on the uint8_t bytearray (in wire format) to a DNS 
 * resource records
 * The rr structure must be initialized with ldns_rr_new().
 * The length of the wiredata of this rr is added to the *pos value.
 * 
 * @param rr pointer to the structure to hold the rdata value
 * @param data pointer to the buffer with the data
 * @param len the length of the data buffer (in bytes)
 * @param pos the position of the rr in the buffer (ie. the number of bytes 
 *            from the start of the buffer)
 * @return LDNS_STATUS_OK if everything succeeds, error otherwise
 */
ldns_status ldns_wire2rr(ldns_rr **rr, const uint8_t *wire, size_t max,
                    size_t *pos, ldns_pkt_section section);

#endif

