#include <ldns/rdata.h>

#ifndef _LDNS_WIRE2HOST_H
#define _LDNS_WIRE2HOST_H

#include <ldns/common.h>
#include <ldns/error.h>
#include <ldns/rr.h>
#include <ldns/packet.h>


/**
 * Converts the data on the uint8_t bytearray (in wire format) to a DNS packet
 *
 * @param data pointer to the buffer with the data
 * @param len the length of the data buffer (in bytes)
 * @param packet pointer to the structure to hold the packet
 * @return the number of bytes read from the wire
 */
ldns_status ldns_wire2pkt(ldns_pkt *packet, const uint8_t *data, size_t len);

ldns_status ldns_wire2dname(ldns_rdf **dname, const uint8_t *wire, size_t max, 
                       size_t *pos);
ldns_status ldns_wire2rr(ldns_rr *rr, const uint8_t *wire, size_t max,
                    size_t *pos, int section);

#endif

