
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
ldns_status ldns_pkt2buffer_wire(ldns_buffer *, const ldns_pkt *);
ldns_status ldns_rr_rdata2buffer_wire(ldns_buffer *, ldns_rr *);
ldns_status ldns_rrsig2buffer_wire(ldns_buffer *, ldns_rr *);
ldns_status ldns_rr_list2buffer_wire(ldns_buffer *, ldns_rr_list *);
uint8_t *ldns_rdf2wire(const ldns_rdf *, size_t *);
uint8_t *ldns_rr2wire(const ldns_rr *, int, size_t *);
uint8_t *ldns_pkt2wire(const ldns_pkt *, size_t *);



#endif
