
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

ldns_status ldns_rdf2buffer_wire(ldns_buffer *buffer, ldns_rdf *rdf);
ldns_status ldns_rr2buffer_wire(ldns_buffer *buffer, ldns_rr *rr, int section);
ldns_status ldns_pkt2buffer_wire(ldns_buffer *buffer, ldns_pkt *pkt);

#endif
