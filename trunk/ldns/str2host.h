
#ifndef _LDNS_STR2HOST_H
#define _LDNS_STR2HOST_H

#include <ldns/common.h>
#include <ldns/error.h>
#include <ldns/rr.h>
#include <ldns/rdata.h>
#include <ldns/packet.h>
#include <ldns/buffer.h>
#include <ctype.h>

ldns_status ldns_conv_int8(ldns_rdf **, const uint8_t *);
ldns_status ldns_conv_int16(ldns_rdf **, const uint8_t *);
ldns_status ldns_conv_int32(ldns_rdf **, const uint8_t *);
ldns_status ldns_conv_time(ldns_rdf **, const uint8_t *);

#endif
