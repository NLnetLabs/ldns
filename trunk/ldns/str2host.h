
#ifndef _LDNS_2HOST_H
#define _LDNS_2HOST_H

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
ldns_status ldns_conv_none(ldns_rdf **, const uint8_t* );
ldns_status ldns_conv_dname(ldns_rdf **, const uint8_t*);
ldns_status ldns_conv_a(ldns_rdf **, const uint8_t*);
ldns_status ldns_conv_aaaa(ldns_rdf **, const uint8_t*);
ldns_status ldns_conv_str(ldns_rdf **, const uint8_t*);
ldns_status ldns_conv_apl(ldns_rdf **, const uint8_t*);
ldns_status ldns_conv_b64(ldns_rdf **, const uint8_t*);
ldns_status ldns_conv_hex(ldns_rdf **, const uint8_t*);
ldns_status ldns_conv_nsec(ldns_rdf **, const uint8_t*);
ldns_status ldns_conv_type(ldns_rdf **, const uint8_t*);
ldns_status ldns_conv_class(ldns_rdf **, const uint8_t*);
ldns_status ldns_conv_cert(ldns_rdf **, const uint8_t*);
ldns_status ldns_conv_alg(ldns_rdf **, const uint8_t*);
ldns_status ldns_conv_unknown(ldns_rdf **, const uint8_t*);
ldns_status ldns_conv_tsigtime(ldns_rdf **, const uint8_t*);
ldns_status ldns_conv_service(ldns_rdf **, const uint8_t*);
ldns_status ldns_conv_loc(ldns_rdf **, const uint8_t*);
ldns_status ldns_conv_wks(ldns_rdf **, const uint8_t*);
ldns_status ldns_conv_nsap(ldns_rdf **, const uint8_t*);

#endif
