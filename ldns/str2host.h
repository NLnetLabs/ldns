
#ifndef _LDNS_2HOST_H
#define _LDNS_2HOST_H

#include <ldns/common.h>
#include <ldns/error.h>
#include <ldns/rr.h>
#include <ldns/rdata.h>
#include <ldns/packet.h>
#include <ldns/buffer.h>
#include <ctype.h>

ldns_status ldns_str2rdf_int8(ldns_rdf **, const uint8_t *);
ldns_status ldns_str2rdf_int16(ldns_rdf **, const uint8_t *);
ldns_status ldns_str2rdf_int32(ldns_rdf **, const uint8_t *);
ldns_status ldns_str2rdf_time(ldns_rdf **, const uint8_t *);
ldns_status ldns_str2rdf_a(ldns_rdf **, const uint8_t*);
ldns_status ldns_str2rdf_aaaa(ldns_rdf **, const uint8_t*);
ldns_status ldns_str2rdf_str(ldns_rdf **, const uint8_t*);
ldns_status ldns_str2rdf_apl(ldns_rdf **, const uint8_t*);
ldns_status ldns_str2rdf_b64(ldns_rdf **, const uint8_t*);
ldns_status ldns_str2rdf_hex(ldns_rdf **, const uint8_t*);
ldns_status ldns_str2rdf_nsec(ldns_rdf **, const uint8_t*);
ldns_status ldns_str2rdf_type(ldns_rdf **, const uint8_t*);
ldns_status ldns_str2rdf_class(ldns_rdf **, const uint8_t*);
ldns_status ldns_str2rdf_cert(ldns_rdf **, const uint8_t*);
ldns_status ldns_str2rdf_alg(ldns_rdf **, const uint8_t*);
ldns_status ldns_str2rdf_unknown(ldns_rdf **, const uint8_t*);
ldns_status ldns_str2rdf_tsigtime(ldns_rdf **, const uint8_t*);
ldns_status ldns_str2rdf_service(ldns_rdf **, const uint8_t*);
ldns_status ldns_str2rdf_loc(ldns_rdf **, const uint8_t*);
ldns_status ldns_str2rdf_wks(ldns_rdf **, const uint8_t*);
ldns_status ldns_str2rdf_nsap(ldns_rdf **, const uint8_t*);

ldns_status ldns_str2rdf_dname(ldns_rdf **, const uint8_t*);

#endif
