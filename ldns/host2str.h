
#ifndef _LDNS_HOST2STR_H
#define _LDNS_HOST2STR_H

#include <ldns/common.h>
#include <ldns/error.h>
#include <ldns/rr.h>
#include <ldns/rdata.h>
#include <ldns/packet.h>
#include <ldns/buffer.h>
#include <ctype.h>

#include "util.h"

ldns_status ldns_rdf2buffer_str(ldns_buffer *, ldns_rdf *);
ldns_status ldns_rr2buffer_str(ldns_buffer *, ldns_rr *);
ldns_status ldns_pkt2buffer_str(ldns_buffer *, ldns_pkt *);
ldns_status ldns_rdf2buffer_str_int16(ldns_buffer *, ldns_rdf *);
char *ldns_rdf2str(ldns_rdf *);
char *ldns_rr2str(ldns_rr *);
char *ldns_pkt2str(ldns_pkt *);
char *buffer2str(ldns_buffer *);



#endif
