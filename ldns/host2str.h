
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

ldns_status ldns_rdf2buffer(ldns_buffer *buffer, ldns_rdf *rdf);
ldns_status ldns_rr2buffer(ldns_buffer *buffer, ldns_rr *rr);
ldns_status ldns_pkt2buffer(ldns_buffer *buffer, ldns_pkt *pkt);
char *ldns_rdf2str(ldns_rdf *);
char *ldns_rr2str(ldns_rr *);
char *ldns_pkt2str(ldns_pkt *);

#endif
