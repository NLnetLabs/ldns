
#ifndef _LDNS_STR2HOST_H
#define _LDNS_STR2HOST_H

#include <ldns/common.h>
#include <ldns/error.h>
#include <ldns/rr.h>
#include <ldns/rdata.h>
#include <ldns/packet.h>
#include <ldns/buffer.h>
#include <ctype.h>

ldns_status zparser_conv_short(ldns_rdf *, const char *);
ldns_status zparser_conv_time(ldns_rdf *, const char *);

#endif
