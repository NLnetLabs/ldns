#include <ldns/rdata.h>

#ifndef _LDNS_HOST2STR_H
#define _LDNS_HOST2STR_H

#include <ldns/common.h>
#include <ldns/error.h>
#include <ldns/rr.h>
#include <ldns/packet.h>
#include <ldns/buffer.h>
#include <ctype.h>

char *ldns_rdf2str(ldns_rdf *rdf);

#endif

