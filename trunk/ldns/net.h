/*
 * net.h
 *
 * DNS Resolver definitions
 *
 * a Net::DNS like library for C
 *
 * (c) NLnet Labs, 2004
 *
 * See the file LICENSE for the license
 */

#ifndef _LDNS_NET_H
#define _LDNS_NET_H

#include <ldns/error.h>
#include <ldns/common.h>
#include <ldns/rr.h>
#include <ldns/rdata.h>
#include <ldns/packet.h>

/* prototypes */
ldns_pkt * ldns_send(ldns_resolver *, ldns_pkt *);
ldns_buffer * ldns_send_udp(ldns_buffer *, const struct sockaddr *, socklen_t)

#endif  /* !_LDNS_NET_H */
