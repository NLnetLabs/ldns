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
#if 0
ldns_pkt * ldns_send(ldns_resolver *, ldns_pkt *);
ldns_pkt * ldns_send_udp(ldns_buffer *, const struct sockaddr *, socklen_t)
#endif

#endif  /* !_LDNS_NET_H */
