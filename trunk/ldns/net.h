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

#include <ldns/packet.h>
#include <ldns/buffer.h>
#include <ldns/resolver.h>

#include <sys/socket.h>

#define LDNS_DEFAULT_TIMEOUT_SEC 5
#define LDNS_DEFAULT_TIMEOUT_USEC 0


/* prototypes */
ldns_pkt * ldns_send_udp(ldns_buffer *, const struct sockaddr_storage *, socklen_t);
ldns_pkt * ldns_send_tcp(ldns_buffer *, const struct sockaddr_storage *, socklen_t);
ldns_pkt * ldns_send(ldns_resolver *, ldns_pkt *);

int ldns_tcp_connect(const struct sockaddr_storage *to, socklen_t tolen);
ssize_t ldns_tcp_send_query(ldns_buffer *qbin, int sockfd, const struct sockaddr_storage *to, socklen_t tolen);
ldns_pkt *ldns_tcp_read_packet(int sockfd);

#endif  /* !_LDNS_NET_H */
