/*
 * net.h
 *
 * DNS Resolver definitions
 *
 * a Net::DNS like library for C
 *
 * (c) NLnet Labs, 2004, 2005
 *
 * See the file LICENSE for the license
 */

#ifndef _LDNS_NET_H
#define _LDNS_NET_H

#include <ldns/packet.h>
#include <ldns/buffer.h>
#include <ldns/resolver.h>
#include <ldns/keys.h>

#include <sys/socket.h>

#define LDNS_DEFAULT_TIMEOUT_SEC 5
#define LDNS_DEFAULT_TIMEOUT_USEC 0


/**
 * Sends a buffer to an ip using udp and return the respons as a ldns_pkt
 * \param[in] qbin the ldns_buffer to be send
 * \param[in] to the ip addr to send to
 * \param[in] tolen length of the ip addr
 * \param[in] timeout the timeout value for the network
 * \param[out] answersize size of the packet
 * \param[out] result packet with the answer
 * \return status
 */
ldns_status ldns_udp_send(uint8_t **result, ldns_buffer *qbin, const struct sockaddr_storage *to, socklen_t tolen, struct timeval timeout, size_t *answersize);

/**
 * Sends a buffer to an ip using tcp and return the respons as a ldns_pkt
 * \param[in] qbin the ldns_buffer to be send
 * \param[in] qbin the ldns_buffer to be send
 * \param[in] to the ip addr to send to
 * \param[in] tolen length of the ip addr
 * \param[in] timeout the timeout value for the network
 * \param[out] answersize size of the packet
 * \param[out] result packet with the answer
 * \return status
 */
ldns_status ldns_tcp_send(uint8_t **result, ldns_buffer *qbin, const struct sockaddr_storage *to, socklen_t tolen, struct timeval timeout, size_t *answersize);

/**
 * Sends ptk to the nameserver at the resolver object. Returns the data
 * as a ldns_pkt
 * 
 * \param[out] pkt packet received from the nameserver
 * \param[in] r the resolver to use 
 * \param[in] query_pkt the query to send
 * \return status
 */
ldns_status ldns_send(ldns_pkt **pkt, ldns_resolver *r, ldns_pkt *query_pkt);

/**
 * Create a tcp socket to the specified address
 * \param[in] to ip and family
 * \param[in] tolen length of to
 * \param[in] timeout timeout for the socket
 * \return a socket descriptor
 */
int ldns_tcp_connect(const struct sockaddr_storage *to, socklen_t tolen, struct timeval timeout);

/**
 * Create a udp socket to the specified address
 * \param[in] to ip and family
 * \param[in] timeout timeout for the socket
 * \return a socket descriptor
 */
int ldns_udp_connect(const struct sockaddr_storage *to, struct timeval timeout);

/**
 * Create a udp socket to the specified address and bind it too (making it
 * a server socket)
 * \param[in] to ip and family
 * \param[in] timeout timeout for the socket
 * \return a socket descriptor
 */
int ldns_udp_server_connect(const struct sockaddr_storage *to, struct timeval timeout);

/**
 * send a query via tcp to a server. Don;t want for the answer
 *
 * \param[in] qbin the buffer to send
 * \param[in] sockfd the socket to use
 * \param[in] to which ip to send it
 * \param[in] tolen socketlen
 * \return number of bytes sent
 */
ssize_t ldns_tcp_send_query(ldns_buffer *qbin, int sockfd, const struct sockaddr_storage *to, socklen_t tolen);

/**
 * send a query via udp to a server. Don;t want for the answer
 *
 * \param[in] qbin the buffer to send
 * \param[in] sockfd the socket to use
 * \param[in] to which ip to send it
 * \param[in] tolen socketlen
 * \return number of bytes sent
 */
ssize_t ldns_udp_send_query(ldns_buffer *qbin, int sockfd, const struct sockaddr_storage *to, socklen_t tolen);
/**
 * Gives back a raw packet from the wire and reads the header data from the given
 * socket. Allocates the data (of size size) itself, so don't forget to free
 *
 * \param[in] sockfd the socket to read from
 * \param[out] size the number of bytes that are read
 * \return the data read
 */
uint8_t *ldns_tcp_read_wire(int sockfd, size_t *size);

/**
 * Gives back a raw packet from the wire and reads the header data from the given
 * socket. Allocates the data (of size size) itself, so don't forget to free
 *
 * \param[in] sockfd the socket to read from
 * \param[in] fr the address of the client (if applicable)
 * \param[in] *frlen the lenght of the client's addr (if applicable)
 * \param[out] size the number of bytes that are read
 * \return the data read
 */
uint8_t *ldns_udp_read_wire(int sockfd, size_t *size, struct sockaddr_storage *fr, socklen_t *frlen);

#endif  /* !_LDNS_NET_H */
