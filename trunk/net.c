/*
 * net.c
 *
 * Network implementation
 * All network related functions are grouped here
 *
 * a Net::DNS like library for C
 *
 * (c) NLnet Labs, 2004
 *
 * See the file LICENSE for the license
 */

#include <config.h>

#include <ldns/rdata.h>
#include <ldns/error.h>
#include <ldns/resolver.h>
#include <ldns/buffer.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include "util.h"



/* send off an buffer and return any reply packet
 * this is done synchronus
 *
 * sock must be opened, binded etc.
 */
ldns_pkt *
ldns_sendbuf(ldns_buffer *buf, int *sockfd, struct sockaddr *dest)
{
	struct timeval tv_s;
	struct timeval tv_e;
	ldns_pkt * new_pkt;
	int bufsize; /* bogus decl. to make it comile */
	
	assert(buf != NULL);
	assert(*sockfd != 0);

	new_pkt = NULL;

	if (sendto(*sockfd, buf, bufsize, 0, dest, 
				(socklen_t) sizeof(*dest)) != bufsize) {
		/* ai */
		return NULL;
	}
	
	return new_pkt;


}
