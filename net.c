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


/**
 * send a query packet by using the stuff defined
 * in the resolver
 */
ldns_pkt *
ldns_send_pkt(ldns_resolver *r, ldns_pkt *query)
{
	/* the resolver has a lot of flags,
	 * make one giant switch the handles them */
	uint8_t config;

	struct sockaddr_in src, dest;
	int sockfd;

	/* binary */
	config = ldns_resolver_ip6(r) * 2 +
		ldns_resolver_usevc(r);

	switch(config) {
		case 0:
			/* ip4/udp */
			src.sin_family = AF_INET;
			src.sin_addr.s_addr(in_addr_t)htonl(INADDR_ANY);
			break;
		case 1:
			/* ip4/tcp */
			break;
		case 2:
			/* ip6/udp */
			break;
		case 3:
			/* ip6/tcp */
			break;
	}
	return NULL;
}


/* send off an buffer and return any reply packet
 * this is done synchronus. Send using udp
 *
 * sock must be opened, binded etc.
 */
ldns_pkt *
ldns_sendbuf_udp(ldns_buffer *buf, int *sockfd, struct sockaddr *dest)
{
	struct timeval tv_s;
	struct timeval tv_e;
	ldns_pkt * new_pkt;
	int bufsize; /* bogus decl. to make it comile */
	
	assert(buf != NULL);
	assert(*sockfd != 0);

	new_pkt = NULL;

	gettimeofday(&tv_s, NULL);

	if (sendto(*sockfd, buf, bufsize, 0, dest, 
				(socklen_t) sizeof(*dest)) != bufsize) {
		/* ai */
		return NULL;
	}

	/* there are some socket options in drill - do we need them
	 * here */
#if 0
        *reply_size = (size_t) recvfrom(sockfd, *reply, MAX_PACKET, 0, /* flags */
                        (struct sockaddr*) &src, &frmlen);
        close(sockfd);
        
        if (*reply_size == (size_t) -1) {
                return RET_FAIL;
        }
#endif
	
	gettimeofday(&tv_e, NULL);
	
	/* turn the reply into a packet? */
	
	return new_pkt;
}


/* send a buffer using tcp */
ldns_pkt *
ldns_sendbuf_tcp(ldns_buffer *buf, int *sockfd, struct sockaddr *dest)
{
	return NULL;
}

/* axfr is a hack - handle it different */
ldns_pkt *
ldns_sendbuf_axfr(ldns_buffer *buf, int *sockfd, struct sockaddr *dest)
{
	return NULL;
}
