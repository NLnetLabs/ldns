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
#include <ldns/wire2host.h>
#include <ldns/host2wire.h>
#include <ldns/host2str.h>
#include <ldns/resolver.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <errno.h>

#include "util.h"


extern int errno;

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

/**
 * Send to ptk to the nameserver at ipnumber. Return the data
 * as a ldns_pkt
 * \param[in] resolver to use 
 * \param[in] query to send
 * \return the pkt received from the nameserver
 */
ldns_pkt *
ldns_send(ldns_resolver *r, ldns_pkt *query_pkt)
{
	uint8_t i;
	
	struct sockaddr_storage *ns;
	struct sockaddr_in *ns4;
	struct sockaddr_in6 *ns6;
	socklen_t ns_len;

	ldns_rdf **ns_array;
	ldns_pkt *reply;
	ldns_buffer *qb;

	ns_array = ldns_resolver_nameservers(r);
	reply = NULL;
	
	printf("we are in ldns_send()\n");
	qb = ldns_buffer_new(MAX_PACKET_SIZE);

	if (ldns_pkt2buffer_wire(qb, query_pkt) != LDNS_STATUS_OK) {
		printf("could not convert to wire fmt\n");
		return NULL;
	}

	printf("nameservers %d\n",ldns_resolver_nameserver_count(r));
	
	/* loop through all defined nameservers */
	for (i = 0; i < ldns_resolver_nameserver_count(r); i++) {

		ns = ldns_rdf2native_sockaddr_storage(ns_array[i]);
		ns_len = (socklen_t) ldns_rdf_size(ns_array[i]);

		/* setup some family specific stuff */
#if 0
		switch(ns->ss_family) {
			case AF_INET:
				ns4 = (struct sockaddr_in*) ns;
				ns4->sin_port = htons(ldns_resolver_port(r));
				printf("port %d\n", ntohs(ns4->sin_port));
				break;
			case AF_INET6:
				ns6 = (struct sockaddr_in6*) ns;
				ns6->sin6_port = htons(ldns_resolver_port(r));
				printf("port %d\n", ntohs(ns6->sin6_port));
				break;
		}
#endif

		printf("ip address len %d\n", ns_len);

		/* query */
		reply = ldns_send_udp(qb, ns, ns_len);
		
		if (reply) {
			printf("reply found\n");
			break;
		}
	}
	return reply;
}


/**
 */
ldns_pkt *
ldns_send_udp(ldns_buffer *qbin, const struct sockaddr_storage *to, socklen_t tolen)
{
	int sockfd;
	ssize_t bytes;
	uint8_t *answer;
	ldns_pkt *answer_pkt;
	struct sockaddr_in *to4;

	struct in_addr *b;

	b = (struct in_addr *) to;

	printf("family %d [4=%d %d] [6=%d %d]\n", ((struct sockaddr*)to)->sa_family,
			AF_INET, PF_INET, AF_INET6, PF_INET6);
	
	if ((sockfd = socket(((struct sockaddr*)to)->sa_family, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
		printf("could not open socket\n");
		return NULL;
	}

	to4 = (struct sockaddr_in*) to;

	printf("port %d len %d\n", 
			ntohs(to4->sin_port), tolen);
	printf("address %s\n", inet_ntoa(*b));

	bytes =  sendto(sockfd, ldns_buffer_begin(qbin),
			ldns_buffer_capacity(qbin), 0, (struct sockaddr *)to, tolen);

	if (bytes == -1) {
		printf("error with sending: %s\n", strerror(errno));
		close(sockfd);
		return NULL;
	}

	if ((size_t) bytes != ldns_buffer_capacity(qbin)) {
		printf("amount mismatch\n");
		close(sockfd);
		return NULL;
	}
	
	/* wait for an response*/
	answer = XMALLOC(uint8_t, MAX_PACKET_SIZE);
	if (!answer) {
		printf("respons alloc error\n");
		return NULL;
	}

	bytes = recv(sockfd, answer, MAX_PACKET_SIZE, 0);

	close(sockfd);

	if (bytes == -1) {
		printf("received too little\n");
		FREE(answer);
		return NULL;
	}
	
	/* resize accordingly */
	XREALLOC(answer, uint8_t *, (size_t) bytes);

        if (ldns_wire2pkt(&answer_pkt, answer, (size_t) bytes) != 
			LDNS_STATUS_OK) {
		printf("could not create packet\n");
		return NULL;
	} else {
		return answer_pkt;
	}
}
