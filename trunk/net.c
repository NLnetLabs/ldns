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

#include "util.h"


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
	
	struct sockaddr *ns_ip;
	socklen_t ns_ip_len;
	ldns_rdf **ns_array;
	ldns_pkt *reply;
	ldns_buffer *qb;

	ns_array = ldns_resolver_nameservers(r);
	reply = NULL;
	
	qb = ldns_buffer_new(MAX_PACKET_SIZE);

	if (ldns_pkt2buffer_wire(qb, query_pkt) != LDNS_STATUS_OK) {
		return NULL;
	}

	/* loop through all defined nameservers */
	for (i = 0; i < ldns_resolver_nameserver_count(r); i++) {
		ns_ip = ldns_rdf2native_aaaaa(ns_array[i]);
		ns_ip_len = ldns_rdf_size(ns_array[i]);

		ldns_rdf_print(stdout, ns_ip);
		printf("\n");

		/* query */
		reply = ldns_send_udp(qb, ns_ip, ns_ip_len);
		
		if (!reply) {
			break;
		}
	}
	return reply;
}


/**
 */
ldns_pkt *
ldns_send_udp(ldns_buffer *qbin, const struct sockaddr *to, socklen_t tolen)
{
	int sockfd;
	ssize_t bytes;
	uint8_t *answer;
	ldns_pkt *answer_pkt;

	
	if ((sockfd = socket(to->sa_family, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
		return NULL;
	}

	bytes =  sendto(sockfd, ldns_buffer_begin(qbin),
			ldns_buffer_capacity(qbin), 0, to, tolen);

	if (bytes == -1) {
		close(sockfd);
		return NULL;
	}

	if ((size_t) bytes != ldns_buffer_capacity(qbin)) {
		close(sockfd);
		return NULL;
	}
	
	/* wait for an response*/
	answer = XMALLOC(uint8_t*, MAX_PACKET_SIZE);
	if (!answer) {
		return NULL;
	}

	bytes = recv(sockfd, answer, MAX_PACKET_SIZE, 0);

	close(sockfd);

	if (bytes == -1) {
		FREE(answer);
		return NULL;
	}
	
	/* resize accordingly */
	XREALLOC(answer, uint8_t *, (size_t) bytes);

        if (ldns_wire2pkt(&answer_pkt, answer, (size_t) bytes) != 
			LDNS_STATUS_OK) {
		return NULL;
	} else {
		return answer_pkt;
	}
}
