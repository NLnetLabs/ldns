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
#include <ldns/net.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <errno.h>

#include "util.h"


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
	struct timeval tv_s;
        struct timeval tv_e;

	ldns_rdf **ns_array;
	ldns_pkt *reply;
	ldns_buffer *qb;
	
	ns_array = ldns_resolver_nameservers(r);
	reply = NULL; ns_len = 0;
	
	qb = ldns_buffer_new(MAX_PACKETLEN);

	if (ldns_pkt2buffer_wire(qb, query_pkt) != LDNS_STATUS_OK) {
		printf("could not convert to wire fmt\n");
		return NULL;
	}

	/* loop through all defined nameservers */
	for (i = 0; i < ldns_resolver_nameserver_count(r); i++) {

		ns = ldns_rdf2native_sockaddr_storage(ns_array[i]);

		if ((ns->ss_family == AF_INET && 
				ldns_resolver_ip6(r) == RESOLV_INET6)
				||
				(ns->ss_family == AF_INET6 &&
				 ldns_resolver_ip6(r) == RESOLV_INET)) {
			/* mismatch, next please */
			continue;
		}

		/* setup some family specific stuff */
		switch(ns->ss_family) {
			case AF_INET:
				ns4 = (struct sockaddr_in*) ns;
				ns4->sin_port = htons(ldns_resolver_port(r));
				ns_len = (socklen_t)sizeof(struct sockaddr_in);
				break;
			case AF_INET6:
				ns6 = (struct sockaddr_in6*) ns;
				ns6->sin6_port = htons(ldns_resolver_port(r));
				ns_len = (socklen_t)sizeof(struct sockaddr_in6);
				break;
		}
		
		gettimeofday(&tv_s, NULL);
		/* query */
		if (1 == ldns_resolver_usevc(r)) {
			reply = ldns_send_tcp(qb, ns, ns_len, ldns_resolver_timeout(r));
		} else {
			/* udp here, please */
			reply = ldns_send_udp(qb, ns, ns_len, ldns_resolver_timeout(r));
		}
		FREE(ns);
		gettimeofday(&tv_e, NULL);

		if (reply) {
			ldns_pkt_set_querytime(reply,
				((tv_e.tv_sec - tv_s.tv_sec) * 1000) +
				(tv_e.tv_usec - tv_s.tv_usec) / 1000);
			ldns_pkt_set_answerfrom(reply, ns_array[i]);
			ldns_pkt_set_when(reply,  ctime((time_t*)&tv_s.tv_sec));
			break;
		} else {
			if (ldns_resolver_fail(r)) {
				/* if fail is set bail out, after the first
				 * one */
				break;
			}
		}

		/* wait retrans seconds... */
	}
	ldns_buffer_free(qb);
	return reply;
}

/**
 * Send a buffer to an ip using udp and return the respons as a ldns_pkt
 * \param[in] qbin the ldns_buffer to be send
 * \param[in] to the ip addr to send to
 * \param[in] tolen length of the ip addr
 * \return a packet with the answer
 */
ldns_pkt *
ldns_send_udp(ldns_buffer *qbin, const struct sockaddr_storage *to, socklen_t tolen, struct timeval timeout)
{
	int sockfd;
	ssize_t bytes;
	uint8_t *answer;
	ldns_pkt *answer_pkt;

/*
        struct timeval timeout;
        
        timeout.tv_sec = LDNS_DEFAULT_TIMEOUT_SEC;
        timeout.tv_usec = LDNS_DEFAULT_TIMEOUT_USEC;
*/        

	if ((sockfd = socket((int)((struct sockaddr*)to)->sa_family, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
		printf("could not open socket\n");
		return NULL;
	}

	if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
			(socklen_t) sizeof(timeout))) {
		perror("setsockopt");
		close(sockfd);
		return NULL;
	}
	
	bytes = sendto(sockfd, ldns_buffer_begin(qbin),
			ldns_buffer_position(qbin), 0, (struct sockaddr *)to, tolen);


	if (bytes == -1) {
		printf("error with sending\n");
		close(sockfd);
		return NULL;
	}

	if ((size_t) bytes != ldns_buffer_position(qbin)) {
		printf("amount mismatch\n");
		close(sockfd);
		return NULL;
	}
	
	/* wait for an response*/
	answer = XMALLOC(uint8_t, MAX_PACKETLEN);
	if (!answer) {
		printf("respons alloc error\n");
		return NULL;
	}

	bytes = recv(sockfd, answer, MAX_PACKETLEN, 0);

	close(sockfd);

	if (bytes == -1) {
		if (errno == EAGAIN) {
			fprintf(stderr, "socket timeout\n");
		}
		printf("received too little\n");
		FREE(answer);
		return NULL;
	}
	
	/* resize accordingly */
	XREALLOC(answer, uint8_t *, (size_t) bytes);

        if (ldns_wire2pkt(&answer_pkt, answer, (size_t) bytes) != 
			LDNS_STATUS_OK) {
		FREE(answer);
		return NULL;
	} else {
		ldns_pkt_set_size(answer_pkt, (size_t) bytes);
		FREE(answer);
		return answer_pkt;
	}
}

/**
 * Create a tcp socket to the specified address
 */
int
ldns_tcp_connect(const struct sockaddr_storage *to, socklen_t tolen, struct timeval timeout)
{
	int sockfd;
	
	if ((sockfd = socket((int)((struct sockaddr*)to)->sa_family, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		perror("could not open socket");
		return 0;
	}

        if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                        (socklen_t) sizeof(timeout))) {
                perror("setsockopt");
                close(sockfd);
                return 0;
        }

	if (connect(sockfd, (struct sockaddr*)to, tolen) == -1) {
 		close(sockfd);
		perror("could not bind socket");
		return 0;
	}

	return sockfd;
}


ssize_t
ldns_tcp_send_query(ldns_buffer *qbin, int sockfd, const struct sockaddr_storage *to, socklen_t tolen)
{
	uint8_t *sendbuf;
	ssize_t bytes;

	/* add length of packet */
	sendbuf = XMALLOC(uint8_t, ldns_buffer_position(qbin) + 2);
	write_uint16(sendbuf, ldns_buffer_position(qbin));
	memcpy(sendbuf+2, ldns_buffer_export(qbin), ldns_buffer_position(qbin));

	bytes = sendto(sockfd, sendbuf,
			ldns_buffer_position(qbin)+2, 0, (struct sockaddr *)to, tolen);

        FREE(sendbuf);

	if (bytes == -1) {
		printf("error with sending\n");
		close(sockfd);
		return 0;
	}
	if ((size_t) bytes != ldns_buffer_position(qbin)+2) {
		printf("amount of sent bytes mismatch\n");
		close(sockfd);
		return 0;
	}
	
	return bytes;
}

/**
 * Creates a new ldns_pkt structure and reads the header data from the given
 * socket
 */
ldns_pkt *
ldns_tcp_read_packet(int sockfd)
{
	ldns_pkt *pkt;
	uint8_t *wire;
	uint16_t wire_size;
	ssize_t bytes = 0;

	wire = XMALLOC(uint8_t, 2);
	while (bytes < 2) {
		bytes = recv(sockfd, wire, 2, 0);
		if (bytes == -1) {
			if (errno == EAGAIN) {
				fprintf(stderr, "socket timeout\n");
			}
			perror("error receiving tcp packet");
			FREE(pkt);
			return NULL;
		}
	}

	wire_size = read_uint16(wire);
	
	FREE(wire);
	wire = XMALLOC(uint8_t, wire_size);
	bytes = 0;

	while (bytes < (ssize_t) wire_size) {
		bytes += recv(sockfd, wire + bytes, (size_t) (wire_size - bytes), 0);
		if (bytes == -1) {
			if (errno == EAGAIN) {
				fprintf(stderr, "socket timeout\n");
			}
			perror("error receiving tcp packet");
			FREE(wire);
			return NULL;
		}
	}

        if (ldns_wire2pkt(&pkt, wire, (size_t) wire_size) != 
			LDNS_STATUS_OK) {
		printf("could not create packet\n");
		FREE(wire);
		return NULL;
	} else {
		ldns_pkt_set_size(pkt, (size_t) bytes);
		FREE(wire);
		return pkt;
	}
}

/**
 * Send a buffer to an ip using tcp and return the respons as a ldns_pkt
 * \param[in] qbin the ldns_buffer to be send
 * \param[in] to the ip addr to send to
 * \param[in] tolen length of the ip addr
 * \return a packet with the answer
 */
/* keep in mind that in DNS tcp messages the first 2 bytes signal the
 * amount data to expect
 */
ldns_pkt *
ldns_send_tcp(ldns_buffer *qbin, const struct sockaddr_storage *to, socklen_t tolen, struct timeval timeout)
{
	int sockfd;
	ldns_pkt *answer;
	
	sockfd = ldns_tcp_connect(to, tolen, timeout);
	
	if (sockfd == 0) {
		return NULL;
	}
	
	if (ldns_tcp_send_query(qbin, sockfd, to, tolen) == 0) {
		return NULL;
	}
	
	answer = ldns_tcp_read_packet(sockfd);
	
	close(sockfd);
	
	return answer;
}

