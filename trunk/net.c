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



#if 0
/* axfr is a hack - handle it different */
ldns_pkt *
ldns_sendbuf_axfr(ldns_buffer *buf, int *sockfd, struct sockaddr *dest)
{
	return NULL;
}
#endif 

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
	reply = NULL; ns_len = 0;
	
	qb = ldns_buffer_new(MAX_PACKET_SIZE);

	if (ldns_pkt2buffer_wire(qb, query_pkt) != LDNS_STATUS_OK) {
		printf("could not convert to wire fmt\n");
		return NULL;
	}

	/* loop through all defined nameservers */
	for (i = 0; i < ldns_resolver_nameserver_count(r); i++) {

		ns = ldns_rdf2native_sockaddr_storage(ns_array[i]);

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

		/* query */
		if (1 == ldns_resolver_usevc(r)) {
			reply = ldns_send_tcp(qb, ns, ns_len);
		} else {
			/* udp here, please */
			reply = ldns_send_udp(qb, ns, ns_len);
		}
		
		if (reply) {
			ldns_pkt_set_answerfrom(reply, ns_array[i]);
			break;
		}
	}
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
ldns_send_udp(ldns_buffer *qbin, const struct sockaddr_storage *to, socklen_t tolen)
{
	int sockfd;
	ssize_t bytes;
	uint8_t *answer;
	ldns_pkt *answer_pkt;

	struct timeval tv_s;
        struct timeval tv_e;

	gettimeofday(&tv_s, NULL);

	if ((sockfd = socket((int)((struct sockaddr*)to)->sa_family, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
		printf("could not open socket\n");
		return NULL;
	}

	bytes = sendto(sockfd, ldns_buffer_begin(qbin),
			ldns_buffer_position(qbin), 0, (struct sockaddr *)to, tolen);

	gettimeofday(&tv_e, NULL);

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
		/* set some extra values in the pkt */
		ldns_pkt_set_querytime(answer_pkt,
				((tv_e.tv_sec - tv_s.tv_sec)*1000) +
				((tv_e.tv_usec - tv_s.tv_usec)/1000));

		return answer_pkt;
	}
}

/**
 * Send a buffer to an ip using tcp and return the respons as a ldns_pkt
 * \param[in] qbin the ldns_buffer to be send
 * \param[in] to the ip addr to send to
 * \param[in] tolen length of the ip addr
 * \return a packet with the answer
 */
ldns_pkt *
ldns_send_tcp(ldns_buffer *qbin, const struct sockaddr_storage *to, socklen_t tolen)
{
	int sockfd;
	ssize_t bytes;
	uint8_t *answer;
	ldns_pkt *answer_pkt;

	struct timeval tv_s;
        struct timeval tv_e;

	gettimeofday(&tv_s, NULL);

	if ((sockfd = socket((int)((struct sockaddr*)to)->sa_family, SOCK_STREAM, IPPROTO_UDP)) == -1) {
		printf("could not open socket\n");
		return NULL;
	}

	return NULL;

	bytes = sendto(sockfd, ldns_buffer_begin(qbin),
			ldns_buffer_position(qbin), 0, (struct sockaddr *)to, tolen);

	gettimeofday(&tv_e, NULL);

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
		/* set some extra values in the pkt */
		ldns_pkt_set_querytime(answer_pkt,
				((tv_e.tv_sec - tv_s.tv_sec)*1000) +
				((tv_e.tv_usec - tv_s.tv_usec)/1000));

		return answer_pkt;
	}
}

/*
 * Read SIZE bytes from the socket into BUF.  Keep reading unless an
 * error occurs (except for EINTR) or EOF is reached.
 */
static bool 
read_socket(int s, void *buf, size_t size)
{
        char *data = buf;
        size_t total_count = 0;

        while (total_count < size) {
                ssize_t count = read(s, data + total_count, size -
                total_count);
                if (count == -1) {
                        if (errno != EINTR) {
                                return false;
                        } else {
                                continue;
                        }
                }
                total_count += count;
        }
        return true;
}

/*
 * Write the complete buffer to the socket, irrespective of short
 * writes or interrupts.
 */
static bool
write_socket(int s, const void *buf, size_t size)
{
        const char *data = buf;
        size_t total_count = 0;

        while (total_count < size) {
                ssize_t count = write(s, data + total_count, size -
                total_count);
                if (count == -1) {
                        if (errno != EINTR) {
                                return false;
                        } else {
                                continue;
                        }
                }
                total_count += count;
        }
        return true;
}
