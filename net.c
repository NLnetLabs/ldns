/*
 * net.c
 *
 * Network implementation
 * All network related functions are grouped here
 *
 * a Net::DNS like library for C
 *
 * (c) NLnet Labs, 2004, 2005
 *
 * See the file LICENSE for the license
 */

#include <ldns/config.h>

#include <ldns/dns.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <errno.h>

ldns_status
ldns_send(ldns_pkt **result, ldns_resolver *r, ldns_pkt *query_pkt)
{
	uint8_t i,j;
	ldns_rdf *temp;
	
	struct sockaddr_storage *ns;
	size_t ns_len;
	struct timeval tv_s;
        struct timeval tv_e;

	ldns_rdf **ns_array;
	ldns_rdf **ns_rand_array;
	ldns_pkt *reply;
	ldns_buffer *qb;

	uint8_t *reply_bytes = NULL;
	size_t reply_size = 0;
	ldns_rdf *tsig_mac = NULL;
	ldns_status status;

	status = LDNS_STATUS_OK;

	ns_rand_array = LDNS_XMALLOC(ldns_rdf*, ldns_resolver_nameserver_count(r));

	if (!query_pkt || !ns_rand_array) {
		/* nothing to do? */
		return LDNS_STATUS_ERR;
	}
	
	ns_array = ldns_resolver_nameservers(r);
	reply = NULL; ns_len = 0;
	for (i = 0; i < ldns_resolver_nameserver_count(r); i++) {
		ns_rand_array[i] = ns_array[i];
	}
	
	qb = ldns_buffer_new(LDNS_MIN_BUFLEN);

	if (ldns_pkt_tsig(query_pkt)) {
		tsig_mac = ldns_rr_rdf(ldns_pkt_tsig(query_pkt), 3);
	}

	if (ldns_pkt2buffer_wire(qb, query_pkt) != LDNS_STATUS_OK) {
		ldns_buffer_free(qb);
		return LDNS_STATUS_ERR;
	}
	/* random should already be setup - isn't so bad
	 * if this isn't "good" random. Note that this
	 * changes the order in the resolver as well!
	 */
	if (ldns_resolver_random(r)) {
		for (i = 0; i < ldns_resolver_nameserver_count(r); i++) {
			j = random() % ldns_resolver_nameserver_count(r);
			/* printf("r = %d, switch i = %d, j = %d\n", 
			 ldns_resolver_nameserver_count(r), i, j);
			 */
			temp = ns_rand_array[i];
			ns_rand_array[i] = ns_rand_array[j];
			ns_rand_array[j] = temp;
		}
	}

	/* loop through all defined nameservers */
	for (i = 0; i < ldns_resolver_nameserver_count(r); i++) {

		ns = ldns_rdf2native_sockaddr_storage(ns_rand_array[i],
				ldns_resolver_port(r), &ns_len);

		if ((ns->ss_family == AF_INET && 
				ldns_resolver_ip6(r) == LDNS_RESOLV_INET6)
				||
				(ns->ss_family == AF_INET6 &&
				 ldns_resolver_ip6(r) == LDNS_RESOLV_INET)) {
			/* mismatch, next please */
			LDNS_FREE(ns);
			continue;
		}

		gettimeofday(&tv_s, NULL);
		/* query */
		if (1 == ldns_resolver_usevc(r)) {
			/* do err handling here ? */
			(void)ldns_tcp_send(&reply_bytes, qb, ns, (socklen_t)ns_len, ldns_resolver_timeout(r), &reply_size);
		} else {
			/* udp here, please */
			(void)ldns_udp_send(&reply_bytes, qb, ns, (socklen_t)ns_len, ldns_resolver_timeout(r), &reply_size);
		}
		
		/* obey the fail directive */
		if (!reply_bytes) {
			if (ldns_resolver_fail(r)) {
				LDNS_FREE(ns);
				ldns_buffer_free(qb);
				return LDNS_STATUS_ERR;
			} else {
				continue;
			}
		} 
		
		if (ldns_wire2pkt(&reply, reply_bytes, reply_size) !=
		    LDNS_STATUS_OK) {
			LDNS_FREE(reply_bytes);
			LDNS_FREE(ns);
			ldns_buffer_free(qb);
			return LDNS_STATUS_ERR;
		}
		
		LDNS_FREE(ns);
		gettimeofday(&tv_e, NULL);

		if (reply) {
			ldns_pkt_set_querytime(reply,
				((tv_e.tv_sec - tv_s.tv_sec) * 1000) +
				(tv_e.tv_usec - tv_s.tv_usec) / 1000);
			ldns_pkt_set_answerfrom(reply, ns_rand_array[i]);
			ldns_pkt_set_when(reply, ctime((time_t*)&tv_s.tv_sec));
			ldns_pkt_set_size(reply, reply_size);
			break;
		} else {
			if (ldns_resolver_fail(r)) {
				/* if fail is set bail out, after the first
				 * one */
				break;
			}
		}

		/* wait retrans seconds... */
		sleep((unsigned int) ldns_resolver_retrans(r));
	}

	if (tsig_mac && reply_bytes) {
		if (!ldns_pkt_tsig_verify(reply,
		                          reply_bytes,
					  reply_size,
		                          ldns_resolver_tsig_keyname(r),
		                          ldns_resolver_tsig_keydata(r),
		                          tsig_mac)) {
			status = LDNS_STATUS_CRYPTO_TSIG_BOGUS;
		}
	}
	
	LDNS_FREE(ns_rand_array);
	LDNS_FREE(reply_bytes);
	ldns_buffer_free(qb);
	if (result) {
		*result = reply;
	}
	return status;
}

ldns_status
ldns_udp_send(uint8_t **result, ldns_buffer *qbin, const struct sockaddr_storage *to, socklen_t tolen, struct timeval timeout, size_t *answer_size)
{
	int sockfd;
	uint8_t *answer;

	sockfd = ldns_udp_connect(to, timeout);

	if (sockfd == 0) {
		return LDNS_STATUS_ERR;
	}

	if (ldns_udp_send_query(qbin, sockfd, to, tolen) == 0) {
		return LDNS_STATUS_ERR;
	}
	
	/* wait for an response*/

	answer = ldns_udp_read_wire(sockfd, answer_size, NULL, NULL);

	/* resize accordingly */
	answer = (uint8_t*)LDNS_XREALLOC(answer, uint8_t *, (size_t)*answer_size);

	*result = answer;
	return LDNS_STATUS_OK;
}

/* 
 * ldns_tcp_server_connect
 *
 * and the normal conetc, for just a socket
 */
int
ldns_udp_server_connect(const struct sockaddr_storage *to, struct timeval timeout)
{
	int sockfd;
	
	if ((sockfd = socket((int)((struct sockaddr*)to)->sa_family, SOCK_DGRAM, IPPROTO_UDP)) 
			== -1) {
                return 0;
        }
	if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
				(socklen_t) sizeof(timeout))) {
		perror("setsockopt");
		close(sockfd);
		return 0;
        }

	if (bind(sockfd, (struct sockaddr*)to, (socklen_t)sizeof(*to)) == -1) {
		perror("bind");
		close(sockfd);
		return 0;
	}
	return sockfd;
}

int
ldns_udp_connect(const struct sockaddr_storage *to, struct timeval timeout)
{
	int sockfd;
	
	if ((sockfd = socket((int)((struct sockaddr*)to)->sa_family, SOCK_DGRAM, IPPROTO_UDP)) 
			== -1) {
                return 0;
        }
	if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
				(socklen_t)sizeof(timeout))) {
		perror("setsockopt");
		close(sockfd);
		return 0;
        }
	return sockfd;
}

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
	sendbuf = LDNS_XMALLOC(uint8_t, ldns_buffer_position(qbin) + 2);
	ldns_write_uint16(sendbuf, ldns_buffer_position(qbin));
	memcpy(sendbuf + 2, ldns_buffer_export(qbin), ldns_buffer_position(qbin));

	bytes = sendto(sockfd, sendbuf,
			ldns_buffer_position(qbin) + 2, 0, (struct sockaddr *)to, tolen);

        LDNS_FREE(sendbuf);

	if (bytes == -1) {
		dprintf("%s", "error with sending\n");
		return 0;
	}
	if ((size_t) bytes != ldns_buffer_position(qbin) + 2) {
		dprintf("%s", "amount of sent bytes mismatch\n");
		return 0;
	}
	return bytes;
}

/* don't wait for an answer */
ssize_t
ldns_udp_send_query(ldns_buffer *qbin, int sockfd, const struct sockaddr_storage *to, 
		socklen_t tolen)
{
	ssize_t bytes;

	bytes = sendto(sockfd, ldns_buffer_begin(qbin),
			ldns_buffer_position(qbin), 0, (struct sockaddr *)to, tolen);

	if (bytes == -1) {
		dprintf("%s", "error with sending\n");
		return 0;
	}
	if ((size_t) bytes != ldns_buffer_position(qbin)) {
		dprintf("%s", "amount mismatch\n");
		return 0;
	}
	return bytes;
}

uint8_t *
ldns_udp_read_wire(int sockfd, size_t *size, struct sockaddr_storage *from,
		socklen_t *fromlen)
{
	uint8_t *wire;
	ssize_t wire_size;
	socklen_t flen;

	wire = LDNS_XMALLOC(uint8_t, LDNS_MAX_PACKETLEN);
	if (!wire) {
		*size = 0;
		return NULL;
	}

	wire_size = recvfrom(sockfd, wire, LDNS_MAX_PACKETLEN, 0, 
			(struct sockaddr*) from, &flen);

	if (from) {
		if (fromlen) {
			*fromlen = flen;
		}
		printf("from len %d\n", (int)flen);
	}

	if (wire_size == -1) {
		if (errno == EAGAIN) {
			dprintf("%s", "socket timeout\n");
		}
		*size = 0;
		perror("error receiving udp packet");
		return NULL;
	}

	*size = (size_t)wire_size;
	wire = LDNS_XREALLOC(wire, uint8_t, (size_t)wire_size);
	return wire;
}

uint8_t *
ldns_tcp_read_wire(int sockfd, size_t *size)
{
	uint8_t *wire;
	uint16_t wire_size;
	ssize_t bytes = 0;

	wire = LDNS_XMALLOC(uint8_t, 2);
	if (!wire) {
		*size = 0;
		return NULL;
	}
	
	while (bytes < 2) {
		bytes = recv(sockfd, wire, 2, 0);
		if (bytes == -1) {
			if (errno == EAGAIN) {
				dprintf("%s", "socket timeout\n");
			}
			perror("error receiving tcp packet");
			*size = 0;
			return NULL;
		}
	}

	wire_size = ldns_read_uint16(wire);
	
	LDNS_FREE(wire);
	wire = LDNS_XMALLOC(uint8_t, wire_size);
	bytes = 0;

	while (bytes < (ssize_t) wire_size) {
		bytes += recv(sockfd, wire + bytes, (size_t) (wire_size - bytes), 0);
		if (bytes == -1) {
			if (errno == EAGAIN) {
				dprintf("%s", "socket timeout\n");
			}
			perror("error receiving tcp packet");
			LDNS_FREE(wire);
			*size = 0;
			return NULL;
		}
	}
	
	*size = (size_t) bytes;
	return wire;
}

/* keep in mind that in DNS tcp messages the first 2 bytes signal the
 * amount data to expect
 */
ldns_status
ldns_tcp_send(uint8_t **result,  ldns_buffer *qbin, const struct sockaddr_storage *to, socklen_t tolen, struct timeval timeout, size_t *answer_size)
{
	int sockfd;
	uint8_t *answer;
	
	sockfd = ldns_tcp_connect(to, tolen, timeout);
	
	if (sockfd == 0) {
		return LDNS_STATUS_ERR;
	}
	
	if (ldns_tcp_send_query(qbin, sockfd, to, tolen) == 0) {
		return LDNS_STATUS_ERR;
	}
	
	answer = ldns_tcp_read_wire(sockfd, answer_size);

	/* resize accordingly */
	answer = (uint8_t*)LDNS_XREALLOC(answer, uint8_t *, (size_t)*answer_size);
	*result = answer;
	return LDNS_STATUS_OK;
}
