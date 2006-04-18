/*
 * nsd-ldnsd. Light-weight DNS daemon, which sends IXFRs
 *
 * Tiny dns server to show how a real one could be built.
 * This version is used for NSD test, send out IXFR's only.
 *
 * (c) NLnet Labs, 2005, 2006
 * See the file LICENSE for the license
 */

#include "config.h"
#include <ldns/dns.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/igmp.h>
#include <errno.h>

#define INBUF_SIZE 4096

void usage(FILE *output)
{
	fprintf(output, "Usage: nsd-ldnsd <port> <zone> <soa-serial>\n");
	fprintf(output, "Listens on the specified port and answer every query with an IXFR\n");
	fprintf(output, "This is NOT a full-fledged authoritative nameserver! It is NOTHING.\n");
}

static int udp_bind(int sock, int port, const char *my_address)
{
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = (in_port_t)htons((uint16_t)port);
		addr.sin_addr.s_addr = INADDR_ANY;
    return bind(sock, (struct sockaddr *)&addr, (socklen_t) sizeof(addr));
}

int
main(int argc, char **argv)
{
	/* arguments */
	int port;
	int soa;
	ldns_rr *zone_name;

	/* network */
	int sock;
	size_t nb;
	struct sockaddr addr_me;
	struct sockaddr addr_him;
	socklen_t hislen;
	const char *my_address;
	uint8_t inbuf[INBUF_SIZE];
	uint8_t *outbuf;

	/* dns */
	ldns_status status;
	ldns_pkt *query_pkt;
	ldns_pkt *answer_pkt;
	size_t answer_size;
	ldns_rr *query_rr;
	ldns_rr_list *answer_qr;
	ldns_rr_list *answer_ns;
	ldns_rr_list *answer_ad;
	
	/* use this to listen on specified interfaces later? */
	my_address = NULL;
		
	if (argc < 4) {
		usage(stdout);
		exit(EXIT_FAILURE);
	} else {
		port = atoi(argv[1]);
		if (port < 1) {
			usage(stdout);
			exit(EXIT_FAILURE);
		}
		if (ldns_rr_new_frm_str(&zone_name, argv[2], 0, NULL, NULL) !=
				LDNS_STATUS_OK) {
			usage(stdout);
			exit(EXIT_FAILURE);
		}
		soa =  atoi(argv[3]);
		if (soa < 1) {
			usage(stdout);
			exit(EXIT_FAILURE);
		}
			
	}
	
	printf("Listening on port %d\n", port);
	sock =  socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		fprintf(stderr, "%s: socket(): %s\n", argv[0], strerror(errno));
		exit(1);
	}

	memset(&addr_me, 0, sizeof(addr_me));

	/* bind: try all ports in that range */
	if (udp_bind(sock, port, my_address)) {
		fprintf(stderr, "%s: cannot bind(): %s\n", argv[0], strerror(errno));
	}

	/* Done. Now receive */
	while (1) {
		nb = (size_t) recvfrom(sock, inbuf, INBUF_SIZE, 0, &addr_him, &hislen);
		if (nb < 1) {
			fprintf(stderr, "%s: recvfrom(): %s\n",
			argv[0], strerror(errno));
			exit(1);
		}

		/*
		show(inbuf, nb, nn, hp, sp, ip, bp);
		*/
		
		printf("Got query of %u bytes\n", (unsigned int) nb);
		status = ldns_wire2pkt(&query_pkt, inbuf, nb);
		if (status != LDNS_STATUS_OK) {
			printf("Got bad packet: %s\n", ldns_get_errorstr_by_id(status));
		} else {
			ldns_pkt_print(stdout, query_pkt);
		}
		
		query_rr = ldns_rr_list_rr(ldns_pkt_question(query_pkt), 0);
		printf("QUERY RR: \n");
		ldns_rr_print(stdout, query_rr);
		
		answer_qr = ldns_rr_list_new();
		ldns_rr_list_push_rr(answer_qr, ldns_rr_clone(query_rr));

		answer_pkt = ldns_pkt_new();
		answer_ns = ldns_rr_list_new();
		answer_ad = ldns_rr_list_new();
		
		ldns_pkt_set_qr(answer_pkt, 1);
		ldns_pkt_set_aa(answer_pkt, 1);
		ldns_pkt_set_id(answer_pkt, ldns_pkt_id(query_pkt));


		
		status = ldns_pkt2wire(&outbuf, answer_pkt, &answer_size);
		
		printf("Answer packet size: %u bytes.\n", (unsigned int) answer_size);
		if (status != LDNS_STATUS_OK) {
			printf("Error creating answer: %s\n", ldns_get_errorstr_by_id(status));
		} else {
			nb = (size_t) sendto(sock, outbuf, answer_size, 0, &addr_him, hislen);
		}
		
		
		
	}

        return 0;
}
