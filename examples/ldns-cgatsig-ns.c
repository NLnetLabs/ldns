/*
 * ldns-cga-tsig.c. Light-weight DNS daemon.
 *
 * Tiny dns server to show how a real one could be built.
 * With CGA-TSIG support.
 *
 * (c) NLnet Labs, 2013
 * See the file LICENSE for the license
 */

#include "config.h"
#include <ldns/ldns.h>

#ifdef HAVE_SYS_SOCKET_H
#  include <sys/socket.h>
#endif
#ifdef HAVE_ARPA_INET_H
#  include <arpa/inet.h>
#endif
#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif
#ifdef HAVE_NETINET_UDP_H
#  include <netinet/udp.h>
#endif
#ifdef HAVE_NETINET_IGMP_H
#  include <netinet/igmp.h>
#endif

#include <errno.h>

#define INBUF_SIZE 4096

void usage(FILE *output)
{
	fprintf(output, "Usage: ldns-cgatsig-ns <address> <port> <zone> <zonefile> <private key> <public key> <modifier> <collision count>\n");
	fprintf(output, "Listens on the specified port and answers queries for the given zone\n");
	fprintf(output, "This is NOT a full-fledged authoritative nameserver!\n");
}

static int udp_bind(int *sock, int port, const char *my_address, struct sockaddr_storage *addr)
{
    struct in_addr maddr4;
    struct in6_addr maddr6 = IN6ADDR_ANY_INIT;
    int prot = AF_INET6;
    struct sockaddr_in *ipv4;
    struct sockaddr_in6 *ipv6;

    maddr4.s_addr = INADDR_ANY;

    if (my_address) {
#ifdef AF_INET6
        if (inet_pton(AF_INET6, my_address, &maddr6) < 1) {
#else
    if (0) {
#endif
            prot = AF_INET;
            if (inet_pton(AF_INET, my_address, &maddr4) < 1) {
                return -2;
            }
        }
    }

    *sock = socket(prot, SOCK_DGRAM, 0);
    if (*sock < 0) {
        return -3;

    }
    if (prot == AF_INET) {
        ipv4 = (struct sockaddr_in*)addr;
#ifndef S_SPLINT_S
        ipv4->sin_family = prot;
#endif
        ipv4->sin_port = (in_port_t) htons((uint16_t)port);
        ipv4->sin_addr = maddr4;
    } else {
        ipv6 = (struct sockaddr_in6*)addr;
#ifndef S_SPLINT_S
        ipv6->sin6_family = prot;
#endif
        ipv6->sin6_port = (in_port_t) htons((uint16_t)port);
        ipv6->sin6_addr = maddr6;
    }

    return bind(*sock, (struct sockaddr *)addr, (socklen_t) sizeof(*addr));
}

/* this will probably be moved to a better place in the library itself */
ldns_rr_list *
get_rrset(const ldns_zone *zone, const ldns_rdf *owner_name, const ldns_rr_type qtype, const ldns_rr_class qclass)
{
	uint16_t i;
	ldns_rr_list *rrlist = ldns_rr_list_new();
	ldns_rr *cur_rr;
	if (!zone || !owner_name) {
		fprintf(stderr, "Warning: get_rrset called with NULL zone or owner name\n");
		return rrlist;
	}
	for (i = 0; i < ldns_zone_rr_count(zone); i++) {
		cur_rr = ldns_rr_list_rr(ldns_zone_rrs(zone), i);
		if (ldns_dname_compare(ldns_rr_owner(cur_rr), owner_name) == 0 &&
		    ldns_rr_get_class(cur_rr) == qclass &&
		    ldns_rr_get_type(cur_rr) == qtype
		   ) {
			ldns_rr_list_push_rr(rrlist, ldns_rr_clone(cur_rr));
		}
	}
	printf("Found rrset of %u rrs\n", (unsigned int) ldns_rr_list_rr_count(rrlist));
	return rrlist;
}

int
Base64Decode(FILE *fp, char **buffer)
{
	BIO *bio, *b64;
	long in_len;
	int out_len;

	fseek(fp, 0, SEEK_END);
	in_len = ftell(fp) - 1;
	rewind(fp);

	*buffer = malloc(in_len);

	if (!*buffer) {
		return 0;
	}

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new_fp(fp, BIO_NOCLOSE);
	bio = BIO_push(b64, bio);
	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
	out_len = BIO_read(bio, *buffer, in_len);
	BIO_free_all(bio);

	if (out_len < 1) {
		free(*buffer);
		return 0;
	}

	(*buffer)[out_len] = '\0';

	return out_len;
}

int
main(int argc, char **argv)
{
	/* arguments */
	int port;
	const char *zone_file;
	const char *pvtk_file;
	const char *pubk_file;
	const char *modf_file;
	int coll_count;
	/* network */
	int sock;
	ssize_t nb;
	struct sockaddr_storage addr_me;
	struct sockaddr addr_him;
	struct sockaddr_in6 *addr6;
	socklen_t hislen = (socklen_t) sizeof(addr_him);
	uint8_t inbuf[INBUF_SIZE];
	uint8_t *outbuf;
	/* dns */
	ldns_status status;
	ldns_pkt *query_pkt;
	ldns_pkt *answer_pkt;
	size_t answer_size;
	ldns_rr_list *query_ad;
	ldns_rr *query_rr;
	ldns_rr *query_tsig;
	ldns_rr *temp_rr;
	ldns_rr_list *answer_qr;
	ldns_rr_list *answer_an;
	ldns_rr_list *answer_ns;
	ldns_rr_list *answer_ad;
	ldns_rdf *origin = NULL;
	/* zone */
	ldns_zone *zone;
	int line_nr;
	FILE *fp;
	/* use this to listen on specified interfaces later? */
	char *my_address = NULL;
	/* cga-tsig */
	RSA *pvtk;
	RSA *pubk;
	char *modf;
	long modf_len = 0;
	uint8_t ip_tag[16] = {0};
	uint8_t prefix[8] = {0};
	int b, i;

	if (argc < 9) {
		usage(stderr);
		exit(EXIT_FAILURE);
	} else {
		my_address = argv[1];
		port = atoi(argv[2]);
		if (port < 1) {
			usage(stderr);
			exit(EXIT_FAILURE);
		}
		if (ldns_str2rdf_dname(&origin, argv[3]) != LDNS_STATUS_OK) {
			fprintf(stderr, "Bad origin, not a correct domain name\n");
			usage(stderr);
			exit(EXIT_FAILURE);
		}
		zone_file = argv[4];
		pvtk_file = argv[5];
		pubk_file = argv[6];
		modf_file = argv[7];
		coll_count = atoi(argv[8]);
		if (coll_count < 0 || coll_count > 2) {
			fprintf(stderr, "Collision count must be 0, 1, or 2\n");
			usage(stderr);
			exit(EXIT_FAILURE);
		}
	}

	printf("Reading zone file %s\n", zone_file);
	fp = fopen(zone_file, "r");
	if (!fp) {
		fprintf(stderr, "Unable to open %s: %s\n", zone_file, strerror(errno));
		exit(EXIT_FAILURE);
	}
	line_nr = 0;
	status = ldns_zone_new_frm_fp_l(&zone, fp, origin, 0, LDNS_RR_CLASS_IN, &line_nr);
	if (status != LDNS_STATUS_OK) {
		printf("Zone reader failed, aborting\n");
		exit(EXIT_FAILURE);
	} else {
		printf("Read %u resource records in zone file\n", (unsigned int) ldns_zone_rr_count(zone));
	}
	fclose(fp);

	printf("Reading private key file %s\n", pvtk_file);
	fp = fopen(pvtk_file, "r");
	if (!fp) {
		fprintf(stderr, "Unable to open %s: %s\n", pvtk_file, strerror(errno));
		exit(EXIT_FAILURE);
	}
	pvtk = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
	if (!pvtk) {
		printf("Private key loader failed, aborting\n");
		exit(EXIT_FAILURE);
	} else {
		printf("Loaded private key\n");
	}
	fclose(fp);

	printf("Reading public key file %s\n", pubk_file);
	fp = fopen(pubk_file, "r");
	if (!fp) {
		fprintf(stderr, "Unable to open %s: %s\n", pubk_file, strerror(errno));
		exit(EXIT_FAILURE);
	}
	pubk = PEM_read_RSAPublicKey(fp, NULL, NULL, NULL);
	if (!pubk) {
		printf("Public key loader failed, aborting\n");
		exit(EXIT_FAILURE);
	} else {
		printf("Loaded public key\n");
	}
	fclose(fp);

	printf("Reading modifier file %s\n", modf_file);
	fp = fopen(modf_file, "r");
	if (!fp) {
		fprintf(stderr, "Unable to open %s: %s\n", modf_file, strerror(errno));
		exit(EXIT_FAILURE);
	}
	modf_len = Base64Decode(fp, &modf);
	if (!modf_len) {
		printf("Modifier loader failed, aborting\n");
		exit(EXIT_FAILURE);
	} else if (modf_len != 16) {
		printf("Modifier is not 16 bytes, aborting\n");
		exit(EXIT_FAILURE);
	} else {
		printf("Loaded modifier\n");
	}
	fclose(fp);

	printf("Listening on port %d\n", port);
	//memset(&addr_me, 0, sizeof(addr_me));

	/* bind: try all ports in that range */
	b = udp_bind(&sock, port, my_address, &addr_me);
	if (b) {
		if (b == -3) {
        fprintf(stderr, "%s: socket(): %s\n", argv[0], strerror(errno));
        exit(1);
		} else {
			fprintf(stderr, "%s: cannot bind(): %s\n", argv[0], strerror(errno));
		}
		exit(errno);
	}

	if (addr_me.ss_family == AF_INET6) {
		addr6 = (struct sockaddr_in6*)&addr_me;
		memcpy(prefix, &(addr6->sin6_addr), 8);
	}

	/* Done. Now receive */
	while (1) {
		nb = recvfrom(sock, (void*)inbuf, INBUF_SIZE, 0, 
			&addr_him, &hislen);
		if (nb < 1) {
			fprintf(stderr, "%s: recvfrom(): %s\n",
			argv[0], strerror(errno));
			exit(1);
		}

		/*
		show(inbuf, nb, nn, hp, sp, ip, bp);
		*/
		printf("Got query of %u bytes\n", (unsigned int) nb);
		status = ldns_wire2pkt(&query_pkt, inbuf, (size_t) nb);
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

		answer_an = get_rrset(zone, ldns_rr_owner(query_rr), ldns_rr_get_type(query_rr), ldns_rr_get_class(query_rr));
		answer_pkt = ldns_pkt_new();
		answer_ns = ldns_rr_list_new();
		answer_ad = ldns_rr_list_new();

		ldns_pkt_set_qr(answer_pkt, 1);
		ldns_pkt_set_aa(answer_pkt, 1);
		ldns_pkt_set_id(answer_pkt, ldns_pkt_id(query_pkt));

		ldns_pkt_push_rr_list(answer_pkt, LDNS_SECTION_QUESTION, answer_qr);
		ldns_pkt_push_rr_list(answer_pkt, LDNS_SECTION_ANSWER, answer_an);
		ldns_pkt_push_rr_list(answer_pkt, LDNS_SECTION_AUTHORITY, answer_ns);
		ldns_pkt_push_rr_list(answer_pkt, LDNS_SECTION_ADDITIONAL, answer_ad);

		if (addr_me.ss_family == AF_INET6) {
//			query_ad = ldns_pkt_additional(query_pkt);
//			query_tsig = NULL;
//	printf("COUNT: %i\n", ldns_rr_list_rr_count(query_ad));
//			/*
//			if there is a TSIG RR, it must be the last and only one in the AD section
//			*/
//			for (i = ldns_rr_list_rr_count(query_ad) - 1; i >= 0; i--) {
//				temp_rr = ldns_rr_list_rr(query_ad, i);
//				if (ldns_rr_get_type(temp_rr) == LDNS_RR_TYPE_TSIG) {
//					if (query_tsig) {
//						query_tsig = NULL; // more than 1 TSIG RR, ignore for now
//						break;
//					}
//					query_tsig = temp_rr;
//					printf("Found TSIG RR\n");
//				} else if (!query_tsig) {
//						break; // last AD RR is not TSIG, ignore for now
//				}
//			}
			query_tsig = ldns_pkt_tsig(query_pkt);

			if (query_tsig && strcasecmp(ldns_rdf2str(ldns_rr_rdf(query_tsig, 0)),
																	 "cga-tsig.") == 0) {
				status = ldns_pkt_tsig_sign_2(answer_pkt,
						ldns_rdf2str(ldns_rr_owner(query_tsig)), NULL, pvtk, pubk,
						NULL, NULL, 300, "cga-tsig.", ldns_rr_rdf(query_tsig, 3),
						ip_tag, modf, prefix, coll_count, 0);
				if (status != LDNS_STATUS_OK) {
					printf("Error signing packet: %s\n", ldns_get_errorstr_by_id(status));
				} else {
					printf("Successfully signed a packet\n");
				}
			}
		}

		status = ldns_pkt2wire(&outbuf, answer_pkt, &answer_size);

		printf("Answer packet size: %u bytes.\n", (unsigned int) answer_size);
		if (status != LDNS_STATUS_OK) {
			printf("Error creating answer: %s\n", ldns_get_errorstr_by_id(status));
		} else {
			nb = sendto(sock, (void*)outbuf, answer_size, 0, 
				&addr_him, hislen);
		}
		ldns_pkt_free(query_pkt);
		ldns_pkt_free(answer_pkt);
		LDNS_FREE(outbuf);
		ldns_rr_list_free(answer_qr);
		ldns_rr_list_free(answer_an);
		ldns_rr_list_free(answer_ns);
		ldns_rr_list_free(answer_ad);
	}
	/* No cleanup because of the infinite loop
	 *
	 * ldns_rdf_deep_free(origin);
	 * ldns_zone_deep_free(zone);
	 * free(modf);
	 * return 0;
	 */
}
