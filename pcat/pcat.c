#ifdef HAVE_GETDELIM
#define _GNU_SOURCE
#endif

#include "config.h"
#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif

#include <ldns/ldns.h>
#include <errno.h>
#include <pcap.h>

#define FAILURE 10000


#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6 	0x86dd
#endif
#define DNS_UDP_OFFSET 	42

#ifndef HAVE_GETDELIM
size_t getdelim(char **lineptr, size_t *n, int delim, FILE *stream);
#endif

/* output: see usage() */

void
usage(FILE *fp)
{
	fprintf(fp, "pcat [-a IP] [-p PORT] [-r] PCAP_FILE\n\n");
	fprintf(fp, "   -a IP\tuse IP as nameserver, defaults to 127.0.0.1\n");
	fprintf(fp, "   -p PORT\tuse PORT as port, defaults to 53\n");
	fprintf(fp, "   -r \t\tthe file is a pcat output file to resend queries from\n");
	fprintf(fp, "   -h \t\tthis help\n");
	fprintf(fp, "  PCAP_FILE\tuse this file as source\n");
	fprintf(fp, "  If no file is given standard input is read\n");
	fprintf(fp, "\nOUTPUT FORMAT:\n");
	fprintf(fp, "    Line based output format, each record consists of 3 lines:\n");
	fprintf(fp, "    1. xxx\t\tdecimal sequence number\n");
	fprintf(fp, "    2. hex dump\t\tquery in hex, network order\n");
	fprintf(fp, "    3. hex dump\t\tanswer in hex, network order\n");
	fprintf(fp, "    4. empty line\n");
	fprintf(fp, "  The reason for 4. is that pcat-print now can be used on the output of pcat.\n");
}

void
data2hex(FILE *fp, u_char *p, size_t l)
{
	size_t i;
	for(i = 0; i < l; i++) {
		fprintf(fp, "%02x", (unsigned int) p[i]);
	}
	fputs("\n", fp);
}

/**
 * Converts a hex string to binary data
 * len is the length of the string
 * buf is the buffer to store the result in
 * offset is the starting position in the result buffer
 *
 * This function returns the length of the result
 */
static size_t
hexstr2bin(char *hexstr, int len, uint8_t *buf, size_t offset, size_t buf_len)
{
        char c;
        int i;
        uint8_t int8 = 0;
        int sec = 0;
        size_t bufpos = 0;

        if (len % 2 != 0) {
                return 0;
        }

        for (i=0; i<len; i++) {
                c = hexstr[i];

                /* case insensitive, skip spaces */
                if (c != ' ') {
                        if (c >= '0' && c <= '9') {
                                int8 += c & 0x0f;
                        } else if (c >= 'a' && c <= 'z') {
                                int8 += (c & 0x0f) + 9;
                        } else if (c >= 'A' && c <= 'Z') {
                                int8 += (c & 0x0f) + 9;
                        } else {
                                return 0;
                        }

                        if (sec == 0) {
                                int8 = int8 << 4;
                                sec = 1;
                        } else {
                                if (bufpos + offset + 1 <= buf_len) {
                                        buf[bufpos+offset] = int8;
                                        int8 = 0;
                                        sec = 0;
                                        bufpos++;
                                } else {
                                        fprintf(stderr, "Buffer too small in hexstr2bin");
					exit(1);
                                }
                        }
                }
        }
        return bufpos;
}

u_char *
pcap2ldns_pkt_ip(const u_char *packet, struct pcap_pkthdr *h)
{
	h->caplen -= DNS_UDP_OFFSET;
	if (h->caplen < 0) {
		return NULL;
	} else {
		return (u_char*)(packet + DNS_UDP_OFFSET);
	}
}

u_char *
pcap2ldns_pkt(const u_char *packet, struct pcap_pkthdr *h)
{
	struct ether_header *eptr;

	eptr = (struct ether_header *) h;
	switch(eptr->ether_type) {
		case ETHERTYPE_IP:
			return pcap2ldns_pkt_ip(packet, h);
			break;
		case ETHERTYPE_IPV6:
			break;
		case ETHERTYPE_ARP:
			fprintf(stderr, "ARP pkt, dropping\n");
			break;
		default:
			fprintf(stderr, "Not IP pkt, dropping\n");
			break;
	}
	return 0;
}

int
main(int argc, char **argv) 
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *p = NULL;
	struct pcap_pkthdr h;
	const u_char *x;
	size_t i = 0;
	ldns_rdf *ip;
	char *ip_str;
	int c;
	size_t failure;
	FILE *infile = NULL;
	int pcat_input_file = 0;

	uint8_t *result;
	uint16_t port;
	ldns_buffer *qpkt;
	u_char *q;
	size_t size;
	socklen_t tolen;
	size_t query_pkt_len;

	struct timeval timeout;
	struct sockaddr_storage *data;
	struct sockaddr_in  *data_in;
	
	ldns_status send_status;

	port = 0;
	ip = NULL;
	ip_str = NULL;
	failure = 0;

	while ((c = getopt(argc, argv, "ha:p:r")) != -1) {
		switch(c) {
		case 'h':
			usage(stdout);
			exit(EXIT_SUCCESS);
		case 'a':
			ip_str = optarg;
			ip = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, optarg);
			if (!ip) {
				fprintf(stderr, "-a requires an IP address\n");
				exit(EXIT_FAILURE);
			}
			break;
		case 'r':
			pcat_input_file = 1;
			break;
		case 'p':
			port = atoi(optarg);
			if (port == 0) {
				fprintf(stderr, "-p requires a port number\n");
				exit(EXIT_FAILURE);
			}
			break;
		default:
			usage(stdout);
			exit(EXIT_FAILURE);
		}
	}
	argc -= optind;
	argv += optind;

	if (port == 0)
		port = 53;

	if (!ip) {
		ip_str = "127.0.0.1";
		ip = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, "127.0.0.1");
	}

	if (pcat_input_file) {
		if (argc < 1) {
			infile = fopen("/dev/stdin", "r");
		} else {
			infile = fopen(argv[0], "r");
		}
		if (!infile) {
			fprintf(stderr, "Cannot open input file: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
	} else {
		if (argc < 1) {
			/* no file given - use standard input */
			p = pcap_open_offline("/dev/stdin", errbuf);
		} else {
			p = pcap_open_offline(argv[0], errbuf);
		}
		if (!p) {
			fprintf(stderr, "Cannot open pcap lib %s\n", errbuf);
			exit(EXIT_FAILURE);
		}
	}

	qpkt = ldns_buffer_new(LDNS_MAX_PACKETLEN);
	data = LDNS_MALLOC(struct sockaddr_storage);
	timeout.tv_sec = 5;
	timeout.tv_usec = 0;

	/* setup the socket */
	data->ss_family = AF_INET;
        data_in = (struct sockaddr_in*) data;
        data_in->sin_port = (in_port_t)htons(port);
        memcpy(&(data_in->sin_addr), ldns_rdf_data(ip), ldns_rdf_size(ip));
        tolen = sizeof(struct sockaddr_in);

	i = 1;  /* start counting at 1 */
	while (1) {
		if(pcat_input_file) {
			/* read pcat format and repeat query in it */
			char buf[65535*2+100];
			uint8_t decoded[65535+100];
			if(!fgets(buf, sizeof(buf), infile)) /* number */
				break;
			if(!fgets(buf, sizeof(buf), infile)) /* query */
				break;
			query_pkt_len = hexstr2bin(buf, strlen(buf)&0xfffffffe, 
				decoded, 0, sizeof(decoded));
			ldns_buffer_write(qpkt, decoded, query_pkt_len);

			if(!fgets(buf, sizeof(buf), infile)) /* answer */
				break;
			if(!fgets(buf, sizeof(buf), infile)) /* empty line */
				break;
		} else {
			if(!(x = pcap_next(p, &h)))
				break;
			q = pcap2ldns_pkt_ip(x, &h);
			ldns_buffer_write(qpkt, q, h.caplen);
			query_pkt_len = h.caplen;
		}

		send_status =ldns_udp_send(&result, qpkt, data, tolen, timeout, &size);
		if (send_status == LDNS_STATUS_OK) {
			/* double check if we are dealing with correct replies 
			 * by converting to a pkt... todo */
			fprintf(stdout, "%d\n", (int)i);
			/* query */
			data2hex(stdout, ldns_buffer_begin(qpkt), query_pkt_len); 
			/* answer */
			data2hex(stdout, result, size);
			fflush(stdout);
		} else {
			/* todo print failure */
			failure++;
			fprintf(stderr, "Failure to send packet %u (attempt %u, error %s)\n", i, (unsigned int) failure, ldns_get_errorstr_by_id(send_status));
			fprintf(stdout, "%d\n", (int)i);
			/* query */
			data2hex(stdout, ldns_buffer_begin(qpkt), query_pkt_len); 
			/* answer, thus empty */
			fprintf(stdout, "\n");
		}
		fputs("\n", stdout);
		ldns_buffer_clear(qpkt);
		i++;
		if (failure > FAILURE) {
			fprintf(stderr, "More than %u failures, bailing out\n", FAILURE);
			exit(EXIT_FAILURE);
		}
	}
	if(pcat_input_file)
		fclose(infile);
	else 	pcap_close(p);
	return 0;
}
