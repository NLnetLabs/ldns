#ifdef HAVE_GETDELIM
#define _GNU_SOURCE
#endif

#include "config.h"

#include <ldns/ldns.h>
#include <pcap.h>

#define FAILURE 100


#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6 	0x86dd
#endif
#define DNS_UDP_OFFSET 	42

#ifndef HAVE_GETDELIM
ssize_t getdelim(char **lineptr, size_t *n, int delim, FILE *stream);
#endif

/* output: see usage() */

void
usage(FILE *fp)
{
	fprintf(fp, "pcat [-a IP] [-p PORT] PCAP_FILE\n\n");
	fprintf(fp, "   -a IP\tuse IP as nameserver, defaults to 127.0.0.1\n");
	fprintf(fp, "   -p PORT\tuse PORT as port, defaults to 53\n");
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
		fprintf(fp, "%02x", p[i]);
	}
	fputs("\n", fp);
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
	pcap_t *p;
	struct pcap_pkthdr h;
	const u_char *x;
	size_t i = 0;
	ldns_rdf *ip;
	char *ip_str;
	int c;
	size_t failure;

	uint8_t *result;
	uint16_t port;
	ldns_buffer *qpkt;
	u_char *q;
	size_t size;
	socklen_t tolen;

	struct timeval timeout;
	struct sockaddr_storage *data;
	struct sockaddr_in  *data_in;

	port = 0;
	ip = NULL;
	ip_str = NULL;
	failure = 0;

	while ((c = getopt(argc, argv, "ha:p:")) != -1) {
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

	if (argc < 1) {
		/* no file given - use standard input */
		p = pcap_fopen_offline(stdin, errbuf);
	} else {
		p = pcap_open_offline(argv[0], errbuf);
	}
	if (!p) {
		fprintf(stderr, "Cannot open pcap lib %s\n", errbuf);
		exit(EXIT_FAILURE);
	}

	qpkt = ldns_buffer_new(LDNS_MAX_PACKETLEN);
	data = LDNS_MALLOC(struct sockaddr_storage);
	timeout.tv_sec = 2;
	timeout.tv_usec = 0;

	/* setup the socket */
	data->ss_family = AF_INET;
        data_in = (struct sockaddr_in*) data;
        data_in->sin_port = (in_port_t)htons(port);
        memcpy(&(data_in->sin_addr), ldns_rdf_data(ip), ldns_rdf_size(ip));
        tolen = sizeof(struct sockaddr_in);

	i = 1;  /* start counting at 1 */
	while ((x = pcap_next(p, &h))) {
		q = pcap2ldns_pkt_ip(x, &h);
		ldns_buffer_write(qpkt, q, h.caplen);

		if (ldns_udp_send(&result, qpkt, data, tolen, timeout, &size) ==
				LDNS_STATUS_OK) {
			/* double check if we are dealing with correct replies 
			 * by converting to a pkt... todo */
			fprintf(stdout, "%zd\n", i);
			/* query */
			data2hex(stdout, q, h.caplen); 
			/* answer */
			data2hex(stdout, result, size);
		} else {
			/* todo print failure */
			failure++;
			fprintf(stderr, "Failure to send packet\n");
			fprintf(stdout, "%zd\n", i);
			/* query */
			data2hex(stdout, q, h.caplen); 
			/* answer, thus empty */
			fprintf(stdout, "\n");
		}
		fputs("\n", stdout);
		ldns_buffer_clear(qpkt);
		i++;
		if (failure > FAILURE) {
			fprintf(stderr, "More then 100 failures, bailing out\n");
			exit(EXIT_FAILURE);
		}
	}
	pcap_close(p);
	return 0;
}
