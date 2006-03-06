#include "config.h"

#include <ldns/dns.h>
#include <pcap.h>

#define DNS_OFFSET 42

#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6 0x86dd
#endif


void
usage(FILE *fp, char *progname)
{
	fprintf(fp, "%s: [-a IP] [-p PORT} PCAP_FILE\n\n");
	fprintf(fp, "   -a IP\tuse IP as nameserver\n");
	fprintf(fp, "   -p PORT\tuse POTR as port\n");
	fprintf(fp, "  PCAP_FILE\tuse this file as source\n");
	fprintf(fp, "  If no file is given standard output is read\n\n");
	fprintf(fp, "  if no address is given 127.0.0.1 port 53 is user\n");
}


u_char *
pcap2ldns_pkt_ip(const u_char *packet, struct pcap_pkthdr *h)
{

	h->caplen=-DNS_OFFSET;
	return (u_char*)(packet + DNS_OFFSET);
#if 0
	if (ldns_wire2pkt(&dns, packet + DNS_OFFSET
					, (h->caplen - DNS_OFFSET)) == LDNS_STATUS_OK) {
 	ldns_pkt_print(stdout, dns); 
	}
#endif
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
	ldns_pkt *rpkt;

	uint8_t *result;
	ldns_buffer *qpkt;
	size_t size;
	socklen_t tolen;

	struct timeval timeout;
	struct sockaddr_storage *data;
	struct sockaddr_in  *data_in;

	ip = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, "127.0.0.1");
	data = LDNS_MALLOC(struct sockaddr_storage);
	timeout.tv_sec = 2;
	timeout.tv_usec = 0;

	data->ss_family = AF_INET;
        data_in = (struct sockaddr_in*) data;
        data_in->sin_port = (in_port_t)htons(53);
        memcpy(&(data_in->sin_addr), ldns_rdf_data(ip), ldns_rdf_size(ip));
        tolen = sizeof(struct sockaddr_in);

	if (!(p = pcap_open_offline("./20011009-134418-q50000.pkt", errbuf))) {
		fprintf(stderr, "Cannot open pcap lib %s\n", errbuf);
		exit(EXIT_FAILURE);
	}

	qpkt = ldns_buffer_new(LDNS_MAX_PACKETLEN);

	while ((x = pcap_next(p, &h))) {
		ldns_buffer_write(qpkt,
				pcap2ldns_pkt_ip(x, &h),
				h.caplen);

		if (ldns_udp_send(&result, qpkt, data, tolen, timeout, &size) ==
				LDNS_STATUS_OK) {
			ldns_wire2pkt(&rpkt, result, size);
			ldns_pkt_print(stdout, rpkt);
		}

		ldns_buffer_clear(qpkt);
		
		i++;

		printf("pkt seen %zd\n", i);
	}
	pcap_close(p);
	return 0;
}
