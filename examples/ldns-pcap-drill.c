#include "config.h"

#include <ldns/dns.h>
#include <pcap.h>


#define ETHER_HDR_SIZE 14
#define UDP_HDR_SIZE 8
#define TCP_HDR_SIZE 0
#define IP6_HDR_SIZE 40

#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6 0x86dd
#endif

#define IP_HL(ip) 	(((ip)->ip_vhl) & 0x0f)

/** 
 * general layout
 *
 * read in a pcap file (tcpdumped)
 * walk over the packets, dump them when pcap_dump()
 * send packet to nameserver, ldns_send_udp
 * 	which can handle raw buffers
 * wait for an reply
 * also write this with pcap_dump
 */

int
pcap2ldns_pkt_ip(const u_char *packet, struct pcap_pkthdr *h)
{
	uint16_t i;
	ldns_status s = 0;
	
	ldns_pkt *dns;

	for(i = 0; i < h->caplen; i++) {
		if ((s = ldns_wire2pkt(&dns, packet + i, (h->caplen - i))) == LDNS_STATUS_OK) {
			printf("%d \n", i);
			ldns_pkt_print(stdout, dns);
		}
	}
	return 0;
}

int
pcap2ldns_pkt(const u_char *packet, struct pcap_pkthdr *h)
{
	struct ether_header *eptr;

	eptr = (struct ether_header *) h;
	switch(eptr->ether_type) {
		case ETHERTYPE_IP:
			return pcap2ldns_pkt_ip(packet, h);
			break;
		case ETHERTYPE_IPV6:
			/*
			return pcap2ldns_pkt_ip6(packet, h);
			*/
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

	if (!(p = pcap_open_offline("/tmp/K/20011009-134418-q50000.pkt", errbuf))) {
		printf("Cannot open pcap lib %s\n", errbuf);
	}

	while ((x = pcap_next(p, &h))) {
		 pcap2ldns_pkt_ip(x, &h); 
		i++;
	}
	printf("pkt seen %zd\n", i);
	pcap_close(p);
	return 0;
}

