#include <config.h>

#include <stdio.h>
#include <stdlib.h>
/*#include <stdint.h>*/
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <ldns/ldns.h>

#define	FOREVER		-1
#define	UDP_HDR_LEN	8

void
process_pkt(u_char *user, const struct pcap_pkthdr *pcap_hdr,
	const u_char *data)
{
	ldns_pkt *packet;
	struct ether_header *eth_hdr;
	struct ip *ip_hdr;
	struct udphdr *udp_hdr;
	int i, err, len;
	ldns_rr_list *question;

	eth_hdr = (struct ether_header *) data;
	len = pcap_hdr->caplen;

	printf("%02x:%02x:%02x:%02x:%02x:%02x",
		eth_hdr->ether_shost[0],
		eth_hdr->ether_shost[1],
		eth_hdr->ether_shost[2],
		eth_hdr->ether_shost[3],
		eth_hdr->ether_shost[4],
		eth_hdr->ether_shost[5]);
	printf(" -> %02x:%02x:%02x:%02x:%02x:%02x",
		eth_hdr->ether_dhost[0],
		eth_hdr->ether_dhost[1],
		eth_hdr->ether_dhost[2],
		eth_hdr->ether_dhost[3],
		eth_hdr->ether_dhost[4],
		eth_hdr->ether_dhost[5]);
	printf(" (0x%x)\n", eth_hdr->ether_type);

	/* handle IPv4 only for the time being */
	if (eth_hdr->ether_type != ETHERTYPE_IP) {
	/*	return;*/
	}
	
	/* skip Ethernet header */
	data += sizeof(struct ether_header);
	len -= sizeof(struct ether_header);

	ip_hdr = (struct ip *) data;

	/* handle UDP only */
	if (ip_hdr->ip_p != IPPROTO_UDP) {
		/*	return;*/
	}

	/* skip IP header */
	data += ip_hdr->ip_hl << 2;
	len -= ip_hdr->ip_hl << 2;

	udp_hdr = (struct udphdr *) data;

	printf(" %d.%d.%d.%d:%d",
		ip_hdr->ip_src.s_addr >> 24 & 0xff,
		ip_hdr->ip_src.s_addr >> 16 & 0xff,
		ip_hdr->ip_src.s_addr >> 8 & 0xff,
		ip_hdr->ip_src.s_addr & 0xff,
		udp_hdr->uh_sport);
	printf(" -> %d.%d.%d.%d:%d",
		ip_hdr->ip_dst.s_addr >> 24 & 0xff,
		ip_hdr->ip_dst.s_addr >> 16 & 0xff,
		ip_hdr->ip_dst.s_addr >> 8 & 0xff,
		ip_hdr->ip_dst.s_addr & 0xff,
		udp_hdr->uh_dport);
	printf(" %d", ip_hdr->ip_hl << 2);

	printf("\n");

	/* skip UDP header */
	data += UDP_HDR_LEN;
	len -= UDP_HDR_LEN;

	err = ldns_wire2pkt(&packet, data, len);
	if (err != LDNS_STATUS_OK) {
		return;
	}

	question = ldns_pkt_question(packet);
	printf("question count: %d\n", question->_rr_count);
	ldns_rr_list_print(stdout, question);
	printf("\n");
	/*
	for (i = 0; i < question->_rr_count; i++) {
		ldns_rr_print(stdout, question->_rrs[i]);
	}
	*/

}

int
main(int argc, char **argv)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *p;

	if (argc != 2) {
		fprintf(stderr, "usage: %s filename\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	if ((p = pcap_open_offline(argv[1], errbuf)) == NULL) {
		fprintf(stderr, "%s\n", errbuf);
		exit(EXIT_FAILURE);
	}
	pcap_loop(p, FOREVER, process_pkt, NULL);
}

