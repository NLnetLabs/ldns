#include "config.h"

#include <ldns/dns.h>

#include <netinet/ip6.h>
#include <errno.h>

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
main(int argc, char **argv) 
{
	
	return 1;

}
