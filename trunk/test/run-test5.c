#include <config.h>
#include <ldns/ldns.h>

int
main()
{
	ldns_pkt *packet;
	
	printf("test 5\n");
	packet = ldns_pkt_query_new_frm_str("www.kanariepiet.com",
	                            LDNS_RR_TYPE_A,
	                            LDNS_RR_CLASS_IN, 0);

	printf("Packet:\n");
	if (packet) 
		ldns_pkt_print(stdout, packet);
	ldns_pkt_free(packet);

	printf("test 5\n");
	packet = ldns_pkt_query_new_frm_str("www.kanariepiet.com",
	                            LDNS_RR_TYPE_A,
	                            LDNS_RR_CLASS_IN, (uint16_t) (LDNS_AD | LDNS_AA));

	printf("Packet:\n");
/*
	if (packet) 
		ldns_pkt_print(stdout, packet);
*/
	
	ldns_pkt_free(packet);
	
	return 0;
}


