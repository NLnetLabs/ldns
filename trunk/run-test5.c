#include <config.h>
#include <ldns/ldns.h>

int
main()
{
	ldns_pkt *packet;
	
	printf("test 5\n");
	
	packet = ldns_pkt_query_new_frm_str("www.kanariepiet.com",
	                            LDNS_RR_TYPE_A,
	                            LDNS_RR_CLASS_IN);

	printf("Packet:\n");
	ldns_pkt_print(stdout, packet);
	
	
	return 0;
}


