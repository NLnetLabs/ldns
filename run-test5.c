#include <config.h>
#include <ldns/ldns.h>

int
main(int argc, char **argv)
{
	ldns_pkt *packet;
	char *str;
	
	printf("test 5\n");
	
	packet = ldns_pkt_query_new_frm_str("www.kanariepiet.com",
	                            LDNS_RR_TYPE_A,
	                            LDNS_RR_CLASS_IN);

	str = ldns_pkt2str(packet);
	
	printf("packet:\n%s\n\n", str);
	
	
	return 0;
}


