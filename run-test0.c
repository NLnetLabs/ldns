/* 
 * test main.c
 *
 */

#include <config.h>

#include <ldns/ldns.h>

#include "util.h"

static const uint8_t wire[] = {
	0xc2, 0xb4, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
	0x00, 0x02, 0x00, 0x02, 0x03, 0x77, 0x77, 0x77,
	0x0b, 0x6b, 0x61, 0x6e, 0x61, 0x72, 0x69, 0x65,
	0x70, 0x69, 0x65, 0x74, 0x03, 0x63, 0x6f, 0x6d,
	0x00, 0x00, 0x01, 0x00, 0x01
};

int
main(void)
{
	t_rdata_field *rd_f;
	ldns_rr_type *rr;
	ldns_packet_type *packet;
	
	rr = ldns_rr_new();

	rd_f = _ldns_rd_field_new(20, RD_DNAME_T, (uint8_t*)"hallo.nl");
	xprintf_rd_field(rd_f);
	
	ldns_rr_push_rd_field(rr, rd_f);

	xprintf_rr(rr);

	packet = ldns_packet_new();
	(void) ldns_wire2packet(packet, wire, sizeof(wire));
	
	printf("packet id: %d\n", (int) packet_id(packet));
	printf("qr bit: %d\n", (int) packet_qr(packet));
	printf("opcode: %d\n",(int) packet_opcode(packet));
	printf("aa bit: %d\n",(int) packet_aa(packet));
	printf("tc bit: %d\n",(int) packet_tc(packet));
	printf("rd bit: %d\n",(int) packet_rd(packet));
	printf("cd bit: %d\n",(int) packet_cd(packet));
	printf("ra bit: %d\n",(int) packet_ra(packet));
	printf("ad bit: %d\n",(int) packet_ad(packet));
	printf("rcode: %d\n",(int) packet_rcode(packet));
	printf("qdcount: %d\n",(int) packet_qdcount(packet));
	printf("ancount: %d\n",(int) packet_ancount(packet));
	printf("nscount: %d\n",(int) packet_nscount(packet));
	printf("arcount: %d\n",(int) packet_arcount(packet));

	ldns_packet_free(packet);
	return 0;
}
