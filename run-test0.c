/* 
 * test main.c
 *
 */

#include <config.h>

#include <ldns/ldns.h>

#include "util.h"

int
main(void)
{
	t_rdata_field *rd_f;
	t_rr *rr;
	uint8_t *wire;
	t_packet *packet;
	
	rr = ldns_rr_new();

	rd_f = _ldns_rd_field_new(20, RD_DNAME_T, (uint8_t*)"hallo.nl");
	xprintf_rd_field(rd_f);
	
	ldns_rr_push_rd_field(rr, rd_f);

	xprintf_rr(rr);

	XMALLOC(wire, uint8_t, 100);
	wire[0] = 0xc2;
	wire[1] = 0xb4;
	wire[2] = 0x81;
	wire[3] = 0x80;
	wire[4] = 0x00;
	wire[5] = 0x01;
	wire[6] = 0x00;
	wire[7] = 0x01;
	wire[8] = 0x00;
	wire[9] = 0x02;
	wire[10] = 0x00;
	wire[11] = 0x02;
	wire[12] = 0x03;
	wire[13] = 0x77;
	wire[14] = 0x77;
	wire[15] = 0x77;
	wire[16] = 0x0b;
	wire[17] = 0x6b;
	wire[18] = 0x61;
	wire[19] = 0x6e;
	
	packet = ldns_packet_new();
	(void) ldns_wire2packet(wire, 20, packet);
	
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
	return 0;
}
