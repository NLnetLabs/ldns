/* 
 * test main.c
 *
 */

#include <config.h>

#include "rdata.h"
#include "rr.h"
#include "packet.h"
#include "prototype.h"

int
main(void)
{
	t_rdata_field *rd_f;
	t_rr *rr;
	uint8_t *wire;
	t_packet *packet;
	
	rr = rr_new();

	rd_f = rd_field_new(20, RD_DNAME_T, (uint8_t*)"hallo.nl");
	xprintf_rd_field(rd_f);
	
	rr_push_rd_field(rr, rd_f);

	xprintf_rr(rr);

	wire = xmalloc(100);
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
	
	packet = dns_packet_new();
	dns_wire2packet(wire, packet);
	
	printf("packet id: %d\n", packet_id(packet));
	printf("qr bit: %d\n", packet_qr(packet));
	printf("opcode: %d\n", packet_opcode(packet));
	printf("aa bit: %d\n", packet_aa(packet));
	printf("tc bit: %d\n", packet_tc(packet));
	printf("rd bit: %d\n", packet_rd(packet));
	printf("cd bit: %d\n", packet_cd(packet));
	printf("ra bit: %d\n", packet_ra(packet));
	printf("ad bit: %d\n", packet_ad(packet));
	printf("rcode: %d\n", packet_rcode(packet));
	printf("qdcount: %d\n", packet_qdcount(packet));
	printf("ancount: %d\n", packet_ancount(packet));
	printf("nscount: %d\n", packet_nscount(packet));
	printf("arcount: %d\n", packet_arcount(packet));
	return 0;
}
