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

	rr = rr_new();

	rd_f = rd_field_new(20, RD_DNAME_T, (uint8_t*)"hallo.nl");
	xprintf_rd_field(rd_f);
	
	rr_push_rd_field(rr, rd_f);

	xprintf_rr(rr);
	return 0;
}
