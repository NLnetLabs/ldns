/* 
 * test main.c
 *
 */

#include <stdio.h>

#include "rdata.h"
#include "rr.h"
#include "packet.h"
#include "prototype.h"

int
main(void)
{
	t_rdata_field *new;

	new = rd_new(20, RD_DNAME_T, (uint8_t*)"hallo.nl");
	xprintf_rd_field(new);
	return 0;
}
