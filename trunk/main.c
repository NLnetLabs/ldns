/* 
 * test main.c
 *
 */

#include <stdio.h>

#include "prototype.h"
#include "rdata.h"
#include "rr.h"
#include "packet.h"

int
main(void)
{
	rdata_t *new;
	printf("size %u\n", (unsigned int)sizeof(struct struct_rdata_t));

	new = rd_new(20, RD_DNAME_T, (uint8_t*)"hallo.nl");
	xprintf_rd(new);
	return 0;
}
