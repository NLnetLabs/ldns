/* 
 * test main.c
 *
 */

#include <stdio.h>

#include "prototype.h"

int
main(void)
{
	rdata_t *new;
	printf("size %u\n", sizeof(struct struct_rdata_t));
	new = rd_new(20, RD_DNAME_T, (uint8_t*)"hallo.nl");

	printf("Hallo\n");
	return 0;
}
