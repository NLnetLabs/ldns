/*
 * util.c
 *
 * some general memory functions
 *
 * a Net::DNS like library for C
 *
 * (c) NLnet Labs, 2004
 *
 * See the file LICENSE for the license
 */

#include <config.h>

#include "rdata.h"
#include "rr.h"

/* put this here tmp. for debugging */
void
xprintf_rd_field(t_rdata_field *rd)
{
	/* assume printable string */
	fprintf(stdout, "size\t:%u\n", (unsigned int)rd_field_size(rd));
	fprintf(stdout, "type\t:%u\n", (unsigned int)rd_field_type(rd));
	fprintf(stdout, "data\t:[%.*s]\n", (int)rd_field_size(rd), (char*)rd_field_data(rd));
}

void
xprintf_rr(t_rr *rr)
{
	/* assume printable string */
	uint16_t count, i;

	count = rr_rd_count(rr);

	for(i = 0; i < count; i++) {
		printf("print rd %u\n", i);
		xprintf_rd_field(rr->_rdata_fields[i]);
	}
}
