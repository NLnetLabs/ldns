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

#include "common.h"
#include "rdata.h"
#include "rr.h"

void *
xmalloc(size_t s)
{
	void *p;
	
	p = (void*)malloc(s);

	return p;
}

/* put this here tmp. for debugging */
void
xprintf_rd_field(t_rdata_field *rd)
{
	/* assume printable string */
	fprintf(stdout, "size\t:%u\n", (unsigned int)rd_size(rd));
	fprintf(stdout, "type\t:%u\n", (unsigned int)rd_type(rd));
	fprintf(stdout, "data\t:[%.*s]\n", (int)rd_size(rd), (char*)rd_data(rd));
}
