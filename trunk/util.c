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

#include <ldns/rdata.h>
#include <ldns/rr.h>

/* put this here tmp. for debugging */
void
xprintf_rd_field(t_rdata_field *rd)
{
	/* assume printable string */
	fprintf(stdout, "size\t:%u\n", (unsigned int)_ldns_rd_field_size(rd));
	fprintf(stdout, "type\t:%u\n", (unsigned int)_ldns_rd_field_type(rd));
	fprintf(stdout, "data\t:[%.*s]\n", (int)_ldns_rd_field_size(rd), (char*)_ldns_rd_field_data(rd));
}

void
xprintf_rr(ldns_rr_type *rr)
{
	/* assume printable string */
	uint16_t count, i;

	count = ldns_rr_rd_count(rr);

	for(i = 0; i < count; i++) {
		printf("print rd %u\n", (unsigned int) i);
		xprintf_rd_field(rr->_rdata_fields[i]);
	}
}
