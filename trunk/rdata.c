/*
 * rdata.c
 *
 * rdata implementation
 *
 * a Net::DNS like library for C
 *
 * (c) NLnet Labs, 2004
 *
 * See the file LICENSE for the license
 */

#include <stdint.h>

#include "prototype.h"
#include "rdata.h"

/* Access functions 
 * do this as functions to get type checking
 */

/* read */
uint16_t
rd_size(rdata_t *rd)
{
	return rd->_size;
}

rd_type_t
rd_type(rdata_t *rd)
{
	return rd->_type;
}

uint8_t *
rd_data(rdata_t *rd)
{
	return rd->_data;
}

/* write */
void
rd_set_size(rdata_t *rd, uint16_t s)
{
	rd->_size = s;
}

void
rd_set_type(rdata_t *rd, rd_type_t t)
{
	rd->_type = t;
}

void
rd_set_data(rdata_t *rd, uint8_t *d)
{
	rd->_data = d;
}

/* allocate a new rdata_t structure 
 * and return it
 */
rdata_t *
rd_new(uint16_t s, rd_type_t t, uint8_t *d)
{
	rdata_t *new;
	new = xmalloc(sizeof(rdata_t));

	if (NULL == new)
		return NULL;

	rd_set_size(new, s);
	rd_set_type(new, t);
	rd_set_data(new, d);

	return(new);
}
