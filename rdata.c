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
#include <string.h>

#include "prototype.h"

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
rd_set_data(rdata_t *rd, uint8_t *d, uint16_t s)
{
	rd->_data = xmalloc(s);
	memcpy(rd->_data, d, s);
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
	rd_set_data(new, d, s);

	return(new);
}

/* allocate a new rdata_t from
 * a NULL terminated string
 * and return it
 *
 * uint8_t == char !!!!
 */
rdata_t *
rd_new_frm_string(rd_type_t t, char *s)
{
	rdata_t *new;
	new = xmalloc(sizeof(rdata_t));

	if (NULL == new)
		return NULL;

	rd_set_size(new, (uint16_t)strlen(s));
	rd_set_type(new, t);
	rd_set_data(new, (uint8_t*) s, (uint16_t)strlen(s));

	return(new);
}

void rd_destroy(rdata_t *rd)
{
	/* empty */
}
