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

#include <config.h>

#include "rdata.h"
#include "prototype.h"

/* Access functions 
 * do this as functions to get type checking
 */

/* read */
uint16_t
rd_field_size(t_rdata_field *rd)
{
	return rd->_size;
}

t_rd_type
rd_field_type(t_rdata_field *rd)
{
	return rd->_type;
}

uint8_t *
rd_field_data(t_rdata_field *rd)
{
	return rd->_data;
}

/* write */
void
rd_field_set_size(t_rdata_field *rd, uint16_t s)
{
	rd->_size = s;
}

void
rd_field_set_type(t_rdata_field *rd, t_rd_type t)
{
	rd->_type = t;
}

void
rd_field_set_data(t_rdata_field *rd, uint8_t *d, uint16_t s)
{
	rd->_data = xmalloc(s);
	memcpy(rd->_data, d, s);
}

/* allocate a new t_rdata_field structure 
 * and return it
 */
t_rdata_field *
rd_field_new(uint16_t s, t_rd_type t, uint8_t *d)
{
	t_rdata_field *new;
	new = xmalloc(sizeof(t_rdata_field));

	if (NULL == new)
		return NULL;

	rd_field_set_size(new, s);
	rd_field_set_type(new, t);
	rd_field_set_data(new, d, s);

	return(new);
}

/* allocate a new t_rdata_field from
 * a NULL terminated string
 * and return it
 *
 * uint8_t == char !!!!
 */
t_rdata_field *
rd_field_new_frm_string(t_rd_type t, char *s)
{
	t_rdata_field *new;
	new = xmalloc(sizeof(t_rdata_field));

	if (NULL == new)
		return NULL;

	rd_field_set_size(new, (uint16_t)strlen(s));
	rd_field_set_type(new, t);
	rd_field_set_data(new, (uint8_t*) s, (uint16_t)strlen(s));

	return(new);
}

void rd_field_destroy(t_rdata_field *rd)
{
	rd = NULL; /* kuch */
	/* empty */
}
