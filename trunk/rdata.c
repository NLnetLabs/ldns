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
rd_type(rdata_t *rd, rd_type_t t)
{
	rd->_type = t;
}

void
rd_data(rdata_t *rd, uint8_t *d)
{
	rd->_data = d;
}
