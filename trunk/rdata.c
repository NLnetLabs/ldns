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

#include <ldns/rdata.h>

#include "util.h"

/* Access functions 
 * do this as functions to get type checking
 */

/* read */
uint16_t
_ldns_rd_field_size(t_rdata_field *rd)
{
	return rd->_size;
}

ldns_rdata_field_type
_ldns_rd_field_type(t_rdata_field *rd)
{
	return rd->_type;
}

uint8_t *
_ldns_rd_field_data(t_rdata_field *rd)
{
	return rd->_data;
}

/* write */
void
_ldns_rd_field_set_size(t_rdata_field *rd, uint16_t s)
{
	rd->_size = s;
}

void
_ldns_rd_field_set_type(t_rdata_field *rd, ldns_rdata_field_type t)
{
	rd->_type = t;
}

void
_ldns_rd_field_set_data(t_rdata_field *rd, uint8_t *d)
{
	/* only copy the pointer */
	rd->_data = d;
}

/**
 * Allocate a new t_rdata_field structure 
 * and return it
 */
t_rdata_field *
_ldns_rd_field_new(uint16_t s, ldns_rdata_field_type t, uint8_t *d)
{
	t_rdata_field *rd;
	rd = MALLOC(t_rdata_field);
	if (!rd) {
		return NULL;
	}

	_ldns_rd_field_set_size(rd, s);
	_ldns_rd_field_set_type(rd, t);
	_ldns_rd_field_set_data(rd, d);

	return rd;
}

/**
 * Allocate a new t_rdata_field from
 * a NULL terminated string
 * and return it
 */
t_rdata_field *
_ldns_rd_field_new_frm_string(ldns_rdata_field_type t, char *s)
{
	return NULL;
}

void 
_ldns_rd_field_destroy(t_rdata_field *rd)
{
	rd = NULL; /* kuch */
	/* empty */
}

