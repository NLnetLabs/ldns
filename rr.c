/*
 * rr.c
 *
 * access function for t_rr
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
#include "prototype.h"
#include "util.h"

/**
 * create a new rr structure.
 */
t_rr *
ldns_rr_new(void)
{
	t_rr *rr;
	MALLOC(rr, t_rr);
        if (!rr)
                return NULL;

	ldns_rr_set_rd_count(rr, 0);
	rr->_rdata_fields = NULL; /* XXX */
        return(rr);
}

/**
 * set the owner in the rr structure
 */
void
ldns_rr_set_owner(t_rr *rr, uint8_t *owner)
{
	rr->_owner = owner;
}

/**
 * set the owner in the rr structure
 */
void
ldns_rr_set_ttl(t_rr *rr, uint16_t ttl)
{
	rr->_ttl = ttl;
}

/**
 * set the rd_count in the rr
 */
void
ldns_rr_set_rd_count(t_rr *rr, uint16_t count)
{
	rr->_rd_count = count;
}

/**
 * set the class in the rr
 */
void
ldns_rr_set_class(t_rr *rr, t_class klass)
{
	rr->_klass = klass;
}

/**
 * set rd_field member in the rr, it will be 
 * placed in the next available spot
 */
void
ldns_rr_push_rd_field(t_rr *rr, t_rdata_field *f)
{
	uint16_t rd_count;

	rd_count = ldns_rr_rd_count(rr);
	
	/* grow the array */
	XREALLOC(rr->_rdata_fields, t_rdata_field *, rd_count + 1);

	/* add the new member */
	rr->_rdata_fields[rd_count] = f;

	ldns_rr_set_rd_count(rr, rd_count + 1);
}

/**
 * return the owner name of an rr structure
 */
uint8_t *
ldns_rr_owner(t_rr *rr)
{
	return rr->_owner;
}

/**
 * return the owner name of an rr structure
 */
uint8_t
ldns_rr_ttl(t_rr *rr)
{
	return rr->_ttl;
}

/**
 * return the rd_count of an rr structure
 */
uint16_t
ldns_rr_rd_count(t_rr *rr)
{
	return rr->_rd_count;
}
