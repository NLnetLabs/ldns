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


/* 
 * create a new rr structure.
 */
t_rr *
rr_new(void)
{
	t_rr *new;
        new = xmalloc(sizeof(t_rr));

        if (NULL == new)
                return NULL;

        return(new);
}


/* do we need access functions for all these members? */

/*
 * set the owner in the rr structure
 */
void
rr_set_owner(t_rr *rr, uint8_t owner)
{
	rr->_owner = owner;
}

/*
 * set the owner in the rr structure
 */
void
rr_set_ttl(t_rr *rr, uint16_t ttl)
{
	rr->_ttl = ttl;
}

void
rr_set_rd_count(t_rr *rr, uint16_t count)
{
	rr->_rd_count = count;
}

void
rr_set_class(t_rr *rr, t_class klass)
{
	rr->_klass = klass;
}


/*
 * return the owner name of an rr structure
 */
uint8_t
rr_owner(t_rr *rr)
{
	return (rr->_owner);
}

/*
 * return the owner name of an rr structure
 */
uint8_t
rr_ttl(t_rr *rr)
{
	return (rr->_ttl);
}
