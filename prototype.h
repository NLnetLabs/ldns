/*
 * prototype.h
 *
 * general prototyps
 *
 * a Net::DNS like library for C
 *
 * (c) NLnet Labs, 2004
 *
 * See the file LICENSE for the license
 */
#include <stdint.h>
#include <stdlib.h>

#include "rdata.h"
/* util.c */
void 		*xmalloc(size_t);

/* rdata.c */
uint16_t	rd_size(rdata_t *);
uint8_t 	*rd_data(rdata_t *);
void 		rd_set_size(rdata_t *, uint16_t);
void 		rd_set_type(rdata_t *, rd_type_t);
void 		rd_set_data(rdata_t *, uint8_t *);
rd_type_t 	rd_type(rdata_t *);
rdata_t 	*rd_new(uint16_t, rd_type_t, uint8_t *);
