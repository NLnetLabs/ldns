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
#ifndef _PROTOTYPE_H
#define _PROTOTYPE_H
#else

#include <stdint.h>
#include <stdlib.h>

#ifndef _RDATA_H
#include "rdata.h"
#endif /* _RDATA_H */
#ifndef _RR_H
#include "rr.h"
#endif /* _RR_H */
#ifndef _PACKET_H
#include "packet.h"
#endif /* _PACKET_H */

/* util.c */
void 		*xmalloc(size_t);
void		xprintf_rd(rdata_t *);

/* rdata.c */
uint16_t	rd_size(rdata_t *);
uint8_t 	*rd_data(rdata_t *);
void 		rd_set_size(rdata_t *, uint16_t);
void 		rd_set_type(rdata_t *, rd_type_t);
void 		rd_set_data(rdata_t *, uint8_t *, uint16_t);
rd_type_t 	rd_type(rdata_t *);
rdata_t 	*rd_new(uint16_t, rd_type_t, uint8_t *);
void		rd_destroy(rdata_t *);

#endif /* _PROTOTYPE_H */
