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
#ifdef _PROTOTYPE_H
#else
#define _PROTOTYPE_H

#include <stdint.h>
#include <stdlib.h>

/* util.c */
void 		*xmalloc(size_t);
void		xprintf_rd(rdata_t *);

#endif /* _PROTOTYPE_H */
