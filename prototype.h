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

/* util.c */
void 	*xmalloc(size_t);
void 	*xrealloc(void *, size_t);
void	xprintf_rd_field(t_rdata_field *);
void	xprintf_rr(t_rr *);

#endif /* _PROTOTYPE_H */
