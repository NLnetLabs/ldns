/*
 * util.h
 *  
 * helper function header file
 * 
 * a Net::DNS like library for C
 * 
 * (c) NLnet Labs, 2004
 * 
 * See the file LICENSE for the license
 */

#ifndef _UTIL_H
#define _UTIL_H

#include <ldns/rr.h>

/**
 * Memory management macro's
 */
#define MALLOC(type)		XMALLOC(type, 1)

#define XMALLOC(type, count)	((type *) malloc((count) * sizeof(type)))

#define REALLOC(ptr, type)	XREALLOC((ptr), type, 1)

#define XREALLOC(ptr, type, count)				\
	((type *) realloc((ptr), (count) * sizeof(type)))

#define FREE(ptr) \
	do { free((ptr)); (ptr) = NULL; } while (0)

#define DEP     printf("DEPRICATED FUNCTION!\n");

/*
 * Copy data allowing for unaligned accesses in network byte order
 * (big endian).
 */
#ifdef S_SPLINT_S

uint16_t read_uint16(const void *src);
uint32_t read_uint32(const void *src);

#else /* S_SPLINT_S */

static inline uint16_t
read_uint16(const void *src)
{
#ifdef ALLOW_UNALIGNED_ACCESSES
	return ntohs(*(uint16_t *) src);
#else
	uint8_t *p = (uint8_t *) src;
	return ((uint16_t) p[0] << 8) | (uint16_t) p[1];
#endif
}

static inline uint32_t
read_uint32(const void *src)
{
#ifdef ALLOW_UNALIGNED_ACCESSES
	return ntohl(*(uint32_t *) src);
#else
	uint8_t *p = (uint8_t *) src;
	return (  ((uint32_t) p[0] << 24)
		| ((uint32_t) p[1] << 16)
		| ((uint32_t) p[2] << 8)
		|  (uint32_t) p[3]);
#endif
}

#endif /* !S_SPLINT_S */

/* prototypes */
void    xprintf_rdf(ldns_rdf *);
void    xprintf_rr(ldns_rr *);

#endif /* !_UTIL_H */
