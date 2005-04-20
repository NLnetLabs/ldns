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

#define dprintf(X,Y) fprintf(stderr, (X), (Y))
/* #define	dprintf(X, Y)  */

/**
 * splint static inline workaround
 */
#ifdef S_SPLINT_S
#define INLINE 
#else
#define INLINE static inline
#endif

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

#define DEP     printf("DEPRECATED FUNCTION!\n");

/*
 * Copy data allowing for unaligned accesses in network byte order
 * (big endian).
 */
INLINE uint16_t
read_uint16(const void *src)
{
#ifdef ALLOW_UNALIGNED_ACCESSES
	return ntohs(*(uint16_t *) src);
#else
	uint8_t *p = (uint8_t *) src;
	return ((uint16_t) p[0] << 8) | (uint16_t) p[1];
#endif
}

INLINE uint32_t
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

/*
 * Copy data allowing for unaligned accesses in network byte order
 * (big endian).
 */
INLINE void
write_uint16(void *dst, uint16_t data)
{
#ifdef ALLOW_UNALIGNED_ACCESSES
	* (uint16_t *) dst = htons(data);
#else
	uint8_t *p = (uint8_t *) dst;
	p[0] = (uint8_t) ((data >> 8) & 0xff);
	p[1] = (uint8_t) (data & 0xff);
#endif
}

INLINE void
write_uint32(void *dst, uint32_t data)
{
#ifdef ALLOW_UNALIGNED_ACCESSES
	* (uint32_t *) dst = htonl(data);
#else
	uint8_t *p = (uint8_t *) dst;
	p[0] = (uint8_t) ((data >> 24) & 0xff);
	p[1] = (uint8_t) ((data >> 16) & 0xff);
	p[2] = (uint8_t) ((data >> 8) & 0xff);
	p[3] = (uint8_t) (data & 0xff);
#endif
}

/* warning. */
INLINE void
write_uint64_as_uint48(void *dst, uint64_t data)
{
	uint8_t *p = (uint8_t *) dst;
	p[0] = (uint8_t) ((data >> 40) & 0xff);
	p[1] = (uint8_t) ((data >> 32) & 0xff);
	p[2] = (uint8_t) ((data >> 24) & 0xff);
	p[3] = (uint8_t) ((data >> 16) & 0xff);
	p[4] = (uint8_t) ((data >> 8) & 0xff);
	p[5] = (uint8_t) (data & 0xff);
}

/* A general purpose lookup table */
typedef struct lookup_table ldns_lookup_table;
struct lookup_table {
        int id;
        const char *name;
};
  
/**
 * Looks up the table entry by name, returns NULL if not found.
 */
ldns_lookup_table *ldns_lookup_by_name(ldns_lookup_table table[],
                                       const char *name);

/**
 * Looks up the table entry by id, returns NULL if not found.
 */
ldns_lookup_table *ldns_lookup_by_id(ldns_lookup_table table[], int id);

/**
 * Returns the value of the specified bit
 * The bits are counted from left to right, so bit #0 is the
 * left most bit.
 */
int get_bit(uint8_t bits[], size_t index);


/**
 * Returns the value of the specified bit
 * The bits are counted from right to left, so bit #0 is the
 * right most bit.
 */
int get_bit_r(uint8_t bits[], size_t index);

/**
 * Returns the value of a to the power of b
 * (or 1 of b < 1)
 */
long power(long a, long b); 

/**
 * Returns the int value of the given (hex) digit
 */
int hexdigit_to_int(char ch);

/**
 * Returns the char (hex) representation of the given int
 */
char int_to_hexdigit(int ch);

#endif /* !_UTIL_H */
