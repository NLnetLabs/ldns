/*
 * rdata.h
 *
 * rdata definitions
 *
 * a Net::DNS like library for C
 *
 * (c) NLnet Labs, 2004
 *
 * See the file LICENSE for the license
 */

#include <stdint.h>

enum enum_rdata_type {
	RD_DNAME_T,	/* domain name */
	RD_INT8_T,	/* 8 bits */
	RD_INT16_T,	/* 16 bits */
	RD_INT32_T,	/* 32 bits */
	RD_INT48_T,	/* 48 bits? */
	RD_A_T,		/* A record */
	RD_AAAA_T,	/* AAAA record */
	RD_STR_T,	/* txt string */
	RD_B64_T,	/* b64 string */
	RD_HEX_T,	/* hex string */
	RD_NSEC_T, 	/* nsec type codes */
	RD_TYPE_T, 	/* a RR type */
	RD_CLASS_T,	/* a class */
	RD_CERT_T,	/* certificates */
	RD_ALG_T	/* a key algorithm */
};
typedef enum enum_rdata_type rd_type_t;

/* 
 * the basic data type
 * 16 bits size
 * 16 bits type 
 * size uint8_t's bytes of the actual data
 * data = network order, expanded (no compression)
 */

struct {
	uint16_t _size;
	rd_type_t _type;
	uint8_t  *_data;
} struct_rdata_t;
typedef struct struct_rdata_t rdata_t;
