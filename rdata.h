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
#ifdef _RDATA_H
#else
#define _RDATA_H

#include <stdint.h>

enum enum_rdata_type 
{
	/** domain name */
	RD_DNAME_T,
	/** 8 bits */
	RD_INT8_T,
	/** 16 bits */
	RD_INT16_T,
	/** 32 bits */
	RD_INT32_T,
	/** 48 bits? */
	RD_INT48_T,
	/** A record */
	RD_A_T,	
	/** AAAA record */
	RD_AAAA_T,
	/** txt string */
	RD_STR_T,
	/** b64 string */
	RD_B64_T,
	/** hex string */
	RD_HEX_T,
	/** nsec type codes */
	RD_NSEC_T, 
	/** a RR type */
	RD_TYPE_T, 
	/** a class */
	RD_CLASS_T,
	/** certificates */
	RD_CERT_T,
	/** a key algorithm */
	RD_ALG_T,
	/** unknown types */
	RD_UNKNOWN_T,
	/** time */
	RD_TIME_T,
	/** protocol and port bitmaps */
	RD_SERVICE_T,
	/** location data */
	RD_LOC_T
};
typedef enum enum_rdata_type rd_type_t;

enum enum_class_type 
{
	/** the Internet */
	CLASS_IN 	= 1,
	/** Chaos class */
	CLASS_CHAOS	= 3,
	/** Hesiod (Dyer 87) */
	CLASS_HS	= 4,
	/** Any class */
	CLASS_ANY	= 255
};
typedef enum enum_class_type class_t;

/**
 * \brief Resource record data
 *
 * The data is a network ordered array of bytes, which size is specified by the (16-bit) size field.<br>
 * To correctly parse it, use the type specified in the (16-bit) type field.
 */
struct struct_rdata_t 
{
	/** \brief The size of the data (in bytes) */
	uint16_t _size;
	/** \brief The type of the data */
	rd_type_t _type;
	/** \brief Pointer to the data (byte buffer) */
	uint8_t  *_data;
};
typedef struct struct_rdata_t rdata_t;

/* prototypes */
uint16_t        rd_size(rdata_t *);
uint8_t         *rd_data(rdata_t *);
void            rd_set_size(rdata_t *, uint16_t);
void            rd_set_type(rdata_t *, rd_type_t);
void            rd_set_data(rdata_t *, uint8_t *, uint16_t);
rd_type_t       rd_type(rdata_t *);
rdata_t         *rd_new(uint16_t, rd_type_t, uint8_t *);
void            rd_destroy(rdata_t *);
#endif	/* _RDATA_H */

