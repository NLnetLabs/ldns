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

#include <config.h>

#define MAXRDATALEN 64

enum type_enum_rdata
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
	/** apl data */
	RD_APL_T,
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
typedef enum type_enum_rdata t_rd_type;

enum type_enum_class
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
typedef enum type_enum_class t_class;

/**
 * \brief Resource record data
 *
 * The data is a network ordered array of bytes, which size is specified by the (16-bit) size field.<br>
 * To correctly parse it, use the type specified in the (16-bit) type field.
 */
struct type_struct_rdata_field 
{
	/** \brief The size of the data (in bytes) */
	uint16_t _size;
	/** \brief The type of the data */
	t_rd_type _type;
	/** \brief Pointer to the data (byte buffer) */
	uint8_t  *_data;
};
typedef struct type_struct_rdata_field t_rdata_field;

/* 
 * \brief struct to hold the whole set of rd_fields
 *
 * How does the whole rdata_field list look. This is called
 * the rdata in dns speak
 */
struct type_struct_rdata_field_descriptor
{
        uint16_t    type;       /* RR type */
        const char *name;       /* Textual name.  */
        uint8_t     minimum;    /* Minimum number of RDATA FIELDs.  */
        uint8_t     maximum;    /* Maximum number of RDATA FIELDs.  */
        uint8_t     wireformat[MAXRDATALEN]; /* rdata_wireformat_type */
};
typedef struct type_struct_rdata_field_descriptor t_rdata_field_descriptor;


/* prototypes */
uint16_t        rd_field_size(t_rdata_field *);
void            rd_field_set_size(t_rdata_field *, uint16_t);
void            rd_field_set_type(t_rdata_field *, t_rd_type);
void            rd_field_set_data(t_rdata_field *, uint8_t *, uint16_t);
t_rd_type       rd_field_type(t_rdata_field *);
t_rdata_field   *rd_field_new(uint16_t, t_rd_type, uint8_t *);
uint8_t         *rd_field_data(t_rdata_field *);
void            rd_field_destroy(t_rdata_field *);
#endif	/* _RDATA_H */
