/*
 * 
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

#ifndef _LDNS_RDATA_H
#define _LDNS_RDATA_H

#include <ldns/common.h>
#include <ldns/error.h>

#define MAX_RDFLEN	65535

/**
 * The different types of RDATA fields.
 */
enum ldns_enum_rdf_type
{
	/** none */
	LDNS_RDF_TYPE_NONE,
	/** domain name */
	LDNS_RDF_TYPE_DNAME,
	/** 8 bits */
	LDNS_RDF_TYPE_INT8,
	/** 16 bits */
	LDNS_RDF_TYPE_INT16,
	/** 32 bits */
	LDNS_RDF_TYPE_INT32,
	/** A record */
	LDNS_RDF_TYPE_A,	
	/** AAAA record */
	LDNS_RDF_TYPE_AAAA,
	/** txt string */
	LDNS_RDF_TYPE_STR,
	/** apl data */
	LDNS_RDF_TYPE_APL,
	/** b64 string */
	LDNS_RDF_TYPE_B64,
	/** hex string */
	LDNS_RDF_TYPE_HEX,
	/** nsec type codes */
	LDNS_RDF_TYPE_NSEC, 
	/** a RR type */
	LDNS_RDF_TYPE_TYPE, 
	/** a class */
	LDNS_RDF_TYPE_CLASS,
	/** certificates */
	LDNS_RDF_TYPE_CERT,
	/** a key algorithm */
	LDNS_RDF_TYPE_ALG,
	/** unknown types */
	LDNS_RDF_TYPE_UNKNOWN,
	/** time */
	LDNS_RDF_TYPE_TIME,
	/** tsig time 48 bits */
	/** period */
	LDNS_RDF_TYPE_PERIOD,
	LDNS_RDF_TYPE_TSIGTIME,
	/** protocol and port bitmaps */
	LDNS_RDF_TYPE_SERVICE,
	/** location data */
	LDNS_RDF_TYPE_LOC,
	/** well known services */
	LDNS_RDF_TYPE_WKS,
	/** NSAP */
	LDNS_RDF_TYPE_NSAP,
	/** IPSECKEY */
	LDNS_RDF_TYPE_IPSECKEY
};
typedef enum ldns_enum_rdf_type ldns_rdf_type;

/**
 * \brief Resource record data
 *
 * The data is a network ordered array of bytes, which size is specified by
 * the (16-bit) size field. To correctly parse it, use the type
 * specified in the (16-bit) type field.
 */
struct ldns_struct_rdf
{
	/** \brief The size of the data (in bytes) */
	uint16_t _size;
	/** \brief The type of the data */
	ldns_rdf_type _type;
	/** \brief Pointer to the data (byte buffer) */
	void  *_data;
};
typedef struct ldns_struct_rdf ldns_rdf;

/* prototypes */
uint16_t        ldns_rdf_size(const ldns_rdf *);
void            ldns_rdf_set_size(ldns_rdf *, uint16_t);
void            ldns_rdf_set_type(ldns_rdf *, ldns_rdf_type);
void            ldns_rdf_set_data(ldns_rdf *, void *);
ldns_rdf_type   ldns_rdf_get_type(const ldns_rdf *);
ldns_rdf	*ldns_rdf_new(uint16_t, ldns_rdf_type, void *);
ldns_rdf	*ldns_rdf_new_frm_data(ldns_rdf_type, uint16_t, const void *);
ldns_rdf 	*ldns_rdf_new_frm_str(ldns_rdf_type, const char *);
ldns_status     ldns_octet(char *word, size_t *length);
uint8_t         *ldns_rdf_data(const ldns_rdf *);
void            ldns_rdf_free(ldns_rdf *);
void            ldns_rdf_free_data(ldns_rdf *);
struct sockaddr_storage * ldns_rdf2native_sockaddr_storage(ldns_rdf *);
ldns_rdf	*ldns_rdf_clone(const ldns_rdf *);
int		ldns_rdf_compare(const ldns_rdf *, const ldns_rdf *);
uint8_t		ldns_rdf2native_int8(ldns_rdf *);
uint16_t	ldns_rdf2native_int16(ldns_rdf *);
uint32_t	ldns_rdf2native_int32(ldns_rdf *);
uint32_t	ldns_str2period(const char *, const char **);

#endif	/* !_LDNS_RDATA_H */
