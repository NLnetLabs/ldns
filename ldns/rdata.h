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

#ifndef _LDNS_RDATA_H
#define _LDNS_RDATA_H

/**
 * LibDNS DESIGN 
 * 
 * The following is a standard RR from our labs zone. If we parse it
 * with LibDNS the RR is put in the following structures:
 * 
 * t_rr: (the entire rr)
 * 
 * nlnetlabs.nl    600     IN      MX      10       open.nlnetlabs.nl.
 *  \              \       \       \       \_                       _/
 *   _owner        _ttl    _klass   _type    \_  rdata_fields[]   _/
 *                                             10          := rdata_fields[0]
 *                                     open.nlnetlabs.nl. := rdata_fields[1]
 *                                      
 * So the entire rdata field of an RR is put in the rdata_fields[] array. This
 * is defined in the
 * 
 * An rr_list is an array of rr's.
 */ 

/*
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
	LDNS_RDF_TYPE_TSIGTIME,
	/** protocol and port bitmaps */
	LDNS_RDF_TYPE_SERVICE,
	/** location data */
	LDNS_RDF_TYPE_LOC
};
typedef enum ldns_enum_rdf_type ldns_rdf_type;

/**
 * \brief Resource record data
 *
 * The data is a network ordered array of bytes, which size is specified by the (16-bit) size field.<br>
 * To correctly parse it, use the type specified in the (16-bit) type field.
 */
struct ldns_struct_rdf
{
	/** \brief The size of the data (in bytes) */
	uint16_t _size;
	/** \brief The type of the data */
	ldns_rdf_type _type;
	/** \brief Pointer to the data (byte buffer) */
	uint8_t  *_data;
};
typedef struct ldns_struct_rdf ldns_rdf;

/* prototypes */
ldns_rdf 	*ldns_rdf_new(uint16_t s, ldns_rdf_type t, uint8_t *d);
uint16_t        ldns_rdf_size(ldns_rdf *);
void            ldns_rdf_set_size(ldns_rdf *, uint16_t);
void            ldns_rdf_set_type(ldns_rdf *, ldns_rdf_type);
void            ldns_rdf_set_data(ldns_rdf *, uint8_t *);
ldns_rdf_type   ldns_rdf_get_type(ldns_rdf *);
ldns_rdf	*ldns_rdf_new(uint16_t, ldns_rdf_type, uint8_t *);
uint8_t         *ldns_rdf_data(ldns_rdf *);
void            ldns_rdf_free(ldns_rdf *);

#endif	/* !_LDNS_RDATA_H */
