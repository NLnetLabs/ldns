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
 * An rrset is an array of rr's.
 */ 

#define MAXRDATALEN 64

enum ldns_enum_rdf_type
{
	/** none */
	RDF_TYPE_NONE,
	/** domain name */
	RDF_TYPE_DNAME,
	/** 8 bits */
	RDF_TYPE_INT8,
	/** 16 bits */
	RDF_TYPE_INT16,
	/** 32 bits */
	RDF_TYPE_INT32,
	/** 48 bits? */
	RDF_TYPE_INT48,
	/** A record */
	RDF_TYPE_A,	
	/** AAAA record */
	RDF_TYPE_AAAA,
	/** txt string */
	RDF_TYPE_STR,
	/** apl data */
	RDF_TYPE_APL,
	/** b64 string */
	RDF_TYPE_B64,
	/** hex string */
	RDF_TYPE_HEX,
	/** nsec type codes */
	RDF_TYPE_NSEC, 
	/** a RR type */
	RDF_TYPE_TYPE, 
	/** a class */
	RDF_TYPE_CLASS,
	/** certificates */
	RDF_TYPE_CERT,
	/** a key algorithm */
	RDF_TYPE_ALG,
	/** unknown types */
	RDF_TYPE_UNKNOWN,
	/** time */
	RDF_TYPE_TIME,
	/** protocol and port bitmaps */
	RDF_TYPE_SERVICE,
	/** location data */
	RDF_TYPE_LOC
};
typedef enum ldns_enum_rdf_type ldns_rdf_type;

enum ldns_enum_class
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
typedef enum ldns_enum_class ldns_class;

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
uint16_t        _ldns_rdf_size(ldns_rdf *);
void            _ldns_rdf_set_size(ldns_rdf *, uint16_t);
void            _ldns_rdf_set_type(ldns_rdf *, ldns_rdf_type);
void            _ldns_rdf_set_data(ldns_rdf *, uint8_t *);
ldns_rdf_type   _ldns_rdf_type(ldns_rdf *);
ldns_rdf	*_ldns_rdf_new(uint16_t, ldns_rdf_type, uint8_t *);
uint8_t         *_ldns_rdf_data(ldns_rdf *);
void            _ldns_rdf_destroy(ldns_rdf *);

#endif	/* !_LDNS_RDATA_H */
