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
	LDNS_RDF_TYPE_TSIG,
	/** variable length any type rdata where the length
	    is specified by the first 2 bytes */
	LDNS_RDF_TYPE_INT16_DATA,
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
/* write access functions */
uint16_t        ldns_rdf_size(const ldns_rdf *);
void            ldns_rdf_set_size(ldns_rdf *, uint16_t);
void            ldns_rdf_set_type(ldns_rdf *, ldns_rdf_type);
void            ldns_rdf_set_data(ldns_rdf *, void *);

/* read access */
ldns_rdf_type   ldns_rdf_get_type(const ldns_rdf *);
uint8_t         *ldns_rdf_data(const ldns_rdf *);


/* creator functions */
/**
 * Allocate a new ldns_rdf structure 
 * fill it and return it
 */
ldns_rdf	*ldns_rdf_new(ldns_rdf_type, uint16_t, void *);

/**
 * Allocate a new rdf structure and fill it.
 * This function _does_ copy the contents from
 * the buffer, unlinke ldns_rdf_new()
 * \param[in] type type of the rdf
 * \param[in] size size of the buffer
 * \param[in] data pointer to the buffer to be copied
 * \return the new rdf structure or NULL on failure
 */
ldns_rdf	*ldns_rdf_new_frm_data(ldns_rdf_type, uint16_t, const void *);

/**
 * Create a new rdf from a string
 * \param[in] type   type to use
 * \param[in] str string to use
 * \return ldns_rdf*
 */
ldns_rdf 	*ldns_rdf_new_frm_str(ldns_rdf_type, const char *);

/**     
 * Create a new rdf from a file containing a string
 * \param[in] type   type to use
 * \param[in] fp the file pointer  to use
 * \return ldns_rdf*
 */             
ldns_rdf 	*ldns_rdf_new_frm_fp(ldns_rdf_type type, FILE *fp);
/* destroy functions */
/**
 * Free a rdf structure leave the 
 * data pointer intact
 * \param[in] rd the pointer to be freed
 * \return void
 */
void            ldns_rdf_free(ldns_rdf *);

/**
 * free a rdf structure _and_ free the
 * data. rdf should be created with _new_frm_data
 * \param[in] rd the rdf structure to be freed
 * \return void
 */
void            ldns_rdf_free_data(ldns_rdf *);

/* conversion functions */
/** return the native uint8_t repr. from the rdf
 * \param[in] rd the ldns_rdf to operate on
 * \return uint8_t the value extracted
 */
ldns_rdf 	*ldns_native2rdf_int8(ldns_rdf_type type, uint8_t value);

/** return the native uint32_t repr. from the rdf
 * \param[in] rd the ldns_rdf to operate on
 * \return uint32_t the value extracted
 */
ldns_rdf 	*ldns_native2rdf_int16(ldns_rdf_type type, uint16_t value);

/**
 * Returns an rdf that contains the given int32 value
 *
 * Because multiple rdf types can contain an int32, the
 * type must be specified
 */
ldns_rdf 	*ldns_native2rdf_int32(ldns_rdf_type type, uint32_t value);

/**
 * Returns an int16_data rdf that contains the data in the
 * given array, preceded by an int16 specifying the length
 *
 * The memory is copied, and an LDNS_RDF_TYPE_INT16DATA is returned
 */
ldns_rdf 	*ldns_native2rdf_int16_data(uint16_t size, uint8_t *data);

/**
 * reverse an rdf, only actually usefull for AAAA and A records
 * the returned rdf has the type LDNS_RDF_TYPE_DNAME!
 * \param[in] *rdf rdf to be reversed
 * \return the reversed rdf (a newly created rdf)
 */
ldns_rdf	*ldns_rdf_address_reverse(ldns_rdf *);

/** return the native uint8_t repr. from the rdf
 * \param[in] rd the ldns_rdf to operate on
 * \return uint8_t the value extracted
 */
uint8_t		ldns_rdf2native_int8(ldns_rdf *);

/** return the native uint16_t repr. from the rdf
 * \param[in] rd the ldns_rdf to operate on
 * \return uint16_t the value extracted
 */
uint16_t	ldns_rdf2native_int16(ldns_rdf *);

/** return the native uint32_t repr. from the rdf
 * \param[in] rd the ldns_rdf to operate on
 * \return uint32_t the value extracted
 */
uint32_t	ldns_rdf2native_int32(ldns_rdf *);

/**
 * convert a ttl value (5d2h) to a long
 * \param[in] nptr the start of the string
 * \param[out] endptr points to the last char in case of error
 * \return the convert duration value
 */
uint32_t	ldns_str2period(const char *, const char **);

/** 
 * return the native sockaddr repr. from the rdf
 * \param[in] rd the ldns_rdf to operate on
 * \return struct sockaddr* the address in the format so other
 * functions can use it (sendto)
 */
struct sockaddr_storage * ldns_rdf2native_sockaddr_storage(ldns_rdf *);

/* misc */
/**
 * remove \\DDD, \\[space] and other escapes from the input
 * See RFC 1035, section 5.1
 * \param[in] word what to check
 * \param[in] length the string
 * \return ldns_status mesg
 */
ldns_status     ldns_octet(char *word, size_t *length);

/**
 * clone a rdf structure. The data is copied
 * \param[in] r rdf to be copied
 * \return a new rdf structure
 */
ldns_rdf	*ldns_rdf_deep_clone(const ldns_rdf *);

/**
 * Compare two rdf's
 * \param[in] rd1 the first one
 * \param[in] rd2 the second one
 * \return 0 if equal
 *         -1 if rd1 comes before rd2
 *         +1 if rd2 comes before rd1
 */
int		ldns_rdf_compare(const ldns_rdf *, const ldns_rdf *);

#endif	/* !_LDNS_RDATA_H */
