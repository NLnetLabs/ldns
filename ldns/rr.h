
/*
 * rr.h
 *
 * resource record definitions
 *
 * a Net::DNS like library for C
 *
 * (c) NLnet Labs, 2004
 *
 * See the file LICENSE for the license
 */

#ifndef _LDNS_RR_H
#define _LDNS_RR_H

#include <ldns/common.h>
#include <ldns/rdata.h>
#include <ldns/rr.h>
#include <ldns/error.h>

/**
 * The different RR classes.
 */
enum ldns_enum_rr_class
{
	/** the Internet */
	LDNS_RR_CLASS_IN 	= 1,
	/** Chaos class */
	LDNS_RR_CLASS_CHAOS	= 3,
	/** Hesiod (Dyer 87) */
	LDNS_RR_CLASS_HS	= 4,
	/** Any class */
	LDNS_RR_CLASS_ANY	= 255,

	LDNS_RR_CLASS_FIRST     = 0,
	LDNS_RR_CLASS_LAST      = 65535,
	LDNS_RR_CLASS_COUNT     = LDNS_RR_CLASS_LAST - LDNS_RR_CLASS_FIRST + 1
};
typedef enum ldns_enum_rr_class ldns_rr_class;

/**
 * The different RR types.
 */
enum ldns_enum_rr_type
{
	/**  a host address */
	LDNS_RR_TYPE_A = 1, 
	/**  an authoritative name server */
	LDNS_RR_TYPE_NS = 2, 
	/**  a mail destination (Obsolete - use MX) */
	LDNS_RR_TYPE_MD = 3, 
	/**  a mail forwarder (Obsolete - use MX) */
	LDNS_RR_TYPE_MF = 4, 
	/**  the canonical name for an alias */
	LDNS_RR_TYPE_CNAME = 5, 
	/**  marks the start of a zone of authority */
	LDNS_RR_TYPE_SOA = 6, 
	/**  a mailbox domain name (EXPERIMENTAL) */
	LDNS_RR_TYPE_MB = 7, 
	/**  a mail group member (EXPERIMENTAL) */
	LDNS_RR_TYPE_MG = 8, 
	/**  a mail rename domain name (EXPERIMENTAL) */
	LDNS_RR_TYPE_MR = 9, 
	/**  a null RR (EXPERIMENTAL) */
	LDNS_RR_TYPE_NULL = 10,
	/**  a well known service description */
	LDNS_RR_TYPE_WKS = 11,
	/**  a domain name pointer */
	LDNS_RR_TYPE_PTR = 12,
	/**  host information */
	LDNS_RR_TYPE_HINFO = 13,
	/**  mailbox or mail list information */
	LDNS_RR_TYPE_MINFO = 14,
	/**  mail exchange */
	LDNS_RR_TYPE_MX = 15,
	/**  text strings */
	LDNS_RR_TYPE_TXT = 16,
	/**  RFC1183 */
	LDNS_RR_TYPE_RP = 17,
	/**  RFC1183 */
	LDNS_RR_TYPE_AFSDB = 18,
	/**  RFC1183 */
	LDNS_RR_TYPE_X25 = 19,
	/**  RFC1183 */
	LDNS_RR_TYPE_ISDN = 20,
	/**  RFC1183 */
	LDNS_RR_TYPE_RT = 21,
	/**  RFC1706 */
	LDNS_RR_TYPE_NSAP = 22,
	/**  2535typecode */
	LDNS_RR_TYPE_SIG = 24,
	/**  2535typecode */
	LDNS_RR_TYPE_KEY = 25,
	/**  RFC2163 */
	LDNS_RR_TYPE_PX = 26,
	/**  ipv6 address */
	LDNS_RR_TYPE_AAAA = 28,
	/**  LOC record  RFC1876 */
	LDNS_RR_TYPE_LOC = 29,
	/**  2535typecode */
	LDNS_RR_TYPE_NXT = 30,
	/**  SRV record RFC2782 */
	LDNS_RR_TYPE_SRV = 33,
	/**  RFC2915 */
	LDNS_RR_TYPE_NAPTR = 35,
	/**  RFC2230 */
	LDNS_RR_TYPE_KX = 36,
	/**  RFC2538 */
	LDNS_RR_TYPE_CERT = 37,
	/**  RFC2672 */
	LDNS_RR_TYPE_DNAME = 39,
	/**  Pseudo OPT record... */
	LDNS_RR_TYPE_OPT = 41,
	/**  RFC3123 */
	LDNS_RR_TYPE_APL = 42,
	/**  draft-ietf-dnsext-delegation */
	LDNS_RR_TYPE_DS = 43,
	/**  SSH Key Fingerprint */
	LDNS_RR_TYPE_SSHFP = 44,
	/**  draft-ietf-dnsext-dnssec-25 */
	LDNS_RR_TYPE_RRSIG = 46,
	LDNS_RR_TYPE_NSEC = 47,      
	LDNS_RR_TYPE_DNSKEY = 48,

	LDNS_RR_TYPE_TSIG = 250,
	LDNS_RR_TYPE_IXFR = 251,
	LDNS_RR_TYPE_AXFR = 252,
	/**  A request for mailbox-related records (MB, MG or MR) */
	LDNS_RR_TYPE_MAILB = 253,
	/**  A request for mail agent RRs (Obsolete - see MX) */
	LDNS_RR_TYPE_MAILA = 254,
	/**  any type (wildcard) */
	LDNS_RR_TYPE_ANY = 255,

	LDNS_RR_TYPE_FIRST = 0,
	LDNS_RR_TYPE_LAST  = 65535,
	LDNS_RR_TYPE_COUNT = LDNS_RR_TYPE_LAST - LDNS_RR_TYPE_FIRST + 1
};
typedef enum ldns_enum_rr_type ldns_rr_type;

/** Maximum length of a dname label */
#define MAXLABELLEN     63
/** Maximum length of a complete dname */
#define MAXDOMAINLEN    255
/** Maximum number of pointers in 1 dname */
#define MAXPOINTERS	126

/**
 * \brief Resource Record type
 *
 * This is the basic DNS element that contains actual data
 */
struct ldns_struct_rr
{
	/** \brief Owner name, uncompressed */
	ldns_rdf	*_owner;	
	/** \brief Time to live  */
	uint32_t	_ttl;	
	/** \brief Number of data fields */
	uint16_t	_rd_count;
	/** \brief the type of the RR. A, MX etc. */
	ldns_rr_type	_rr_type;	
	/** \brief Class of the resource record.  */
	ldns_rr_class	_rr_class;
	/* everything in the rdata is in network order */
	/** \brief The list of rdata's */
	ldns_rdf	 **_rdata_fields;
};
typedef struct ldns_struct_rr ldns_rr;

/**
 * \brief Resource Record Set
 *
 * Contains a list of rr's <br>
 * No official RFC-like checks are made 
 */
struct ldns_struct_rrset
{
	ldns_rr *rrs;

};
typedef struct ldns_struct_rrset ldns_rrset;

/* 
 * \brief struct to hold the whole set of rd_fields
 *
 * How does the whole rdata_field list look. This is called
 * the rdata in dns speak
 */
struct ldns_struct_rr_descriptor
{
        uint16_t    _type;       /* RR type */
        const char *_name;       /* Textual name.  */
        uint8_t     _minimum;    /* Minimum number of RDATA FIELDs.  */
        uint8_t     _maximum;    /* Maximum number of RDATA FIELDs.  */
        const ldns_rdf_type *_wireformat;
	ldns_rdf_type _variable;
};
typedef struct ldns_struct_rr_descriptor ldns_rr_descriptor;


/* prototypes */
ldns_rr * ldns_rr_new(void);
void ldns_rr_set_owner(ldns_rr *, ldns_rdf *);
void ldns_rr_set_ttl(ldns_rr *, uint16_t);
void ldns_rr_set_rd_count(ldns_rr *, uint16_t);
void ldns_rr_set_type(ldns_rr *, ldns_rr_type);
void ldns_rr_set_class(ldns_rr *, ldns_rr_class);
bool ldns_rr_push_rdf(ldns_rr *, ldns_rdf *);
ldns_rdf *ldns_rr_owner(ldns_rr *);
uint8_t ldns_rr_ttl(ldns_rr *);
uint16_t ldns_rr_rd_count(ldns_rr *);
ldns_rr_type ldns_rr_get_type(ldns_rr *);
ldns_rr_class ldns_rr_get_class(ldns_rr *);


const ldns_rr_descriptor *ldns_rr_descript(uint16_t type);
size_t ldns_rr_descriptor_minimum(const ldns_rr_descriptor *descriptor);
size_t ldns_rr_descriptor_maximum(const ldns_rr_descriptor *descriptor);
ldns_rdf_type ldns_rr_descriptor_field_type(const ldns_rr_descriptor *descriptor, size_t index);

#endif /* _LDNS_RR_H */
