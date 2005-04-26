/**
 * \file rr.h
 *
 *  resource record definitions
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

/** Maximum length of a dname label */
#define MAX_LABELLEN     63
/** Maximum length of a complete dname */
#define MAX_DOMAINLEN    255
/** Maximum number of pointers in 1 dname */
#define MAX_POINTERS	65535
/** Maximum number of rr's in a rr_list */
#define MAX_RR		65535
/** The bytes TTL, CLASS and length use up in an rr */
#define RR_OVERHEAD	10


/**
 *  The different RR classes.
 */
enum ldns_enum_rr_class
{
	/** the Internet */
	LDNS_RR_CLASS_IN 	= 1,
	/** Chaos class */
	LDNS_RR_CLASS_CH	= 3,
	/** Hesiod (Dyer 87) */
	LDNS_RR_CLASS_HS	= 4,
	/** Any class */
	LDNS_RR_CLASS_ANY	= 255,

	LDNS_RR_CLASS_FIRST     = 0,
	LDNS_RR_CLASS_LAST      = 65535,
	LDNS_RR_CLASS_COUNT     = LDNS_RR_CLASS_LAST - LDNS_RR_CLASS_FIRST + 1
};
typedef enum ldns_enum_rr_class ldns_rr_class;

enum ldns_enum_rr_compress
{
	/** compression is allowed */
	LDNS_RR_COMPRESS,
	LDNS_RR_NO_COMPRESS
};
typedef enum ldns_enum_rr_compress ldns_rr_compress;

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
	/**  RFC1348 */
	LDNS_RR_TYPE_NSAP_PTR = 23,
	/**  2535typecode */
	LDNS_RR_TYPE_SIG = 24,
	/**  2535typecode */
	LDNS_RR_TYPE_KEY = 25,
	/**  RFC2163 */
	LDNS_RR_TYPE_PX = 26,
	/**  RFC1712 */
	LDNS_RR_TYPE_GPOS = 27,
	/**  ipv6 address */
	LDNS_RR_TYPE_AAAA = 28,
	/**  LOC record  RFC1876 */
	LDNS_RR_TYPE_LOC = 29,
	/**  2535typecode */
	LDNS_RR_TYPE_NXT = 30,
	/**  draft-ietf-nimrod-dns-01.txt */
	LDNS_RR_TYPE_EID = 31,
	/**  draft-ietf-nimrod-dns-01.txt */
	LDNS_RR_TYPE_NIMLOC = 32,
	/**  SRV record RFC2782 */
	LDNS_RR_TYPE_SRV = 33,
	/**  http://www.jhsoft.com/rfc/af-saa-0069.000.rtf */
	LDNS_RR_TYPE_ATMA = 34,
	/**  RFC2915 */
	LDNS_RR_TYPE_NAPTR = 35,
	/**  RFC2230 */
	LDNS_RR_TYPE_KX = 36,
	/**  RFC2538 */
	LDNS_RR_TYPE_CERT = 37,
	/**  RFC2874 */
	LDNS_RR_TYPE_A6 = 38,
	/**  RFC2672 */
	LDNS_RR_TYPE_DNAME = 39,
	/**  dnsind-kitchen-sink-02.txt */
	LDNS_RR_TYPE_SINK = 40,
	/**  Pseudo OPT record... */
	LDNS_RR_TYPE_OPT = 41,
	/**  RFC3123 */
	LDNS_RR_TYPE_APL = 42,
	/**  draft-ietf-dnsext-delegation */
	LDNS_RR_TYPE_DS = 43,
	/**  SSH Key Fingerprint */
	LDNS_RR_TYPE_SSHFP = 44,
	/**  draft-richardson-ipseckey-rr-11.txt */
	LDNS_RR_TYPE_IPSECKEY = 45,
	/**  draft-ietf-dnsext-dnssec-25 */
	LDNS_RR_TYPE_RRSIG = 46,
	LDNS_RR_TYPE_NSEC = 47,      
	LDNS_RR_TYPE_DNSKEY = 48,

	LDNS_RR_TYPE_UINFO = 100,
	LDNS_RR_TYPE_UID = 101,
	LDNS_RR_TYPE_GID = 102,
	LDNS_RR_TYPE_UNSPEC = 103,

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

/**
 *  Resource Record type
 *
 * This is the basic DNS element that contains actual data
 */
struct ldns_struct_rr
{
	/**  Owner name, uncompressed */
	ldns_rdf	*_owner;	
	/**  Time to live  */
	uint32_t	_ttl;	
	/**  Number of data fields */
	uint16_t	_rd_count;
	/**  the type of the RR. A, MX etc. */
	ldns_rr_type	_rr_type;	
	/**  Class of the resource record.  */
	ldns_rr_class	_rr_class;
	/* everything in the rdata is in network order */
	/**  The list of rdata's */
	ldns_rdf	 **_rdata_fields;
};
typedef struct ldns_struct_rr ldns_rr;

/**
 *  Resource Record Set
 *
 * Contains a list of rr's <br>
 * No official RFC-like checks are made 
 */
struct ldns_struct_rr_list
{
	uint16_t _rr_count;
	ldns_rr **_rrs;
};
typedef struct ldns_struct_rr_list ldns_rr_list;

/* 
 * struct to hold the whole set of rd_fields
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
	ldns_rr_compress _compress;
};
typedef struct ldns_struct_rr_descriptor ldns_rr_descriptor;

/**     
 * create a new rr structure.
 * \return ldns_rr *
 */
ldns_rr * ldns_rr_new(void);

/** 
 * create a new rr structure and based on the type
 * alloc enough space to hold all the rdf's
 */
ldns_rr * ldns_rr_new_frm_type(ldns_rr_type t);

/**
 *  free a RR structure
 * \param[in] *rr the RR to be freed 
 * \return void
 */
void ldns_rr_free(ldns_rr *rr);

/**
 * create a rr from a string
 * string should be a fully filled in rr, like
 * ownername &lt;space&gt; TTL &lt;space&gt; CLASS &lt;space&gt; TYPE &lt;space&gt; RDATA
 * \param[in] str the string to convert
 * \return the new rr
 */
ldns_rr * ldns_rr_new_frm_str(const char *str);

/**
 * Create a new rr from a file containing a string
 * \param[in] fp the file pointer  to use
 * \return ldns_rr*
 */
ldns_rr * ldns_rr_new_frm_fp(FILE *fp);

/**
 *  set the owner in the rr structure
 * \param[in] *rr rr to operate on
 * \param[in] *owner set to this owner
 * \return void
 */
void ldns_rr_set_owner(ldns_rr *rr, ldns_rdf *owner);

/**
 * set the ttl in the rr structure
 * \param[in] *rr rr to operate on
 * \param[in] ttl set to this ttl
 * \return void
 */
void ldns_rr_set_ttl(ldns_rr *rr, uint32_t ttl);

/**
 * set the rd_count in the rr
 * \param[in] *rr rr to operate on
 * \param[in] count set to this count
 * \return void
 */
void ldns_rr_set_rd_count(ldns_rr *rr, uint16_t count);

/**
 *  set the type in the rr
 * \param[in] *rr rr to operate on
 * \param[in] rr_type set to this type
 * \return void
 */
void ldns_rr_set_type(ldns_rr *rr, ldns_rr_type rr_type);

/**
 * set the class in the rr
 * \param[in] *rr rr to operate on
 * \param[in] rr_class set to this class
 * \return void
 */
void ldns_rr_set_class(ldns_rr *rr, ldns_rr_class rr_class);

/**
 * set a rdf member, it will be set on the 
 * position given. The old value is returned, like pop
 * \param[in] *rr the rr to operate on
 * \param[in] *f the rdf to set
 * \param[in] position the position the set the rdf
 * \return  the old value in the rr, NULL on failyre
 */
ldns_rdf * ldns_rr_set_rdf(ldns_rr *rr, ldns_rdf *f, uint16_t position);

/**
 * set rd_field member, it will be 
 * placed in the next available spot
 * \param[in] *rr rr to operate on
 * \param[in] *f the data field member to set
 * \return bool
 */
bool ldns_rr_push_rdf(ldns_rr *rr, ldns_rdf *f);

/**
 * remove a rd_field member, it will be 
 * popped from the last place
 * \param[in] *rr rr to operate on
 * \return rdf which was popped (null if nothing)
 */
ldns_rdf * ldns_rr_pop_rdf(ldns_rr *rr);

/**
 * return the rdata field member counter
 * \param[in] *rr rr to operate on
 * \param[in] nr the number of the rdf to return
 * \return ldns_rdf *
 */
ldns_rdf * ldns_rr_rdf(const ldns_rr *rr, uint16_t nr);

/**
 * return the owner name of an rr structure
 * \param[in] *rr rr to operate on
 * \return ldns_rdf * 
 */
ldns_rdf * ldns_rr_owner(const ldns_rr *rr);

/**
 * return the ttl of an rr structure
 * \param[in] *rr the rr to read from
 * \return the ttl of the rr
 */
uint32_t ldns_rr_ttl(const ldns_rr *rr);

/**
 * return the rd_count of an rr structure
 * \param[in] *rr the rr to read from
 * \return the rd count of the rr
 */
uint16_t ldns_rr_rd_count(const ldns_rr *rr);

/**
 * Returns the type of the rr
 * \param[in] *rr the rr to read from
 * \return the type of the rr
 */
ldns_rr_type ldns_rr_get_type(const ldns_rr *rr);

/**
 * Returns the class of the rr
 * \param[in] *rr the rr to read from
 * \return the class of the rr
 */
ldns_rr_class ldns_rr_get_class(const ldns_rr *rr);

/* rr_lists */

/**
 * return the number of rr's in a rr_list
 * \param[in] rr_list  the rr_list to read from
 * \return the number of rr's
 */
uint16_t ldns_rr_list_rr_count(ldns_rr_list *rr_list);

/**
 * set the number of rr's in a rr_list 
 * \param[in] rr_list the rr_list to set the count on
 * \param[in] count the number of rr in this list
 * \return void
 */
void ldns_rr_list_set_rr_count(ldns_rr_list *rr_list, uint16_t count);

/**
 * return a specific rr of an rrlist
 * \param[in] rr_list the rr_list to read from
 * \param[in] nr return this rr
 * \return the rr at position nr
 */
ldns_rr * ldns_rr_list_rr(ldns_rr_list *rr_list, uint16_t nr);

/**
 * create a new rr_list strcture
 * \return a new rr_list structure
 */
ldns_rr_list * ldns_rr_list_new();

/**
 * free an rr_list structure
 * \param[in] rr_list the list to free
 * \return void
 */
void ldns_rr_list_free(ldns_rr_list *rr_list);

/**
 * concatenate two ldns_rr_lists together
 * \param[in] left the leftside
 * \param[in] right the rightside
 * \return a new rr_list with leftside/rightside concatenated
 */
ldns_rr_list * ldns_rr_list_cat(ldns_rr_list *left, ldns_rr_list *right);

/**
 * push an  rr to a rrlist
 * \param[in] rr_list the rr_list to push to 
 * \param[in] rr the rr to push 
 * \return false on error, otherwise true
 */
bool ldns_rr_list_push_rr(ldns_rr_list *rr_list, ldns_rr *rr);

/**
 * pop the last rr from a rrlist
 * \param[in] rr_list the rr_list to pop from
 * \return NULL if nothing to pop. Otherwise the popped RR
 */
ldns_rr * ldns_rr_list_pop_rr(ldns_rr_list *rr_list);

/**
 * check if an rr_list is a rrset
 * \param[in] rr_list the rr_list to check
 * \return true if it is an rrset otherwise false
 */
bool ldns_is_rrset(ldns_rr_list *rr_list);

/**
 * Push an rr to an rrset (which really are rr_list's)
 * \param[in] *rr_list the rrset to push the rr to
 * \param[in] *rr the rr to push
 * \return true if the push succeeded otherwise false
 */
bool ldns_rr_set_push_rr(ldns_rr_list *rr_list, ldns_rr *rr);

/**
 * pop the last rr from a rrset. This function is there only
 * for the symmetry.
 * \param[in] rr_list the rr_list to pop from
 * \return NULL if nothing to pop. Otherwise the popped RR
 *
 */
ldns_rr * ldns_rr_set_pop_rr(ldns_rr_list *rr_list);


/**
 * retrieve a rrtype by looking up its name
 * \param[in] name a string with the name
 * \return the type which corresponds with the name
 */
ldns_rr_type ldns_get_rr_type_by_name(const char *name);

/**
 * retrieve a class by looking up its name
 * \param[in] name string with the name
 * \return the cass which corresponds with the name
 */
ldns_rr_class ldns_get_rr_class_by_name(const char *name);

/**
 * clone a rr and all its data
 * \param[in] rr the rr to clone
 * \return the new rr or NULL on failure
 */
ldns_rr * ldns_rr_deep_clone(const ldns_rr *rr);

/**
 * Clone an rr list
 * \param[in] rrlist the rrlist to clone
 * \return the cloned rr list
 */
ldns_rr_list * ldns_rr_list_deep_clone(ldns_rr_list *rrlist);

/**
 * sort an rr_list. the sorting is done inband
 * \param[in] unsorted the rr_list to be sorted
 * \return void
 */
void ldns_rr_list_sort(ldns_rr_list *unsorted);

/**
 * Compare two rr
 * \param[in] rr1 the first one
 * \param[in] rr2 the second one
 * \return 0 if equal
 *         -1 if rr1 comes before rr2
 *         +1 if rr2 comes before rr1
 */
int ldns_rr_compare(const ldns_rr *rr1, const ldns_rr *rr2);

/**
 * Returns true of the given rr's are equal, where
 * Also returns true if one records is a DS that represents the
 * other DNSKEY record
 * \param[in] rr1 the first rr
 * \param[in] rr2 the second rr
 * \return true if equal otherwise false
 */
bool ldns_rr_compare_ds(const ldns_rr *rr1, const ldns_rr *rr2);

/** 
 * calculate the uncompressed size of an RR
 * \param[in] r the rr to operate on
 * \return size of the rr
 */
size_t ldns_rr_uncompressed_size(const ldns_rr *r);

/** 
 * convert each dname in a rr to its canonical form
 * \param[in] rr the rr to work on
 * \return void
 */
void ldns_rr2canonical(ldns_rr *rr);

/** 
 * convert each dname in each rr in a rr_list to its canonical form
 * \param[in] rr_list the rr_list to work on
 * \return void
 */
void ldns_rr_list2canonical(ldns_rr_list *rr_list);

/** 
 * count the number of labels of the ownername
 * \param[in] rr 
 * \return the number of labels
 */
uint8_t ldns_rr_label_count(ldns_rr *rr);

/* todo */
const ldns_rr_descriptor *ldns_rr_descript(uint16_t);
size_t ldns_rr_descriptor_minimum(const ldns_rr_descriptor *);
size_t ldns_rr_descriptor_maximum(const ldns_rr_descriptor *);
ldns_rdf_type ldns_rr_descriptor_field_type(const ldns_rr_descriptor *, size_t);

#endif /* _LDNS_RR_H */
