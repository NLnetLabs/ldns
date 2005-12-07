/*
 * rr.h -  resource record definitions
 *
 * a Net::DNS like library for C
 *
 * (c) NLnet Labs, 2004, 2005
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
#define LDNS_MAX_LABELLEN     63
/** Maximum length of a complete dname */
#define LDNS_MAX_DOMAINLEN    255
/** Maximum number of pointers in 1 dname */
#define LDNS_MAX_POINTERS	65535
/** Maximum number of rr's in a rr_list */
#define LDNS_MAX_RR		65535
/** The bytes TTL, CLASS and length use up in an rr */
#define LDNS_RR_OVERHEAD	10


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

/**
 *  Used to specify whether compression is allowed.
 */
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
	size_t	        _rd_count;
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
	size_t _rr_count;
	ldns_rr **_rrs;
};
typedef struct ldns_struct_rr_list ldns_rr_list;

/**
 * struct to hold the whole set of rd_fields.
 *
 * How does the whole rdata_field list look. This is called
 * the rdata in dns speak.
 */
struct ldns_struct_rr_descriptor
{
	/** RR type */
	uint16_t    _type;
	/** Textual name.  */
	const char *_name;
	/** Minimum number of RDATA FIELDs.  */
	uint8_t     _minimum;
	/** Maximum number of RDATA FIELDs.  */
	uint8_t     _maximum;
	/** wireformat specification for the rr */
	const ldns_rdf_type *_wireformat;
	/** Special rdf types */
	ldns_rdf_type _variable;
	/** Specifies whether compression can be used */
	ldns_rr_compress _compress;
};
typedef struct ldns_struct_rr_descriptor ldns_rr_descriptor;

/**     
 * creates a new rr structure.
 * \return ldns_rr *
 */
ldns_rr* ldns_rr_new(void);

/** 
 * creates a new rr structure, based on the given type.
 * alloc enough space to hold all the rdf's
 */
ldns_rr* ldns_rr_new_frm_type(ldns_rr_type t);

/**
 * frees an RR structure
 * \param[in] *rr the RR to be freed 
 * \return void
 */
void ldns_rr_free(ldns_rr *rr);

/**
 * creates an rr from a string.
 * The string should be a fully filled-in rr, like
 * ownername &lt;space&gt; TTL &lt;space&gt; CLASS &lt;space&gt; TYPE &lt;space&gt; RDATA.
 * \param[in] str the string to convert
 * \param[in] default_ttl pointer to a default ttl for the rr. If 0 DEF_TTL will be used
 * \param[in] origin when the owner is relative add this
 * \return the new rr
 */
ldns_rr* ldns_rr_new_frm_str(const char *str, uint16_t default_ttl, ldns_rdf *origin);

/**
 * creates a new rr from a file containing a string.
 * \param[in] fp the file pointer to use
 * \param[in] default_ttl pointer to a default ttl for the rr. If NULL DEF_TTL will be used
 *            the pointer will be updated if the file contains a $TTL directive
 * \param[in] origin when the owner is relative add this
 * 	      the pointer will be updated if the file contains a $ORIGIN directive
 * \return ldns_rr*
 */
ldns_rr* ldns_rr_new_frm_fp(FILE *fp, uint16_t *default_ttl, ldns_rdf **origin);

/**
 * creates a new rr from a file containing a string.
 * \param[in] fp the file pointer to use
 * \param[in] default_ttl a default ttl for the rr. If 0 DEF_TTL will be used
 *            the pointer will be updated if the file contains a $TTL directive
 * \param[in] origin when the owner is relative add this
 * 	      the pointer will be updated if the file contains a $ORIGIN directive
 * \param[in] line_nr pointer to an integer containing the current line number (for debugging purposes)
 * \return ldns_rr*
 */
ldns_rr* ldns_rr_new_frm_fp_l(FILE *fp, uint16_t *default_ttl, ldns_rdf **origin, int *line_nr);

/**
 * sets the owner in the rr structure.
 * \param[in] *rr rr to operate on
 * \param[in] *owner set to this owner
 * \return void
 */
void ldns_rr_set_owner(ldns_rr *rr, ldns_rdf *owner);

/**
 * sets the ttl in the rr structure.
 * \param[in] *rr rr to operate on
 * \param[in] ttl set to this ttl
 * \return void
 */
void ldns_rr_set_ttl(ldns_rr *rr, uint32_t ttl);

/**
 * sets the rd_count in the rr.
 * \param[in] *rr rr to operate on
 * \param[in] count set to this count
 * \return void
 */
void ldns_rr_set_rd_count(ldns_rr *rr, size_t count);

/**
 * sets the type in the rr.
 * \param[in] *rr rr to operate on
 * \param[in] rr_type set to this type
 * \return void
 */
void ldns_rr_set_type(ldns_rr *rr, ldns_rr_type rr_type);

/**
 * sets the class in the rr.
 * \param[in] *rr rr to operate on
 * \param[in] rr_class set to this class
 * \return void
 */
void ldns_rr_set_class(ldns_rr *rr, ldns_rr_class rr_class);

/**
 * sets a rdf member, it will be set on the 
 * position given. The old value is returned, like pop.
 * \param[in] *rr the rr to operate on
 * \param[in] *f the rdf to set
 * \param[in] position the position the set the rdf
 * \return  the old value in the rr, NULL on failyre
 */
ldns_rdf* ldns_rr_set_rdf(ldns_rr *rr, ldns_rdf *f, size_t position);

/**
 * sets rd_field member, it will be 
 * placed in the next available spot.
 * \param[in] *rr rr to operate on
 * \param[in] *f the data field member to set
 * \return bool
 */
bool ldns_rr_push_rdf(ldns_rr *rr, ldns_rdf *f);

/**
 * removes a rd_field member, it will be 
 * popped from the last position.
 * \param[in] *rr rr to operate on
 * \return rdf which was popped (null if nothing)
 */
ldns_rdf* ldns_rr_pop_rdf(ldns_rr *rr);

/**
 * returns the rdata field member counter.
 * \param[in] *rr rr to operate on
 * \param[in] nr the number of the rdf to return
 * \return ldns_rdf *
 */
ldns_rdf* ldns_rr_rdf(const ldns_rr *rr, size_t nr);

/**
 * returns the owner name of an rr structure.
 * \param[in] *rr rr to operate on
 * \return ldns_rdf * 
 */
ldns_rdf* ldns_rr_owner(const ldns_rr *rr);

/**
 * returns the ttl of an rr structure.
 * \param[in] *rr the rr to read from
 * \return the ttl of the rr
 */
uint32_t ldns_rr_ttl(const ldns_rr *rr);

/**
 * returns the rd_count of an rr structure.
 * \param[in] *rr the rr to read from
 * \return the rd count of the rr
 */
size_t ldns_rr_rd_count(const ldns_rr *rr);

/**
 * returns the type of the rr.
 * \param[in] *rr the rr to read from
 * \return the type of the rr
 */
ldns_rr_type ldns_rr_get_type(const ldns_rr *rr);

/**
 * returns the class of the rr.
 * \param[in] *rr the rr to read from
 * \return the class of the rr
 */
ldns_rr_class ldns_rr_get_class(const ldns_rr *rr);

/* rr_lists */

/**
 * returns the number of rr's in an rr_list.
 * \param[in] rr_list  the rr_list to read from
 * \return the number of rr's
 */
size_t ldns_rr_list_rr_count(const ldns_rr_list *rr_list);

/**
 * sets the number of rr's in an rr_list.
 * \param[in] rr_list the rr_list to set the count on
 * \param[in] count the number of rr in this list
 * \return void
 */
void ldns_rr_list_set_rr_count(ldns_rr_list *rr_list, size_t count);

/* set a specific rr */
ldns_rr * ldns_rr_list_set_rr(ldns_rr_list *rr_list, ldns_rr *r, size_t count);

/**
 * returns a specific rr of an rrlist.
 * \param[in] rr_list the rr_list to read from
 * \param[in] nr return this rr
 * \return the rr at position nr
 */
ldns_rr* ldns_rr_list_rr(ldns_rr_list *rr_list, size_t nr);

/**
 * creates a new rr_list structure.
 * \return a new rr_list structure
 */
ldns_rr_list* ldns_rr_list_new();

/**
 * frees an rr_list structure.
 * \param[in] rr_list the list to free
 * \return void
 */
void ldns_rr_list_free(ldns_rr_list *rr_list);

/**
 * frees an rr_list structure and all rrs contained therein.
 * \param[in] rr_list the list to free
 * \return void
 */
void ldns_rr_list_deep_free(ldns_rr_list *rr_list);

/**
 * concatenates two ldns_rr_lists together. This modifies
 * *left (to extend it and add the pointers from *right).
 * \param[in] left the leftside
 * \param[in] right the rightside
 * \return a left with right concatenated to it
 */
bool ldns_rr_list_cat(ldns_rr_list *left, ldns_rr_list *right);

/**
 * concatenates two ldns_rr_lists together, but makes clones of the rr's 
 * (instead of pointer copying).
 * \param[in] left the leftside
 * \param[in] right the rightside
 * \return a new rr_list with leftside/rightside concatenated
 */
ldns_rr_list* ldns_rr_list_cat_clone(ldns_rr_list *left, ldns_rr_list *right);

/**
 * pushes an rr to an rrlist.
 * \param[in] rr_list the rr_list to push to 
 * \param[in] rr the rr to push 
 * \return false on error, otherwise true
 */
bool ldns_rr_list_push_rr(ldns_rr_list *rr_list, ldns_rr *rr);

/**
 * pops the last rr from an rrlist.
 * \param[in] rr_list the rr_list to pop from
 * \return NULL if nothing to pop. Otherwise the popped RR
 */
ldns_rr* ldns_rr_list_pop_rr(ldns_rr_list *rr_list);

/**
 * returns true if the given rr is one of the rrs in the
 * list, or if it is equal to one
 * \param[in] rr_list the rr_list to check
 * \param[in] rr the rr to check
 * \return true if rr_list contains rr, false otherwise
 */
bool ldns_rr_list_contains_rr(ldns_rr_list *rr_list, ldns_rr *rr); 

/**
 * checks if an rr_list is a rrset.
 * \param[in] rr_list the rr_list to check
 * \return true if it is an rrset otherwise false
 */
bool ldns_is_rrset(ldns_rr_list *rr_list);

/**
 * pushes an rr to an rrset (which really are rr_list's).
 * \param[in] *rr_list the rrset to push the rr to
 * \param[in] *rr the rr to push
 * \return true if the push succeeded otherwise false
 */
bool ldns_rr_set_push_rr(ldns_rr_list *rr_list, ldns_rr *rr);

/**
 * pops the last rr from an rrset. This function is there only
 * for the symmetry.
 * \param[in] rr_list the rr_list to pop from
 * \return NULL if nothing to pop. Otherwise the popped RR
 *
 */
ldns_rr* ldns_rr_set_pop_rr(ldns_rr_list *rr_list);

/**
 * pops the first rrset from the list,
 * the list must be sorted, so that all rr's from each rrset
 * are next to each other
 */
ldns_rr_list *ldns_rr_list_pop_rrset(ldns_rr_list *rr_list);


/**
 * retrieves a rrtype by looking up its name.
 * \param[in] name a string with the name
 * \return the type which corresponds with the name
 */
ldns_rr_type ldns_get_rr_type_by_name(const char *name);

/**
 * retrieves a class by looking up its name.
 * \param[in] name string with the name
 * \return the cass which corresponds with the name
 */
ldns_rr_class ldns_get_rr_class_by_name(const char *name);

/**
 * clones a rr and all its data
 * \param[in] rr the rr to clone
 * \return the new rr or NULL on failure
 */
ldns_rr* ldns_rr_clone(const ldns_rr *rr);

/**
 * clones an rrlist.
 * \param[in] rrlist the rrlist to clone
 * \return the cloned rr list
 */
ldns_rr_list* ldns_rr_list_clone(ldns_rr_list *rrlist);

/**
 * sorts an rr_list (canonical wire format). the sorting is done inband.
 * \param[in] unsorted the rr_list to be sorted
 * \return void
 */
void ldns_rr_list_sort(ldns_rr_list *unsorted);

/**
 * sorts an rr_list (owner - class - type). the sorting is done inband.
 * \param[in] unsorted the rr_list to be sorted
 * \return void
 */
void ldns_rr_list_sort_oct(ldns_rr_list *unsorted);

/**
 * compares two rrs.
 * \param[in] rr1 the first one
 * \param[in] rr2 the second one
 * \return 0 if equal
 *         -1 if rr1 comes before rr2
 *         +1 if rr2 comes before rr1
 */
int ldns_rr_compare(const ldns_rr *rr1, const ldns_rr *rr2);

/**
 * compares two rrs. (owner-class-type order)
 * \param[in] rr1 the first one
 * \param[in] rr2 the second one
 * \return 0 if equal
 *         -1 if rr1 comes before rr2
 *         +1 if rr2 comes before rr1
 */
int ldns_rr_compare_oct(const ldns_rr *rr1, const ldns_rr *rr2);

/**
 * returns true of the given rr's are equal.
 * Also returns true if one record is a DS that represents the
 * same DNSKEY record as the other record
 * \param[in] rr1 the first rr
 * \param[in] rr2 the second rr
 * \return true if equal otherwise false
 */
bool ldns_rr_compare_ds(const ldns_rr *rr1, const ldns_rr *rr2);

/** 
 * calculates the uncompressed size of an RR.
 * \param[in] r the rr to operate on
 * \return size of the rr
 */
size_t ldns_rr_uncompressed_size(const ldns_rr *r);

/** 
 * converts each dname in a rr to its canonical form.
 * \param[in] rr the rr to work on
 * \return void
 */
void ldns_rr2canonical(ldns_rr *rr);

/** 
 * converts each dname in each rr in a rr_list to its canonical form.
 * \param[in] rr_list the rr_list to work on
 * \return void
 */
void ldns_rr_list2canonical(ldns_rr_list *rr_list);

/** 
 * counts the number of labels of the ownername.
 * \param[in] rr count the labels of this rr
 * \return the number of labels
 */
uint8_t ldns_rr_label_count(ldns_rr *rr);

/* todo */

/**
 * returns the resource record descriptor for the given rr type.
 *
 * \param[in] type the type value of the rr type
 *\return the ldns_rr_descriptor for this type
 */
const ldns_rr_descriptor *ldns_rr_descript(uint16_t type);

/**
 * returns the minimum number of rdata fields of the rr type this descriptor describes.
 *
 * \param[in]  descriptor for an rr type
 * \return the minimum number of rdata fields
 */
size_t ldns_rr_descriptor_minimum(const ldns_rr_descriptor *descriptor);

/**
 * returns the maximum number of rdata fields of the rr type this descriptor describes.
 *
 * \param[in]  descriptor for an rr type
 * \return the maximum number of rdata fields
 */
size_t ldns_rr_descriptor_maximum(const ldns_rr_descriptor *descriptor);

/**
 * returns the rdf type for the given rdata field number of the rr type for the given descriptor.
 *
 * \param[in] descriptor for an rr type
 * \param[in] field the field number
 * \return the rdf type for the field
 */
ldns_rdf_type ldns_rr_descriptor_field_type(const ldns_rr_descriptor *descriptor, size_t field);

/**
 * Return the rr_list which matches the rdf at position field. Think
 * type-covered stuff for RRSIG
 * 
 * \param[in] l the rr_list to look in
 * \param[in] r the rdf to use for the comparison
 * \param[in] pos at which position can we find the rdf
 * 
 * \return a new rr list with only the RRs that match 
 *
 */
ldns_rr_list *ldns_rr_list_subtype_by_rdf(ldns_rr_list *l, ldns_rdf *r, size_t pos);

/**
 * convert an rdf of type LDNS_RDF_TYPE_TYPE to an actual
 * LDNS_RR_TYPE. This is usefull in the case when inspecting
 * the rrtype covered field of an RRSIG.
 * \param[in] rd the rdf to look at
 * \return a ldns_rr_type with equivalent LDNS_RR_TYPE
 *
 */
ldns_rr_type    ldns_rdf2rr_type(const ldns_rdf *rd);

/* added while doing lua */
bool ldns_rr_list_insert_rr(ldns_rr_list *rr_list, ldns_rr *r, size_t count);

#endif /* _LDNS_RR_H */
