
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
#ifdef _RR_H
#else
#define _RR_H

#include "rdata.h"
#include "rr.h"

/* the different RR types */
/**  a host address */
#define TYPE_A          1 
/**  an authoritative name server */
#define TYPE_NS         2 
/**  a mail destination (Obsolete - use MX) */
#define TYPE_MD         3 
/**  a mail forwarder (Obsolete - use MX) */
#define TYPE_MF         4 
/**  the canonical name for an alias */
#define TYPE_CNAME      5 
/**  marks the start of a zone of authority */
#define TYPE_SOA        6 
/**  a mailbox domain name (EXPERIMENTAL) */
#define TYPE_MB         7 
/**  a mail group member (EXPERIMENTAL) */
#define TYPE_MG         8 
/**  a mail rename domain name (EXPERIMENTAL) */
#define TYPE_MR         9 
/**  a null RR (EXPERIMENTAL) */
#define TYPE_NULL       10
/**  a well known service description */
#define TYPE_WKS        11
/**  a domain name pointer */
#define TYPE_PTR        12
/**  host information */
#define TYPE_HINFO      13
/**  mailbox or mail list information */
#define TYPE_MINFO      14
/**  mail exchange */
#define TYPE_MX         15
/**  text strings */
#define TYPE_TXT        16
/**  RFC1183 */
#define TYPE_RP         17
/**  RFC1183 */
#define TYPE_AFSDB      18
/**  RFC1183 */
#define TYPE_X25        19
/**  RFC1183 */
#define TYPE_ISDN       20
/**  RFC1183 */
#define TYPE_RT         21
/**  RFC1706 */
#define TYPE_NSAP       22

/**  2535typecode */
#define TYPE_SIG        24
/**  2535typecode */
#define TYPE_KEY        25
/**  RFC2163 */
#define TYPE_PX         26

/**  ipv6 address */
#define TYPE_AAAA       28
/**  LOC record  RFC1876 */
#define TYPE_LOC        29
/**  2535typecode */
#define TYPE_NXT        30

/**  SRV record RFC2782 */
#define TYPE_SRV        33

/**  RFC2915 */
#define TYPE_NAPTR      35
/**  RFC2230 */
#define TYPE_KX         36
/**  RFC2538 */
#define TYPE_CERT       37

/**  RFC2672 */
#define TYPE_DNAME      39

/**  Pseudo OPT record... */
#define TYPE_OPT        41
/**  RFC3123 */
#define TYPE_APL        42
/**  draft-ietf-dnsext-delegation */
#define TYPE_DS         43
/**  SSH Key Fingerprint */
#define TYPE_SSHFP      44

/**  draft-ietf-dnsext-dnssec-25 */
#define TYPE_RRSIG      46
#define TYPE_NSEC       47      
#define TYPE_DNSKEY     48

#define TYPE_TSIG       250
#define TYPE_IXFR       251
#define TYPE_AXFR       252
/**  A request for mailbox-related records (MB, MG or MR) */
#define TYPE_MAILB      25
/**  A request for mail agent RRs (Obsolete - see MX) */
#define TYPE_MAILA      25
/**  any type (wildcard) */
#define TYPE_ANY        25

/** Maximum length of a dname label */
#define MAXLABELLEN     63
/** Maximum length of a complete dname */
#define MAXDOMAINLEN    255

/**
 * \brief Resource Record type
 *
 * This is the basic DNS element that contains actual data
 */
struct type_struct_rr
{
	/** \brief Owner name, uncompressed */
	uint8_t		*_owner;	
	/** \brief Time to live  */
	uint32_t	_ttl;	
	/** \brief Number of data fields */
	uint16_t	_rd_count;
	/** \brief the type of the RR. A, MX etc. */
	uint16_t	_type;	
	/** \brief Class of the resource record.
	 *
	 * name chosen to avoid clash with class keyword
	 */
	t_class		_klass;	
	/* everything in the rdata is in network order */
	/** \brief The list of rdata's */
	t_rdata_field	**_rdata_fields;
};
typedef struct type_struct_rr t_rr;

/**
 * \brief Resource Record Set
 *
 * Contains a list of rr's <br>
 * No official RFC-like checks are made 
 */
struct type_struct_rrset
{
	t_rr *rrs;

};
typedef struct type_struct_rrset t_rrset;

/* prototypes */
t_rr * ldns_rr_new(void);
void ldns_rr_set_owner(t_rr *, uint8_t *);
void ldns_rr_set_ttl(t_rr *, uint16_t);
void ldns_rr_set_rd_count(t_rr *, uint16_t);
void ldns_rr_set_class(t_rr *, t_class);
void ldns_rr_push_rd_field(t_rr *, t_rdata_field *);
uint8_t *ldns_rr_owner(t_rr *);
uint8_t ldns_rr_ttl(t_rr *);
uint16_t ldns_rr_rd_count(t_rr *);
#endif /* _RR_H */
