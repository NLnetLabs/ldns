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

#include <stdint.h>
#include <string.h>
#include "rdata.h"
#include "rr.h"

/* the different RR types */
#define TYPE_A          1       /* a host address */
#define TYPE_NS         2       /* an authoritative name server */
#define TYPE_MD         3       /* a mail destination (Obsolete - use MX) */
#define TYPE_MF         4       /* a mail forwarder (Obsolete - use MX) */
#define TYPE_CNAME      5       /* the canonical name for an alias */
#define TYPE_SOA        6       /* marks the start of a zone of authority */
#define TYPE_MB         7       /* a mailbox domain name (EXPERIMENTAL) */
#define TYPE_MG         8       /* a mail group member (EXPERIMENTAL) */
#define TYPE_MR         9       /* a mail rename domain name (EXPERIMENTAL) */
#define TYPE_NULL       10      /* a null RR (EXPERIMENTAL) */
#define TYPE_WKS        11      /* a well known service description */
#define TYPE_PTR        12      /* a domain name pointer */
#define TYPE_HINFO      13      /* host information */
#define TYPE_MINFO      14      /* mailbox or mail list information */
#define TYPE_MX         15      /* mail exchange */
#define TYPE_TXT        16      /* text strings */
#define TYPE_RP         17      /* RFC1183 */
#define TYPE_AFSDB      18      /* RFC1183 */
#define TYPE_X25        19      /* RFC1183 */
#define TYPE_ISDN       20      /* RFC1183 */
#define TYPE_RT         21      /* RFC1183 */
#define TYPE_NSAP       22      /* RFC1706 */

#define TYPE_SIG        24      /* 2535typecode */
#define TYPE_KEY        25      /* 2535typecode */
#define TYPE_PX         26      /* RFC2163 */

#define TYPE_AAAA       28      /* ipv6 address */
#define TYPE_LOC        29      /* LOC record  RFC1876 */
#define TYPE_NXT        30      /* 2535typecode */

#define TYPE_SRV        33      /* SRV record RFC2782 */

#define TYPE_NAPTR      35      /* RFC2915 */
#define TYPE_KX         36      /* RFC2230 */
#define TYPE_CERT       37      /* RFC2538 */

#define TYPE_DNAME      39      /* RFC2672 */

#define TYPE_OPT        41      /* Pseudo OPT record... */
#define TYPE_APL        42      /* RFC3123 */
#define TYPE_DS         43      /* draft-ietf-dnsext-delegation */
#define TYPE_SSHFP      44      /* SSH Key Fingerprint */

#define TYPE_RRSIG      46      /* draft-ietf-dnsext-dnssec-25 */
#define TYPE_NSEC       47      
#define TYPE_DNSKEY     48

#define TYPE_TSIG       250
#define TYPE_IXFR       251
#define TYPE_AXFR       252
#define TYPE_MAILB      253     /* A request for mailbox-related records (MB, MG or MR) */
#define TYPE_MAILA      254     /* A request for mail agent RRs (Obsolete - see MX) */
#define TYPE_ANY        255     /* any type (wildcard) */

#define MAXLABELLEN     63
#define MAXDOMAINLEN    255

/* the general rr type */
struct struct_rr_type
{
	uint8_t		*owner;		/* owner name, uncompressed */
	uint32_t	ttl;		/* ttl  */
	uint16_t	rd_count;	/* amount of rdata */
	uint16_t	type;		/* the type of the RR. A, MX etc. */
	class_t		klass;		/* avoid clash with class keyword */
	/* everything in the rdata is in network order */
	rdata_t		*rdata;		/* a list of data's */

};
typedef struct struct_rr_type rr_t;

/* rrset contain a list of rr's 
 * no official RFC-like checks are made 
 */
struct t_rrset_type
{
	rr_t *rrs;

};
typedef struct t_rrset_type rrset_t;

#endif /* _RR_H */
