/*
 * dns.h -- defines for the Domain Name System
 *
 * Copyright (c) 2001-2005, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 * A bunch of defines that are used in the DNS
 */

#ifndef _DNS_H_
#define _DNS_H_

#define LDNS_IP4ADDRLEN      (32/8)
#define LDNS_IP6ADDRLEN      (128/8)
#define LDNS_PORT	53
#define LDNS_ROOT_LABEL	'\0'

/* lookup tables for standard DNS stuff  */

/* Taken from RFC 2538, section 2.1.  */
extern ldns_lookup_table ldns_certificate_types[];
/* Taken from RFC 2535, section 7.  */
extern ldns_lookup_table ldns_algorithms[];
/* rr types  */
extern ldns_lookup_table ldns_rr_classes[];
/* if these are used elsewhere */
extern ldns_lookup_table ldns_rcodes[];
extern ldns_lookup_table ldns_opcodes[];

#endif /* _DNS_H_ */
