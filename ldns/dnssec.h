/*
 * dnssec.h -- defines for the Domain Name System (SEC) (DNSSEC)
 *
 * Copyright (c) 2001-2005, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 * A bunch of defines that are used in the DNS
 */

#ifndef _DNSSEC_H_
#define _DNSSEC_H_

#include <openssl/ssl.h>

/**
 * algorigthms used in dns
 */

enum ldns_enum_algorithm
{
	LDNS_RSAMD5		= 1,
	LDNS_DH			= 2,
	LDNS_DSA		= 3,
	LDNS_ECC		= 4,
	LDNS_RSASHA1		= 5,
	LDNS_INDIRECT		= 252,
	LDNS_PRIVATEDNS		= 253,
	LDNS_PRIVATEOID		= 254
};
typedef enum ldns_enum_algorithm ldns_algorithm;

/* prototypes */
bool ldns_verify_rrsig_dsa(ldns_buffer *, ldns_buffer *, ldns_buffer *);
bool ldns_verify_rrsig_rsasha1(ldns_buffer *, ldns_buffer *, ldns_buffer *);
bool ldns_verify_rrsig_rsamd5(ldns_buffer *, ldns_buffer *, ldns_buffer *);
bool ldns_verify_rrsig(ldns_rr_list *, ldns_rr *, ldns_rr_list *);
bool ldns_verify(ldns_rr_list *, ldns_rr_list *, ldns_rr_list *);	
uint16_t ldns_keytag(ldns_rr *);
DSA *ldns_key_buf2dsa(ldns_buffer *);
RSA *ldns_key_buf2rsa(ldns_buffer *);

#endif /* _DNSSEC_H_ */
