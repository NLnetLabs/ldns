/*
 * error.h
 *
 * error reporting function and definition
 *
 * a Net::DNS like library for C
 *
 * (c) NLnet Labs, 2004
 *
 * See the file LICENSE for the license
 */

#ifndef _ERROR_H
#define _ERROR_H

enum ldns_enum_status 
{
	LDNS_STATUS_OK			= 0,
	LDNS_STATUS_EMPTY_LABEL		= 1,
	LDNS_STATUS_LABEL_OVERFLOW 	= 2,
	LDNS_STATUS_DOMAINNAME_OVERFLOW = 3,
	LDNS_STATUS_DDD_OVERFLOW 	= 4,
	LDNS_STATUS_PACKET_OVERFLOW 	= 5,
	LDNS_STATUS_INVALID_POINTER 	= 6,
	LDNS_STATUS_MEM_ERR	 	= 7,
	LDNS_STATUS_INTERNAL_ERR	= 8,
	LDNS_STATUS_INT_EXP		= 9 
};
typedef enum ldns_enum_status ldns_status;

#endif /* _ERROR_H */
