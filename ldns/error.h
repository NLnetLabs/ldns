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

/* we do negative error codes? */
#define __X 	-1

enum ldns_enum_status 
{
	LDNS_STATUS_OK			= 0,
	LDNS_STATUS_EMPTY_LABEL		= 1 * __X,
	LDNS_STATUS_LABEL_OVERFLOW 	= 2 * __X,
	LDNS_STATUS_DOMAINNAME_OVERFLOW = 3 * __X,
	LDNS_STATUS_DDD_OVERFLOW 	= 4 * __X,
	LDNS_STATUS_PACKET_OVERFLOW 	= 5 * __X,
	LDNS_STATUS_INVALID_POINTER 	= 6 * __X
	

};
typedef enum ldns_enum_status ldns_status;

#endif /* _ERROR_H */
