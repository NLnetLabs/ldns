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
#define _ERORR_H

/* we do negative error codes? */
#define __X 	-1

enum ldns_enum_status_type 
{
	LDNS_E_OK		= 0,
	LDNS_E_EMPTY_LABEL	= 1 * __X,
	LDNS_E_DDD_OVERFLOW	= 2 * __X

};
typedef enum ldns_enum_status_type ldns_status_type;

#endif /* _ERROR_H */
