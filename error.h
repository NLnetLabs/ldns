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
	EEMPTY_LABEL	= 1 * __X,
	EDDD_OVERFLOW	= 2 * __X

};
typedef enum ldns_enum_status_type ldns_t_status;

#endif /* _ERROR_H */
