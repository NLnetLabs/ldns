/*
 * parse.h 
 *
 * a Net::DNS like library for C
 * LibDNS Team @ NLnet Labs
 * (c) NLnet Labs, 2005
 * See the file LICENSE for the license
 */

#ifndef _PARSE_H_
#define _PARSE_H_

#include <ldns/common.h>


#define MAXTOKEN_LEN		1024
#define LDNS_EAT_SPACE		true


/* what we can parse */
enum ldns_enum_parse
{
	LDNS_SPACE_STR,		/* str with spaces */
	LDNS_STR,		/* str without spaces */
	LDNS_QUOTE_STR,		/* str with \ in it */
	LDNS_QUOTE_SPACE_STR	/* str with \ in it and spaces */
};
typedef enum ldns_enum_parse ldns_parse;

/* 
 * get a token/char from the stream F
 * return 0 on error of EOF of F
 * return >0 length of what is read.
 * This function deals with ( and ) in the stream
 * and ignore \n when it finds them
 */
size_t ldns_get_token(FILE *f, char *token, bool eat_space);

/* 
 * get the next string and supply the type we want
 * return 0 on error, otherwise the length
 */
size_t ldns_get_str(FILE *f, char *word, ldns_parse type);

#endif /*  _PARSE_H_ */
