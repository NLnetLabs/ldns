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


#define LDNS_PARSE_SKIP_SPACE		"\f\n\r\t\v"
#define LDNS_PARSE_NORMAL		" \f\n\r\t\v"
#define MAXLINE_LEN		512
#define MAXKEYWORD_LEN		32

/* 
 * get a token/char from the stream F
 * return 0 on error of EOF of F
 * return >0 length of what is read.
 * This function deals with ( and ) in the stream
 * and ignore \n when it finds them
 */
ssize_t ldns_get_token(FILE *f, char *token, const char *delim);

/* 
 * search for keyword and delim. Give everything back
 * after the keyword + k_del until we hit d_del
 */
ssize_t 
ldns_get_keyword_data(FILE *f, const char *keyword, const char *k_del, char *data, const char *d_del);


#endif /*  _PARSE_H_ */
