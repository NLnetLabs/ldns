/*
 * a generic (simple) parser. Use to parse rr's, private key 
 * information and /etc/resolv.conf files
 *
 * a Net::DNS like library for C
 * LibDNS Team @ NLnet Labs
 * (c) NLnet Labs, 2005
 * See the file LICENSE for the license
 */


#include <config.h>

#include <limits.h>
#include <strings.h>

#include <ldns/parse.h>

#include <ldns/rr.h>
#include <ldns/dns.h>
#include "util.h"




/* 
 * get the next string and supply the type we 
 * want
 */
size_t
ldns_get_str(FILE *f, char *word, ldns_parse type)
{
	size_t i;

	i = 0;
	switch (type) {
	case LDNS_SPACE_STR:
		i = ldns_get_token(f, word, LDNS_EAT_SPACE);
		return i;	
	case LDNS_STR:
		i = ldns_get_token(f, word, false);
		return i;
	case LDNS_QUOTE_STR:
		i = ldns_get_token(f, word, false);
		break;
	case LDNS_QUOTE_SPACE_STR:
		i = ldns_get_token(f, word, LDNS_EAT_SPACE);
		break;
	}
	/* only reach this spot if the str was quoted */
	/* mangle the quoted string and return what we got */
	return i;
}





















/* 
 * get a token/char from the stream F
 * return 0 on error of EOF of F
 * return >0 length of what is read.
 * This function deals with ( and ) in the stream
 * and ignore \n when it finds them
 */
size_t
ldns_get_token(FILE *f, char *token, bool eat_space)
{	
	int c;
	int p; /* 0 -> no parenthese seen, >0 nr of ( seen */
	char *t;
	uint8_t i;

	p = 0;
	i = 0;
	t = token;
	while ((c = getc(f)) != EOF) {
		if (c == '(') {
			p++;
			continue;
		}

		if (c == ')') {
			p--;
			continue;
		}

		if (p < 0) {
			/* more ) then ( */
			token = NULL;
			return 0;
		}

		if (c == '\n' && p != 0) {
			/* in parentheses */
			continue;
		}

		if (isspace(c)) {
			if (isblank(c) && eat_space) {
				/* ordered to keep eating */
				*t++ = c;
				i++;
				continue;
			}
			goto tokenread;
		}
		
		*t++ = c;
		i++;
	}

tokenread:
	if (p != 0 || c == EOF) {
		/* ( count doesn't match ) count or EOF reached */
		token = NULL;
		return 0;
	} else {
		*t = '\0';
		return i;
	}
	
}
