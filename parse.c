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
 * search for keyword and delim. Give everything back
 * after the delimeter(s) 
 */
ssize_t
ldns_get_keyword_data(FILE *f, char *keyword, char *del	, char *data, ldns_parse d_type)
{
	/* we assume: keyword|sep|data */
	char *fkeyword;

	fkeyword = XMALLOC(char, MAXKEYWORD_LEN);

	ldns_get_str(f, fkeyword, LDNS_STR);

	printf("%s\n", fkeyword);
	return 0;
}


ssize_t
ldns_get_str(FILE *f, char *word, ldns_parse type)
{
	ssize_t i;

	i = 0;
	switch (type) {
	case LDNS_SPACE_STR:
		i = ldns_get_token(f, word, LDNS_EAT_SPACE);
		return i;	
	case LDNS_STR:
		i = ldns_get_token(f, word, NULL);
		return i;
	case LDNS_QUOTE_STR:
		i = ldns_get_token(f, word, NULL);
		break;
	case LDNS_QUOTE_SPACE_STR:
		i = ldns_get_token(f, word, LDNS_EAT_SPACE);
		break;
	}
	/* only reach this spot if the str was quoted */
	/* mangle the quoted string and return what we got */
	return i;
}

ssize_t
ldns_get_token(FILE *f, char *token, const char *delim)
{	
	int c;
	int p; /* 0 -> no parenthese seen, >0 nr of ( seen */
	char *t;
	ssize_t i;
	const char *d;
        const char *del;

	/* standard delimeters */
	if (!delim) {
		/* from isspace(3) */
		del = " \f\n\r\t\v";
	} else {
		del = delim;
	}


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
			return -1;
		}

		if (c == '\n' && p != 0) {
			/* in parentheses */
			continue;
		}

		/* check if we hit the delim */
		for (d = del; *d; d++) {
                        if (c == *d) {
				goto tokenread;
                        }
		}
#if 0
		if (isspace(c)) {
			if (isblank(c) && eat_space) {
				/* ordered to keep eating */
				*t++ = c;
				i++;
				continue;
			}
			goto tokenread;
		}
#endif
		
		*t++ = c;
		if (i++ > MAXLINE_LEN) {
			return -1;
		}
	}

tokenread:
	if (p != 0 || c == EOF) {
		/* ( count doesn't match ) count or EOF reached */
		return 0;
	} else {
		*t = '\0';
		return i;
	}
	
}
