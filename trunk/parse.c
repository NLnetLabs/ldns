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

ssize_t
ldns_get_keyword_data(FILE *f, const char *keyword, const char *k_del, char *data, 
		const char *d_del)
{
	/* we assume: keyword|sep|data */
	char *fkeyword;
	ssize_t i;

	fkeyword = XMALLOC(char, MAXKEYWORD_LEN);
	i = 0;

	i = ldns_get_token(f, fkeyword, k_del);

	printf("[%s]\n", fkeyword);

	/* case??? */
	if (strncmp(fkeyword, keyword, strlen(keyword)) == 0) {
		/* whee, the match! */
		printf("Matching keyword\n\n");
		/* retrieve it's data */
		i = ldns_get_token(f, data, d_del);
		return i;
	} else {
		return -1;
	}
}

/* walk along the file until you get a hit */
ssize_t
ldns_get_all_keyword_data(FILE *f, const char *keyword, const char *k_del, char *data,
		const char *d_del)
{
	while (ldns_get_keyword_data(f, keyword, k_del, data, d_del) == -1) {
		/* improve ldns_get_keyword_data */
	
		/* do something here and a walk through the file */
	}
	/* reset for next call, this function is rather expensive, as
	 * for multiple keywords, it walks the file multiple time. But must
	 * files are small
	 */
	rewind(f);
	return 0;
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
		del = LDNS_PARSE_NORMAL;
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
