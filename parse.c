/*
 * a generic (simple) parser. Use to parse rr's, private key 
 * information and /etc/resolv.conf files
 *
 * a Net::DNS like library for C
 * LibDNS Team @ NLnet Labs
 * (c) NLnet Labs, 2005
 * See the file LICENSE for the license
 */
#include <ldns/config.h>
#include <ldns/dns.h>

#include <limits.h>
#include <strings.h>

ldns_lookup_table ldns_directive_types[] = {
        { LDNS_DIR_TTL, "$TTL" },  
        { LDNS_DIR_ORIGIN, "$ORIGIN" }, 
        { LDNS_DIR_INCLUDE, "$INCLUDE" },  
        { 0, NULL }
};

ssize_t
ldns_fget_keyword_data(FILE *f, const char *keyword, const char *k_del, char *data, 
		const char *d_del, size_t data_limit)
{
	/* we assume: keyword|sep|data */
	char *fkeyword;
	ssize_t i;

	fkeyword = LDNS_XMALLOC(char, LDNS_MAX_KEYWORDLEN);
	i = 0;

	i = ldns_fget_token(f, fkeyword, k_del, LDNS_MAX_KEYWORDLEN);

	/* case??? i instead of strlen? */
	if (strncmp(fkeyword, keyword, LDNS_MAX_KEYWORDLEN - 1) == 0) {
		/* whee! */
		/* printf("%s\n%s\n", "Matching keyword", fkeyword); */
		i = ldns_fget_token(f, data, d_del, data_limit);
		LDNS_FREE(fkeyword);
		return i;
	} else {
		LDNS_FREE(fkeyword);
		return -1;
	}
}

/* walk along the file until you get a hit */
/* number of occurences.... !! */
ssize_t
ldns_fget_all_keyword_data(FILE *f, const char *keyword, const char *k_del, char *data,
		const char *d_del)
{
	while (ldns_fget_keyword_data(f, keyword, k_del, data, d_del, LDNS_MAX_LINELEN) == -1) {
		/* improve ldns_get_keyword_data */
	
		/* do something here and a walk through the file */
	}

	/* reset for next call, this function is rather expensive, as
	 * for multiple keywords, it walks the file multiple time. Files
	 * need to be small.
	 */

	rewind(f);
	return 0;
}

/* add max_limit here? */
ssize_t
ldns_fget_token(FILE *f, char *token, const char *delim, size_t limit)
{	
	int c;
	int p; /* 0 -> no parenthese seen, >0 nr of ( seen */
	int com;
	char *t;
	size_t i;
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
	com = 0;
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
			/* more ) then ( - close off the string */
			*t = '\0';
			return 0;
		}

		/* do something with comments ; */
		if (c == ';') {
			com = 1;
		}

		if (c == '\n' && com != 0) {
			/* comments */
			com = 0;
			*t = ' ';
			continue;
		}

		if (com == 1) {
			*t = ' ';
			continue;
		}

		if (c == '\n' && p != 0 && t > token) {
			/* in parentheses */
			continue;
		}

		/* check if we hit the delim */
		for (d = del; *d; d++) {
                        if (c == *d) {
				goto tokenread;
                        }
		}

		*t++ = c;
		i++;
		if (limit > 0 && i >= limit) {
			*t = '\0';
			return -1;
		}
	}

	*t = '\0';
	if (i == 0) {
		/* nothing read */
		return -1;
	}
	if (p != 0) {
		return -1;
	}
	return (ssize_t)i;

tokenread:
	ldns_fskipcs(f, delim);
	*t = '\0';
	if (p != 0) {
		return -1;
	}

	return (ssize_t)i;
}

ssize_t
ldns_bget_keyword_data(ldns_buffer *b, const char *keyword, const char *k_del, char *data, 
		const char *d_del)
{
	/* we assume: keyword|sep|data */
	char *fkeyword;
	ssize_t i;

	fkeyword = LDNS_XMALLOC(char, LDNS_MAX_KEYWORDLEN);
	i = 0;

	i = ldns_bget_token(b, fkeyword, k_del, 0);

	dprintf("[%s]\n", fkeyword);

	/* case??? */
	if (strncmp(fkeyword, keyword, strlen(keyword)) == 0) {
		/* whee, the match! */
		dprintf("%s", "Matching keyword\n\n");
		/* retrieve it's data */
		i = ldns_bget_token(b, data, d_del, 0);
		return i;
	} else {
		return -1;
	}
}

/* walk along the file until you get a hit */
ssize_t
ldns_bget_all_keyword_data(ldns_buffer *b, const char *keyword, const char *k_del, char *data,
		const char *d_del)
{
	while (ldns_bget_keyword_data(b, keyword, k_del, data, d_del) == -1) {
		/* improve ldns_get_keyword_data */
	
		/* do something here and a walk through the file */
	}
	/* reset for next call, this function is rather expensive, as
	 * for multiple keywords, it walks the file multiple time. But must
	 * files are small
	 */
	ldns_buffer_rewind(b);
	return 0;
}

ssize_t
ldns_bget_token(ldns_buffer *b, char *token, const char *delim, size_t limit)
{	
	int c;
	int p; /* 0 -> no parenthese seen, >0 nr of ( seen */
	int com;
	char *t;
	size_t i;
	const char *d;
        const char *del;

	/* standard delimiters */
	if (!delim) {
		/* from isspace(3) */
		del = LDNS_PARSE_NORMAL;
	} else {
		del = delim;
	}

	p = 0;
	i = 0;
	com = 0;
	t = token;
	while ((c = ldns_bgetc(b)) != EOF) {
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
			*t = '\0';
			return 0;
		}

		/* do something with comments ; */
		if (c == ';') {
			com = 1;
		}

		if (c == '\n' && com != 0) {
			/* comments */
			com = 0;
			*t = ' ';
			continue;
		}

		if (com == 1) {
			*t = ' ';
			continue;
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
		
		*t++ = c;
		i++;
		if (limit > 0 && i >= limit - 1) {
			*t = '\0';
			return -1;
		}
	}
	*t = '\0';
	if (i == 0) {
		/* nothing read */
		return -1;
	}
	if (p != 0) {
		return -1;
	}
	return (ssize_t)i;

tokenread:
	ldns_bskipcs(b, delim);

	*t = '\0';
	if (p != 0) {
		return -1; 
	}
	return (ssize_t)i;
}

void
ldns_bskipc(ldns_buffer *buffer, char c)
{
        while (c == (char) ldns_buffer_read_u8_at(buffer, ldns_buffer_position(buffer))) {
                if (ldns_buffer_available_at(buffer, buffer->_position + sizeof(char), sizeof(char))) {
                        buffer->_position += sizeof(char);
                } else {
                        return;
                }
        }
}

void
ldns_bskipcs(ldns_buffer *buffer, const char *s)
{
        bool found;
        char c;
        const char *d;

        while(ldns_buffer_available_at(buffer, buffer->_position, sizeof(char))) {
                c = (char) ldns_buffer_read_u8_at(buffer,
                                           buffer->_position);
                found = false;
                for (d = s; *d; d++) {
                        if (*d == c) {
                                found = true;
                        }
                }
                if (found && buffer->_limit > buffer->_position) {
                        buffer->_position += sizeof(char);
                } else {
                        return;
                }
        }
}

void
ldns_fskipc(FILE *fp, char c)
{
	fp = fp;
	c = c;
}


void
ldns_fskipcs(FILE *fp, const char *s)
{
        bool found;
        char c;
        const char *d;

	while ((c = fgetc(fp)) != EOF) {
                found = false;
                for (d = s; *d; d++) {
                        if (*d == c) {
                                found = true;
                        }
                }
		if (!found) {
			/* with getc, we've read too far */
			ungetc(c, fp);
			return;
		}
	}
}

ldns_directive
ldns_directive_new_frm_str(const char *str, void **arg)
{
	str = str;
	arg = arg;
	/* directive<SPACE>arguments */
	return LDNS_DIR_TTL;
}
