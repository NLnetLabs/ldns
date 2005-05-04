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
#include <ldns/buffer.h>


#define LDNS_PARSE_SKIP_SPACE		"\f\n\r\v"
#define LDNS_PARSE_NORMAL		" \f\n\r\t\v"
#define LDNS_PARSE_NO_NL		" \t"
#define LDNS_MAX_LINELEN		512
#define LDNS_MAX_KEYWORDLEN		32

/** 
 * Get a token/char from the stream F.
 * This function deals with ( and ) in the stream,
 * and ignore \n when it finds them.
 * \param[in] *f the file to read from
 * \param[out] *token the read token is put here
 * \param[in] *delim chars at which the parsing should stop
 * \param[in] *limit how much to read. If 0 use builtin maximum
 * \return 0 on error of EOF of F otherwise return the length of what is * read
 */
ssize_t ldns_fget_token(FILE *f, char *token, const char *delim, size_t limit);

/* 
 * search for keyword and delim. Give everything back
 * after the keyword + k_del until we hit d_del
 */
ssize_t ldns_fget_keyword_data(FILE *f, const char *keyword, const char *k_del, char *data, const char *d_del);

/**
 * Get a token/char from the stream b.
 * This function deals with ( and ) in the stream,
 * and ignore \n when it finds them.
 * \param[in] *b the file to read from
 * \param[out] *token the read token is put here
 * \param[in] *delim chars at which the parsing should stop
 * \param[in] *limit how much to read. If 0 use builtin maximum
 * \return 0 on error of EOF of b otherwise return the length of what is * read
 */
ssize_t ldns_bget_token(ldns_buffer *b, char *token, const char *delim, size_t limit);

/* 
 * search for keyword and delim. Give everything back
 * after the keyword + k_del until we hit d_del
 */
ssize_t ldns_bget_keyword_data(ldns_buffer *b, const char *keyword, const char *k_del, char *data, const char *d_del);

/**
 * Remove comments from a string. A comment = ';'.
 * Go on with this until one reaches a newline (\n).
 * The comments are replaces with spaces.
 * \param[in] str the string to remove the comments from. String must be * writeable
 * \return the new string
 */
char *ldns_str_remove_comment(char *str);

/**
 * Get the next character from a buffer. Advance the position pointer with 1.
 * When end of buffer is reached return EOF. This is the buffer's equiv.
 * for getc().
 * \param[in] *buffer buffer to read from
 * \return EOF on failure otherwise return the character
 */
int ldns_bgetc(ldns_buffer *buffer);

/**
 * Skip all of the characters in the given string in the buffer, moving
 * the position to the first character that is not in *s
 * \param[in] *buffer buffer to use
 * \param[in] *s character to skip
 * \return void
 */
void ldns_bskipcs(ldns_buffer *buffer, const char *s);

/**
 * Skip all of the characters in the given string in the fp, moving
 * the position to the first character that is not in *s
 * \param[in] *fp file to use
 * \param[in] *s character to skip
 * \return void
 */
void ldns_fskipcs(FILE *fp, const char *s);

#endif /*  _PARSE_H */
