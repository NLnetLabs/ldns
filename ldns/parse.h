/*
 * parse.h 
 *
 * a Net::DNS like library for C
 * LibDNS Team @ NLnet Labs
 * (c) NLnet Labs, 2005
 * See the file LICENSE for the license
 */

#ifndef _LDNS_PARSE_H_
#define _LDNS_PARSE_H_

#include <ldns/common.h>
#include <ldns/buffer.h>


#define LDNS_PARSE_SKIP_SPACE		"\f\n\r\v"
#define LDNS_PARSE_NORMAL		" \f\n\r\t\v"
#define LDNS_PARSE_NO_NL		" \t"
#define LDNS_MAX_LINELEN		512
#define LDNS_MAX_KEYWORDLEN		32

/** 
 * returns a token/char from the stream F.
 * This function deals with ( and ) in the stream,
 * and ignores when it finds them.
 * \param[in] *f the file to read from
 * \param[out] *token the token is put here
 * \param[in] *delim chars at which the parsing should stop
 * \param[in] *limit how much to read. If 0 use builtin maximum
 * \return 0 on error of EOF of F otherwise return the length of what is read
 */
ssize_t ldns_fget_token(FILE *f, char *token, const char *delim, size_t limit);

/* 
 * searches for keyword and delim. Gives everything back
 * after the keyword + k_del until we hit d_del
 */
ssize_t ldns_fget_keyword_data(FILE *f, const char *keyword, const char *k_del, char *data, const char *d_del, size_t data_limit);

/**
 * returns a token/char from the buffer b.
 * This function deals with ( and ) in the buffer,
 * and ignores when it finds them.
 * \param[in] *b the buffer to read from
 * \param[out] *token the token is put here
 * \param[in] *delim chars at which the parsing should stop
 * \param[in] *limit how much to read. If 0 use builtin maximum
 * \returns 0 on error of EOF of b otherwise return the length of what is read
 */
ssize_t ldns_bget_token(ldns_buffer *b, char *token, const char *delim, size_t limit);

/* 
 * searches for keyword and delim. Gives everything back
 * after the keyword + k_del until we hit d_del
 */
ssize_t ldns_bget_keyword_data(ldns_buffer *b, const char *keyword, const char *k_del, char *data, const char *d_del);

/**
 * removes comments from a string. A comment = ';'.
 * Goes on with this until a newline (\n) is reached.
 * The comments are replaces with spaces.
 * \param[in] str the string to remove the comments from. String must be writeable
 * \return the new string
 */
char *ldns_str_remove_comment(char *str);

/**
 * returns the next character from a buffer. Advances the position pointer with 1.
 * When end of buffer is reached returns EOF. This is the buffer's equivalent
 * for getc().
 * \param[in] *buffer buffer to read from
 * \return EOF on failure otherwise return the character
 */
int ldns_bgetc(ldns_buffer *buffer);

/**
 * skips all of the characters in the given string in the buffer, moving
 * the position to the first character that is not in *s.
 * \param[in] *buffer buffer to use
 * \param[in] *s characters to skip
 * \return void
 */
void ldns_bskipcs(ldns_buffer *buffer, const char *s);

/**
 * skips all of the characters in the given string in the fp, moving
 * the position to the first character that is not in *s.
 * \param[in] *fp file to use
 * \param[in] *s characters to skip
 * \return void
 */
void ldns_fskipcs(FILE *fp, const char *s);

#endif /* _LDNS_PARSE_H */
