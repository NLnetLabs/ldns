/*
 * buf.h
 *
 * a buffer with dns data and a length
 *
 * a Net::DNS like library for C
 *
 * (c) NLnet Labs, 2004
 *
 * See the file LICENSE for the license
 */

struct ldns_struct_buf
{
	size_t size;
	uint8_t *data;
};
typedef ldns_struct_buf ldns_buf;

