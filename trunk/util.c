/*
 * util.c
 *
 * some general memory functions
 *
 * a Net::DNS like library for C
 *
 * (c) NLnet Labs, 2004
 *
 * See the file LICENSE for the license
 */

#include <stdint.h>
#include <stdlib.h>

void *
xmalloc(size_t s)
{
	void *p;
	
	p = (void*)malloc(s);

	return p;
}
