/*
 * test_digest.c -- Test internal digest function
 *
 * Copyright (c) 2024, Red Hat. All rights reserved.
 * 
 * This software is open source.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 * 
 * Neither the name of the NLNET LABS nor the names of its contributors may
 * be used to endorse or promote products derived from this software without
 * specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */



#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <ldns/sha2.h>
#include <ldns/ldns.h>
#include <ldns/util.h>

#include "ldns/config.h"

#ifdef HAVE_OPENSSL_EVP_H
#  include <openssl/evp.h>
#endif

#if LDNS_REVISION >= 0x10804
	typedef const unsigned char digest_data_t;
#else
	typedef unsigned char digest_data_t;
#endif

typedef unsigned char * (*ldns_md_f)(digest_data_t *data, unsigned int data_len, unsigned char *digest);

static void print_hex(const unsigned char *digest, unsigned int digest_len)
{
	for (size_t i = 0; i < digest_len; i++)
		printf("%02x", digest[i]);

	printf("\n");
}

static int test_md(ldns_md_f ldns_md, unsigned int digest_len, const char *md_name, unsigned char *sign_buf, size_t sign_len)
{
	unsigned char *digest = NULL;
#ifdef HAVE_OPENSSL_EVP_H
	int match = 1;
	const EVP_MD *md = EVP_get_digestbyname(md_name);
	unsigned char *digest_o = NULL;
#endif

	digest = calloc(1, digest_len);
	digest = ldns_md(sign_buf, sign_len, digest);
	printf("%-6s: ", md_name);
	print_hex(digest, digest_len);

#ifdef HAVE_OPENSSL_EVP_H
	/* recheck output with openssl */
	digest_o = calloc(1, digest_len);
	if (!EVP_Digest(sign_buf, sign_len, digest_o, &digest_len, md, NULL))
		puts("OpenSSL error!");
	match = memcmp(digest, digest_o, digest_len);
	if (match == 0)
		printf("Result %s matches OpenSSL.\n", md_name);
	else
		printf("Result %s DIFFERS from OpenSSL: %d\n", md_name, match);

	free(digest);
	free(digest_o);
	return match;
#else
	/* print only ldns digest, nothing to compare it to. */
	return 0;
#endif
}

int main(void)
{
	int match = 0;
	unsigned char sign_buf[] = { 0x00, 0x06, 0x08, 0x02, 0x00, 0x00, 0x0e, 0x10, \
				     0x64, 0x8a, 0xfd, 0xa0, 0x64, 0x78, 0x7a, 0x55, \
				     0xd5, 0xf3, 0x03, 0x70, 0x75, 0x62, 0x02, 0x73, \
				     0x61, 0x00, 0x03, 0x70, 0x75, 0x62, 0x02, 0x73, \
				     0x61, 0x00, 0x00, 0x06, 0x00, 0x01, 0x00, 0x00, \
				     0x0e, 0x10, 0x00, 0x36, 0x02, 0x63, 0x31, 0x03, \
				     0x64, 0x6e, 0x73, 0x02, 0x73, 0x61, 0x00, 0x0a, \
				     0x68, 0x6f, 0x73, 0x74, 0x6d, 0x61, 0x73, 0x74, \
				     0x65, 0x72, 0x03, 0x6e, 0x69, 0x63, 0x03, 0x6e, \
				     0x65, 0x74, 0x02, 0x73, 0x61, 0x00, 0x78, 0x95, \
				     0x72, 0x89, 0x00, 0x00, 0x2a, 0x30, 0x00, 0x00, \
				     0x0e, 0x10, 0x00, 0x36, 0xee, 0x80, 0x00, 0x00, \
				     0x0e, 0x10 };

	/* If you want to see sign_buf contents, uncomment this */
	if (getenv("DEBUG")) {
	   printf("    sign_buf len: %zd\nsign_buf content: ", sizeof(sign_buf));
	   for (size_t i=0; i < sizeof(sign_buf); i++) {
	     if (sign_buf[i] > 31 && sign_buf[i] < 127) {
	       printf("%c", sign_buf[i]);
	     } else {
	       printf("\\%o", sign_buf[i]);
	     }
	   }
	   printf("\n   digests: ");
	}
	match += (test_md(&ldns_sha1,   LDNS_SHA1_DIGEST_LENGTH,   "sha1",   sign_buf, sizeof(sign_buf)) != 0);
	match += (test_md(&ldns_sha256, LDNS_SHA256_DIGEST_LENGTH, "sha256", sign_buf, sizeof(sign_buf)) != 0);
	match += (test_md(&ldns_sha384, LDNS_SHA384_DIGEST_LENGTH, "sha384", sign_buf, sizeof(sign_buf)) != 0);
	match += (test_md(&ldns_sha512, LDNS_SHA512_DIGEST_LENGTH, "sha512", sign_buf, sizeof(sign_buf)) != 0);

	return (abs(match));
}
