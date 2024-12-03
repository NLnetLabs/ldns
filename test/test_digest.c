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

const unsigned char test_dg_sha1[] = { 0xf2,0x7e,0x9f,0xc6,0x96,0x91,0x51,0x42,0xa0,0x8c,0x47,0x81,0x01,0x75,0xa5,0x42,0xf0,0x6e,0x7c,0xa5 };
const unsigned char test_dg_sha256[] = { 0x11,0xbf,0xfb,0x5c,0xd0,0x16,0x14,0x8d,0xce,0xdc,0x72,0xa5,0xa9,0xd8,0x14,0xab,0xfd,0x88,0x2e,
					 0xa8,0xd8,0x55,0x27,0xaf,0xc4,0xef,0xed,0x6a,0x3f,0x81,0x9c,0x1d };
const unsigned char test_dg_sha384[] = { 0x8f,0xa5,0xa2,0x34,0x17,0x72,0x19,0x62,0x9b,0x1c,0x6e,0x79,0x35,0xc7,0x07,0x49,0x24,0x18,0xf5,0xe3,
					 0x9f,0xcf,0x83,0x6a,0x20,0xae,0x45,0xc8,0xad,0xfa,0x4a,0xd2,0xa1,0x51,0xd0,0xb8,0x10,0xd3,0xee,0x83,
					 0xeb,0x3e,0xb6,0x33,0xa0,0xdd,0xc3,0xf9 };
const unsigned char test_dg_sha512[] = { 0xd9,0xf4,0x3d,0x10,0x9d,0xb3,0x9a,0x18,0x5f,0x95,0x3b,0xfe,0x90,0xfa,0xf2,0xd5,0x69,0xae,0x99,0x19,
					 0x43,0x5e,0x03,0x7e,0xb8,0x0f,0xc4,0xdf,0x10,0xd7,0x77,0xf7,0x2d,0x82,0xa2,0xe4,0xf6,0x91,0x88,0xcc,
					 0xd4,0x78,0xbe,0xec,0xd7,0x02,0x18,0x61,0xb0,0x57,0xbb,0x15,0x1e,0x79,0x9a,0xf2,0xfa,0x40,0xb2,0xb1,
					 0xa3,0xd8,0x74,0x89 };

static void print_hex(const unsigned char *digest, unsigned int digest_len)
{
	for (size_t i = 0; i < digest_len; i++)
		printf("%02x", digest[i]);

	printf("\n");
}

static int test_md(ldns_md_f ldns_md, unsigned int digest_len, const char *md_name,
		   unsigned char *sign_buf, size_t sign_len, const unsigned char *check)
{
	unsigned char *digest = NULL;
	int match = 1;
#ifdef HAVE_OPENSSL_EVP_H
	const EVP_MD *md = EVP_get_digestbyname(md_name);
	unsigned char *digest_o = NULL;
#endif

	digest = calloc(1, digest_len);
	digest = ldns_md(sign_buf, sign_len, digest);
	printf("%-6s: ", md_name);
	print_hex(digest, digest_len);

	match = memcmp(digest, check, digest_len);
	if (match == 0)
		printf("Result %s matches stored digest.\n", md_name);
	else
		printf("Result %s DIFFERS from stored digest: %d\n", md_name, match);

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
	return abs(match);
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
	match += (test_md(&ldns_sha1,   LDNS_SHA1_DIGEST_LENGTH,   "sha1",   sign_buf, sizeof(sign_buf), test_dg_sha1) != 0);
	match += (test_md(&ldns_sha256, LDNS_SHA256_DIGEST_LENGTH, "sha256", sign_buf, sizeof(sign_buf), test_dg_sha256) != 0);
	match += (test_md(&ldns_sha384, LDNS_SHA384_DIGEST_LENGTH, "sha384", sign_buf, sizeof(sign_buf), test_dg_sha384) != 0);
	match += (test_md(&ldns_sha512, LDNS_SHA512_DIGEST_LENGTH, "sha512", sign_buf, sizeof(sign_buf), test_dg_sha512) != 0);

	return (abs(match));
}
