/*
 */

#include "ldns/config.h"

#include <ldns/ldns.h>

/* Avoid signedness warnings */
#define CH_PTR(ptr) ((char*)(ptr))
#define UCH_PTR(ptr) ((unsigned char*)(ptr))

void print_data_ar(const uint8_t *data, const size_t len) {
	size_t i;

	for (i = 0; i < len; i++) {
		printf("%02x ", data[i]);
	}
}

int
test_sha1(const void *data, const void *expect_result_str)
{
	int result;
	unsigned char *digest, *d;
	unsigned int digest_len;
	uint8_t *expect_result;
	size_t data_len;

	data_len = strlen(CH_PTR(data));

	expect_result = malloc(strlen(CH_PTR(expect_result_str)) / 2);
	(void) ldns_hexstring_to_data(expect_result, expect_result_str);

	digest_len = LDNS_SHA1_DIGEST_LENGTH;
	digest = malloc(digest_len);

	d = ldns_sha1(data, data_len, digest);

	if (!d) {
		printf("Error in digest of test data (digesting failed):\n");
		print_data_ar(data, data_len);
		printf("\n");
		result = 1;
	} else {
		if (strncmp(CH_PTR(expect_result), CH_PTR(digest), digest_len) != 0) {
			printf("Bad sha1 digest: got: ");
			print_data_ar(digest, digest_len);
			printf("Expected:                 ");
			printf("%s\n", CH_PTR(expect_result));
			printf("Data:\t%s\n", CH_PTR(data));

			result = 2;
		} else {
			result = 0;
		}
	}
	free(digest);
	free(expect_result);
	return result;
}

int
test_sha256(const void *data, const void *expect_result_str)
{
	int result;
	unsigned char *digest, *d;
	unsigned int digest_len;
	uint8_t *expect_result;
	size_t data_len;

	data_len = strlen(CH_PTR(data));

	expect_result = malloc(strlen(CH_PTR(expect_result_str)) / 2);
	(void) ldns_hexstring_to_data(expect_result, expect_result_str);

	digest_len = LDNS_SHA256_DIGEST_LENGTH;
	digest = malloc(digest_len);

	d = ldns_sha256(data, data_len, digest);

	if (!d) {
		printf("Error in digest of test data (digesting failed):\n");
		print_data_ar(data, data_len);
		printf("\n");
		result = 1;
	} else {
		if (strncmp(CH_PTR(expect_result), CH_PTR(digest), digest_len) != 0) {
			printf("Bad sha256 digest: got: ");
			print_data_ar(digest, digest_len);
			printf("Expected:                 ");
			printf("%s\n", CH_PTR(expect_result));
			printf("Data:\t%s\n", CH_PTR(data));

			result = 2;
		} else {
			result = 0;
		}
	}
	free(digest);
	free(expect_result);
	return result;
}

int
test_sha384(const void *data, const void *expect_result_str)
{
	int result;
	unsigned char *digest, *d;
	unsigned int digest_len;
	uint8_t *expect_result;
	size_t data_len;

	data_len = strlen(CH_PTR(data));

	expect_result = malloc(strlen(CH_PTR(expect_result_str)) / 2);
	(void) ldns_hexstring_to_data(expect_result, expect_result_str);

	digest_len = LDNS_SHA384_DIGEST_LENGTH;
	digest = malloc(digest_len);

	d = ldns_sha384(data, data_len, digest);

	if (!d) {
		printf("Error in digest of test data (digesting failed):\n");
		print_data_ar(data, data_len);
		printf("\n");
		result = 1;
	} else {
		if (strncmp(CH_PTR(expect_result), CH_PTR(digest), digest_len) != 0) {
			printf("Bad sha384 digest: got: ");
			print_data_ar(digest, digest_len);
			printf("Expected:                 ");
			printf("%s\n", CH_PTR(expect_result));
			printf("Data:\t%s\n", CH_PTR(data));

			result = 2;
		} else {
			result = 0;
		}
	}
	free(digest);
	free(expect_result);
	return result;
}

int
test_sha512(const void *data, const void *expect_result_str)
{
	int result;
	unsigned char *digest, *d;
	unsigned int digest_len;
	uint8_t *expect_result;
	size_t data_len;

	data_len = strlen(CH_PTR(data));

	expect_result = malloc(strlen(CH_PTR(expect_result_str)) / 2);
	(void) ldns_hexstring_to_data(expect_result, expect_result_str);

	digest_len = LDNS_SHA512_DIGEST_LENGTH;
	digest = malloc(digest_len);

	d = ldns_sha512(data, data_len, digest);

	if (!d) {
		printf("Error in digest of test data (digesting failed):\n");
		print_data_ar(data, data_len);
		printf("\n");
		result = 1;
	} else {
		if (strncmp(CH_PTR(expect_result), CH_PTR(digest), digest_len) != 0) {
			printf("Bad sha512 digest: got: ");
			print_data_ar(digest, digest_len);
			printf("Expected:                 ");
			printf("%s\n", CH_PTR(expect_result));
			printf("Data:\t%s\n", CH_PTR(data));

			result = 2;
		} else {
			result = 0;
		}
	}
	free(digest);
	free(expect_result);
	return result;
}

int
main(void)
{
	int result = EXIT_SUCCESS;

	/* SHA-1 */
	if (test_sha1("", "da39a3ee5e6b4b0d3255bfef95601890afd80709") != 0) {
		result = EXIT_FAILURE;
	}
	if (test_sha1("abc", "A9993E364706816ABA3E25717850C26C9CD0D89D") != 0) {
		result = EXIT_FAILURE;
	}
	if (test_sha1("Test vector from febooti.com", "a7631795f6d59cd6d14ebd0058a6394a4b93d868") != 0) {
		result = EXIT_FAILURE;
	}
	if (test_sha1("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "84983E441C3BD26EBAAE4AA1F95129E5E54670F1") != 0) {
		result = EXIT_FAILURE;
	}

	/* SHA-256 */
	if (test_sha256("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") != 0) {
		result = EXIT_FAILURE;
	}
	if (test_sha256("Test vector from febooti.com", "077b18fe29036ada4890bdec192186e10678597a67880290521df70df4bac9ab") != 0) {
		result = EXIT_FAILURE;
	}

	/* SHA-384 */
	if (test_sha384("", "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b") != 0) {
		result = EXIT_FAILURE;
	}
	if (test_sha384("Test vector from febooti.com", "388bb2d487de48740f45fcb44152b0b665428c49def1aaf7c7f09a40c10aff1cd7c3fe3325193c4dd35d4eaa032f49b0") != 0) {
		result = EXIT_FAILURE;
	}
	if (test_sha384("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "edb12730a366098b3b2beac75a3bef1b0969b15c48e2163c23d96994f8d1bef760c7e27f3c464d3829f56c0d53808b0b") != 0) {
		result = EXIT_FAILURE;
	}

	/* SHA-512 */
	if (test_sha512("", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e") != 0) {
		result = EXIT_FAILURE;
	}
	if (test_sha512("Test vector from febooti.com", "09fb898bc97319a243a63f6971747f8e102481fb8d5346c55cb44855adc2e0e98f304e552b0db1d4eeba8a5c8779f6a3010f0e1a2beb5b9547a13b6edca11e8a") != 0) {
		result = EXIT_FAILURE;
	}

	if (test_sha512("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "b73d1929aa615934e61a871596b3f3b33359f42b8175602e89f7e06e5f658a243667807ed300314b95cacdd579f3e33abdfbe351909519a846d465c59582f321") != 0) {
		result = EXIT_FAILURE;
	}

	printf("unit test is %s\n", result==EXIT_SUCCESS?"ok":"fail");
	exit(result);
}
