/*
 */

#include "ldns/config.h"

#include <ldns/ldns.h>

int test_duration(void)
{
	ldns_duration_type *d1 = NULL, *d2 = NULL;
	char *s1 = NULL, *s2 = NULL, *s3 = NULL;
	int r = -1;

	if (!(d1 = ldns_duration_create()))
		fprintf(stderr, "ldns_duration_create() returned NULL\n");

	else if (!(s1 = ldns_duration2string(d1)))
		fprintf(stderr, "ldns_duration2string() returned NULL\n");

	else if (!(d2 = ldns_duration_create_from_string("PT0S")))
		fprintf( stderr
		       , "ldns_duration_create_from_string(\"P0D\") returned NULL\n");

	else if (ldns_duration_compare(d1, d2))
		fprintf(stderr, "0 durations not equal\n");

	else if ((d1->years = 1), (d1->months = 3), 0)
		; /* pass */

	else if (!(s2 = ldns_duration2string(d1)))
		fprintf(stderr, "ldns_duration2string() returned NULL\n");

	else if (strcmp(s2, "P1Y3M"))
		fprintf(stderr, "\"%s\" should have been \"P1Y3M\"\n", s2);

	else if ((d1->minutes = 3), 0)
		; /* pass */

	else if (!(s3 = ldns_duration2string(d1)))
		fprintf(stderr, "ldns_duration2string() returned NULL\n");

	else if (strcmp(s3, "P1Y3MT3M"))
		fprintf(stderr, "\"%s\" should have been \"P1Y3MT3M\"\n", s3);

	else if (ldns_duration_compare(d1, d2) <= 0)
		fprintf(stderr, "ldns_duration_compare() error\n");
	else
		r = 0;

	if (d1)	ldns_duration_cleanup(d1);
	if (d2)	ldns_duration_cleanup(d2);
	if (s1)	free(s1);
	if (s2)	free(s2);
	if (s3)	free(s3);
	return r;
}


void print_data_ar(const uint8_t *data, const size_t len) {
	size_t i;
	
	for (i = 0; i < len; i++) {
		printf("%02x ", data[i]);
	}
}


int
test_base64_encode(uint8_t *data, size_t data_len, const char *expect_result)
{
	int result;
	
	char *text;
	size_t text_len;

	text_len = ldns_b64_ntop_calculate_size(data_len);
	text = malloc(text_len);
	
	result = ldns_b64_ntop(data, data_len, text, text_len);
	
	text_len = result;

	if (result < 0) {
		printf("Error 1 encoding base64 test data (result %d):\n", result);
		print_data_ar(data, data_len);
		printf("\n");
		result = 1;
	} else {
		if (strncmp(expect_result, text, text_len) != 0) {
			printf("Bad base64 encoding: got: ");
			printf("%s\n", text);
			printf("Expected:                 ");
			printf("%s\n", expect_result);
			printf("Data:\t");
			print_data_ar(data, data_len);
			printf("\n");
			
			result = 2;
		} else {
			result = 0;
		}
	}
	free(text);
	return result;
}

int
test_base64_decode(const char *str, const uint8_t *expect_data, size_t expect_data_len)
{
	int result;
	
	uint8_t *data;
	size_t data_len;

	size_t i;

	data_len = ldns_b64_pton_calculate_size(strlen(str));
	
	if(!(data = malloc(data_len)))
		return -1;
	
	result = ldns_b64_pton(str, data, data_len);
	
	data_len = result;
	
	if (result < 0) {
		printf("Error 2 decoding base64 test data (return code %d): %s\n", result, str);
		result = 1;
	} else {
		result = 0;
		if (data_len != expect_data_len) {
			printf("Bad base64 decoding, wrong result length for string %s:\n", str);
			printf("Got:      ");
			print_data_ar(data, data_len);
			printf("\n");
			printf("Expected: ");
			print_data_ar(expect_data, expect_data_len);
			printf("\n");
			result = 2;
		} else {
			for (i = 0; i < data_len; i++) {
				if (data[i] != expect_data[i]) {
					result = 3;
				}
			}
			if (result != 0) {
				printf("Bad base64 decoding string %s:\n", str);
				printf("Got:      ");
				print_data_ar(data, data_len);
				printf("\n");
				printf("Expected: ");
				print_data_ar(expect_data, expect_data_len);
				printf("\n");
			}
		}
	}
	free(data);
	return result;
}

int
test_base32_encode(uint8_t *data, size_t data_len, const char *expect_result)
{
	int result;
	
	char *text;
	size_t text_len;

	text_len = ldns_b32_ntop_calculate_size(data_len) + 10;
	text = malloc(text_len);
	
	result = ldns_b32_ntop(data, data_len, text, text_len);
	
	if (result < 0) {
		printf("Error 3 encoding base32 test data (result %d):\n", result);
		print_data_ar(data, data_len);
		printf("\n");
		result = 1;
	} else {
		if (strncmp(expect_result, text, text_len) != 0) {
			printf("Bad base32 encoding: got: ");
			printf("%s\n", text);
			printf("Expected:                 ");
			printf("%s\n", expect_result);
			printf("Data:\t");
			print_data_ar(data, data_len);
			printf("\n");
			
			result = 2;
		} else {
			result = 0;
		}
	}
	free(text);
	return result;
}

int
test_base32_decode(const char *str, const uint8_t *expect_data, size_t expect_data_len)
{
	int result;
	
	uint8_t *data;
	size_t data_len;

	size_t i;

	data_len = ldns_b32_pton_calculate_size(strlen(str))  +  10;
	
	if (!(data = malloc(data_len)))
		return -1;
	
	result = ldns_b32_pton(str, strlen(str), data, data_len);
	
	data_len = result;
	
	if (result < 0) {
		printf("Error 4 decoding base32 test data (result %d): %s\n", result, str);
		result = 1;
	} else {
		result = 0;
		if (data_len != expect_data_len) {
			printf("Bad base32 decoding, wrong result length for string %s:\n", str);
			printf("Got:      ");
			print_data_ar(data, data_len);
			printf("\n");
			printf("Expected: ");
			print_data_ar(expect_data, expect_data_len);
			printf("\n");
			result = 2;
		} else {
			for (i = 0; i < data_len; i++) {
				if (data[i] != expect_data[i]) {
					result = 3;
				}
			}
			if (result != 0) {
				printf("Bad base32 decoding string %s:\n", str);
				printf("Got:      ");
				print_data_ar(data, data_len);
				printf("\n");
				printf("Expected: ");
				print_data_ar(expect_data, expect_data_len);
				printf("\n");
			}
		}
	}
	free(data);
	return result;
}

int
test_base32_encode_extended_hex(uint8_t *data, size_t data_len, const char *expect_result)
{
	int result;
	
	char *text;
	size_t text_len;

	text_len = ldns_b32_ntop_calculate_size(data_len) + 10;
	text = malloc(text_len);
	
	result = ldns_b32_ntop_extended_hex(data, data_len, text, text_len);
	
	
	if (result < 0) {
		printf("Error 5 encoding base32 extended hex test data (result %d):\n", result);
		print_data_ar(data, data_len);
		printf("\n");
		result = 1;
	} else {
		data_len = result;
		if (strncmp(expect_result, text, text_len) != 0) {
			printf("Bad base32 encoding: got: ");
			printf("%s\n", text);
			printf("Expected:                 ");
			printf("%s\n", expect_result);
			printf("Data:\t");
			print_data_ar(data, data_len);
			printf("\n");
			
			result = 2;
		} else {
			result = 0;
		}
	}
	free(text);
	return result;
}

int
test_base32_decode_extended_hex(const char *str, const uint8_t *expect_data, size_t expect_data_len)
{
	int result;
	
	uint8_t *data;
	size_t data_len;

	size_t i;

	data_len = ldns_b32_pton_calculate_size(strlen(str)) + 10;
	
	if (!(data = malloc(data_len)))
		return -1;
	
	result = ldns_b32_pton_extended_hex(str, strlen(str), data, data_len);
	
	data_len = result;
	
	if (result < 0) {
		printf("Error 6 decoding base32 extended hex test data (result %d): %s\n", result, str);
		result = 1;
	} else {
		result = 0;
		if (data_len != expect_data_len) {
			printf("Bad base32 decoding, wrong result length for string %s:\n", str);
			printf("Got:      ");
			print_data_ar(data, data_len);
			printf("\n");
			printf("Expected: ");
			print_data_ar(expect_data, expect_data_len);
			printf("\n");
			result = 2;
		} else {
			for (i = 0; i < data_len; i++) {
				if (data[i] != expect_data[i]) {
					result = 3;
				}
			}
			if (result != 0) {
				printf("Bad base32 decoding string %s:\n", str);
				printf("Got:      ");
				print_data_ar(data, data_len);
				printf("\n");
				printf("Expected: ");
				print_data_ar(expect_data, expect_data_len);
				printf("\n");
			}
		}
	}
	free(data);
	return result;
}



int
test_sha1(const void *data, const void *expect_result_str)
{
	int result;
	unsigned char *digest, *d;
	unsigned int digest_len;
	uint8_t *expect_result;
	size_t data_len;
	
	data_len = strlen(data);

	expect_result = malloc(strlen((char *)expect_result_str) / 2);
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
		if (strncmp((char *)expect_result, (char *)digest, digest_len) != 0) {
			printf("Bad sha1 digest: got: ");
			print_data_ar(digest, digest_len);
			printf("Expected:                 ");
			printf("%s\n", (char *)expect_result);
			printf("Data:\t%s\n", (char *)data);
			
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
	
	data_len = strlen(data);

	expect_result = malloc(strlen((char *)expect_result_str) / 2);
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
		if (strncmp((char *)expect_result, (char *)digest, digest_len) != 0) {
			printf("Bad sha256 digest: got: ");
			print_data_ar(digest, digest_len);
			printf("Expected:                 ");
			printf("%s\n", (char *)expect_result);
			printf("Data:\t%s\n", (char *)data);
			
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
	uint8_t *data;
	size_t data_len;

	int result = EXIT_SUCCESS;

	/* rfc3548 example 1 */
	data_len = 6;
	data = malloc(data_len);
	data[0] = 0x14;
	data[1] = 0xfb;
	data[2] = 0x9c;
	data[3] = 0x03;
	data[4] = 0xd9;
	data[5] = 0x7e;
	if (test_base64_encode(data, data_len, "FPucA9l+") != 0) {
		result = EXIT_FAILURE;
	}
	if (test_base64_decode("FPucA9l+", data, data_len) != 0) {
		result = EXIT_FAILURE;
	}
	free(data);

	/* rfc3548 example 2 */
	data_len = 5;
	data = malloc(data_len);
	data[0] = 0x14;
	data[1] = 0xfb;
	data[2] = 0x9c;
	data[3] = 0x03;
	data[4] = 0xd9;
	if (test_base64_encode(data, data_len, "FPucA9k=") != 0) {
		result = EXIT_FAILURE;
	}
	if (test_base64_decode("FPucA9k=", data, data_len) != 0) {
		result = EXIT_FAILURE;
	}
	free(data);

	/* rfc3548 example 3 */
	data_len = 4;
	data = malloc(data_len);
	data[0] = 0x14;
	data[1] = 0xfb;
	data[2] = 0x9c;
	data[3] = 0x03;
	if (test_base64_encode(data, data_len, "FPucAw==") != 0) {
		result = EXIT_FAILURE;
	}
	if (test_base64_decode("FPucAw==", data, data_len) != 0) {
		result = EXIT_FAILURE;
	}
	free(data);


	/* base32 from http://www.garykessler.net/library/base64.html */
	data_len = 5;
	data = malloc(data_len);
	data[0] = 0xc9;
	data[1] = 0x6e;
	data[2] = 0x96;
	data[3] = 0x17;
	data[4] = 0xad;
/*	if (test_base32_encode(data, data_len, "ZFXJMF5N") != 0) {*/
	if (test_base32_encode(data, data_len, "zfxjmf5n") != 0) {
		result = EXIT_FAILURE;
	}
/*	if (test_base32_decode("ZFXJMF5N", data, data_len) != 0) {*/
	if (test_base32_decode("zfxjmf5n", data, data_len) != 0) {
		result = EXIT_FAILURE;
	}
	free(data);

	data_len = 3;
	data = malloc(data_len);
	data[0] = 0x4d;
	data[1] = 0x5a;
	data[2] = 0x90;
/*	if (test_base32_encode(data, data_len, "JVNJA===") != 0) {*/
	if (test_base32_encode(data, data_len, "jvnja===") != 0) {
		result = EXIT_FAILURE;
	}
/*	if (test_base32_decode("JVNJA===", data, data_len) != 0) {*/
	if (test_base32_decode("jvnja===", data, data_len) != 0) {
		result = EXIT_FAILURE;
	}
	free(data);


	/* base32 extended_hex */
	data_len = 5;
	data = malloc(data_len);
	data[0] = 0xc9;
	data[1] = 0x6e;
	data[2] = 0x96;
	data[3] = 0x17;
	data[4] = 0xad;
/*	if (test_base32_encode_extended_hex(data, data_len, "P5N9C5TD") != 0) {*/
	if (test_base32_encode_extended_hex(data, data_len, "p5n9c5td") != 0) {
		result = EXIT_FAILURE;
	}
/*	if (test_base32_decode_extended_hex("P5N9C5TD", data, data_len) != 0) {*/
	if (test_base32_decode_extended_hex("p5n9c5td", data, data_len) != 0) {
		result = EXIT_FAILURE;
	}
	free(data);

	data_len = 3;
	data = malloc(data_len);
	data[0] = 0x4d;
	data[1] = 0x5a;
	data[2] = 0x90;
/*	if (test_base32_encode_extended_hex(data, data_len, "9LD90===") != 0) {*/
	if (test_base32_encode_extended_hex(data, data_len, "9ld90===") != 0) {
		result = EXIT_FAILURE;
	}
/*	if (test_base32_decode_extended_hex("9LD90===", data, data_len) != 0) {*/
	if (test_base32_decode_extended_hex("9ld90===", data, data_len) != 0) {
		result = EXIT_FAILURE;
	}
	free(data);

	/* base32 extended_hex (TODO no source! these need to be checked)*/


	/* and an encoding that went wrong once */
	data_len = 20;
	data = malloc(data_len);
	data[0] = 0x8a;
	data[1] = 0xb3;
	data[2] = 0xeb;
	data[3] = 0x19;
	data[4] = 0xd3;
	data[5] = 0x4f;
	data[6] = 0xc3;
	data[7] = 0xa2;
	data[8] = 0x76;
	data[9] = 0xf5;
	data[10] = 0x9f;
	data[11] = 0x3b;
	data[12] = 0x7d;
	data[13] = 0xe6;
	data[14] = 0x6e;
	data[15] = 0x2f;
	data[16] = 0x10;
	data[17] = 0x3b;
	data[18] = 0x58;
	data[19] = 0x3a;
/*	if (test_base32_encode_extended_hex(data, data_len, "HAPUM6EJ9V1Q4TNLJSTNRPJE5S83MM1Q") != 0) {*/
	if (test_base32_encode_extended_hex(data, data_len, "hapum6ej9v1q4tnljstnrpje5s83mm1q") != 0) {
		result = EXIT_FAILURE;
	}
/*	if (test_base32_decode_extended_hex("HAPUM6EJ9V1Q4TNLJSTNRPJE5S83MM1Q", data, data_len) != 0) {*/
	if (test_base32_decode_extended_hex("hapum6ej9v1q4tnljstnrpje5s83mm1q", data, data_len) != 0) {
		result = EXIT_FAILURE;
	}
	free(data);

	/* tests from josfessons draft */
	/* BASE64("") = "" */
	/* BASE32("") = "" */
	/* BASE32-HEX("") = "" */
	data_len = 0;
	if (test_base64_encode(data, data_len, "") != 0) {
		result = EXIT_FAILURE;
	}
	if (test_base64_decode("", data, data_len) != 0) {
		result = EXIT_FAILURE;
	}
	if (test_base32_encode(data, data_len, "") != 0) {
		result = EXIT_FAILURE;
	}
	if (test_base32_decode("", data, data_len) != 0) {
		result = EXIT_FAILURE;
	}
	if (test_base32_encode_extended_hex(data, data_len, "") != 0) {
		result = EXIT_FAILURE;
	}
	if (test_base32_decode_extended_hex("", data, data_len) != 0) {
		result = EXIT_FAILURE;
	}

	/* BASE64("f") = "Zg==" */
	/* BASE32("f") = "MY======" */
	/* BASE32-HEX("f") = "CO======" */
	data_len = 1;
	data = malloc(data_len);
	data[0] = 'f';
	if (test_base64_encode(data, data_len, "Zg==") != 0) {
		result = EXIT_FAILURE;
	}
	if (test_base64_decode("Zg==", data, data_len) != 0) {
		result = EXIT_FAILURE;
	}
/*	if (test_base32_encode(data, data_len, "MY======") != 0) {*/
	if (test_base32_encode(data, data_len, "my======") != 0) {
		result = EXIT_FAILURE;
	}
/*	if (test_base32_decode("MY======", data, data_len) != 0) {*/
	if (test_base32_decode("my======", data, data_len) != 0) {
		result = EXIT_FAILURE;
	}
/*	if (test_base32_encode_extended_hex(data, data_len, "CO======") != 0) {*/
	if (test_base32_encode_extended_hex(data, data_len, "co======") != 0) {
		result = EXIT_FAILURE;
	}
/*	if (test_base32_decode_extended_hex("CO======", data, data_len) != 0) {*/
	if (test_base32_decode_extended_hex("co======", data, data_len) != 0) {
		result = EXIT_FAILURE;
	}
	free(data);
	

	/* BASE64("fo") = "Zm8=" */
	/* BASE32("fo") = "MZXQ====" */
	/* BASE32-HEX("fo") = "CPNG====" */
	data_len = 2;
	data = malloc(data_len);
	data[0] = 'f';
	data[1] = 'o';
	if (test_base64_encode(data, data_len, "Zm8=") != 0) {
		result = EXIT_FAILURE;
	}
	if (test_base64_decode("Zm8=", data, data_len) != 0) {
		result = EXIT_FAILURE;
	}
/*	if (test_base32_encode(data, data_len, "MZXQ====") != 0) {*/
	if (test_base32_encode(data, data_len, "mzxq====") != 0) {
		result = EXIT_FAILURE;
	}
/*	if (test_base32_decode("MZXQ====", data, data_len) != 0) {*/
	if (test_base32_decode("mzxq====", data, data_len) != 0) {
		result = EXIT_FAILURE;
	}
/*	if (test_base32_encode_extended_hex(data, data_len, "CPNG====") != 0) {*/
	if (test_base32_encode_extended_hex(data, data_len, "cpng====") != 0) {
		result = EXIT_FAILURE;
	}
/*	if (test_base32_decode_extended_hex("CPNG====", data, data_len) != 0) {*/
	if (test_base32_decode_extended_hex("cpng====", data, data_len) != 0) {
		result = EXIT_FAILURE;
	}
	free(data);

	/* BASE64("foo") = "Zm9v" */
	/* BASE32("foo") = "MZXW6===" */
	/* BASE32-HEX("foo") = "CPNMU===" */
	data_len = 3;
	data = malloc(data_len);
	data[0] = 'f';
	data[1] = 'o';
	data[2] = 'o';
	if (test_base64_encode(data, data_len, "Zm9v") != 0) {
		result = EXIT_FAILURE;
	}
	if (test_base64_decode("Zm9v", data, data_len) != 0) {
		result = EXIT_FAILURE;
	}
/*	if (test_base32_encode(data, data_len, "MZXW6===") != 0) {*/
	if (test_base32_encode(data, data_len, "mzxw6===") != 0) {
		result = EXIT_FAILURE;
	}
/*	if (test_base32_decode("MZXW6===", data, data_len) != 0) {*/
	if (test_base32_decode("mzxw6===", data, data_len) != 0) {
		result = EXIT_FAILURE;
	}
/*	if (test_base32_encode_extended_hex(data, data_len, "CPNMU===") != 0) {*/
	if (test_base32_encode_extended_hex(data, data_len, "cpnmu===") != 0) {
		result = EXIT_FAILURE;
	}
/*	if (test_base32_decode_extended_hex("CPNMU===", data, data_len) != 0) {*/
	if (test_base32_decode_extended_hex("cpnmu===", data, data_len) != 0) {
		result = EXIT_FAILURE;
	}
	free(data);

	/* BASE64("foob") = "Zm9vYg==" */
	/* BASE32("foob") = "MZXW6YQ=" */
	/* BASE32-HEX("foob") = "CPNMUOG=" */
	data_len = 4;
	data = malloc(data_len);
	data[0] = 'f';
	data[1] = 'o';
	data[2] = 'o';
	data[3] = 'b';
	if (test_base64_encode(data, data_len, "Zm9vYg==") != 0) {
		result = EXIT_FAILURE;
	}
	if (test_base64_decode("Zm9vYg==", data, data_len) != 0) {
		result = EXIT_FAILURE;
	}
/*	if (test_base32_encode(data, data_len, "MZXW6YQ=") != 0) {*/
	if (test_base32_encode(data, data_len, "mzxw6yq=") != 0) {
		result = EXIT_FAILURE;
	}
/*	if (test_base32_decode("MZXW6YQ=", data, data_len) != 0) {*/
	if (test_base32_decode("mzxw6yq=", data, data_len) != 0) {
		result = EXIT_FAILURE;
	}
/*	if (test_base32_encode_extended_hex(data, data_len, "CPNMUOG=") != 0) {*/
	if (test_base32_encode_extended_hex(data, data_len, "cpnmuog=") != 0) {
		result = EXIT_FAILURE;
	}
/*	if (test_base32_decode_extended_hex("CPNMUOG=", data, data_len) != 0) {*/
	if (test_base32_decode_extended_hex("cpnmuog=", data, data_len) != 0) {
		result = EXIT_FAILURE;
	}
	free(data);

	/* BASE64("fooba") = "Zm9vYmE=" */
	/* BASE32("fooba") = "MZXW6YTB" */
	/* BASE32-HEX("fooba") = "CPNMUOJ1" */
	data_len = 5;
	data = malloc(data_len);
	data[0] = 'f';
	data[1] = 'o';
	data[2] = 'o';
	data[3] = 'b';
	data[4] = 'a';
	if (test_base64_encode(data, data_len, "Zm9vYmE=") != 0) {
		result = EXIT_FAILURE;
	}
	if (test_base64_decode("Zm9vYmE=", data, data_len) != 0) {
		result = EXIT_FAILURE;
	}
/*	if (test_base32_encode(data, data_len, "MZXW6YTB") != 0) {*/
	if (test_base32_encode(data, data_len, "mzxw6ytb") != 0) {
		result = EXIT_FAILURE;
	}
/*	if (test_base32_decode("MZXW6YTB", data, data_len) != 0) {*/
	if (test_base32_decode("mzxw6ytb", data, data_len) != 0) {
		result = EXIT_FAILURE;
	}
/*	if (test_base32_encode_extended_hex(data, data_len, "CPNMUOJ1") != 0) {*/
	if (test_base32_encode_extended_hex(data, data_len, "cpnmuoj1") != 0) {
		result = EXIT_FAILURE;
	}
/*	if (test_base32_decode_extended_hex("CPNMUOJ1", data, data_len) != 0) {*/
	if (test_base32_decode_extended_hex("cpnmuoj1", data, data_len) != 0) {
		result = EXIT_FAILURE;
	}
	free(data);

	/* BASE64("foobar") = "Zm9vYmFy" */
	/* BASE32("foobar") = "MZXW6YTBOI======" */
	/* BASE32-HEX("foobar") = "CPNMUOJ1E8======"  */
	data_len = 6;
	data = malloc(data_len);
	data[0] = 'f';
	data[1] = 'o';
	data[2] = 'o';
	data[3] = 'b';
	data[4] = 'a';
	data[5] = 'r';
	if (test_base64_encode(data, data_len, "Zm9vYmFy") != 0) {
		result = EXIT_FAILURE;
	}
	if (test_base64_decode("Zm9vYmFy", data, data_len) != 0) {
		result = EXIT_FAILURE;
	}
/*	if (test_base32_encode(data, data_len, "MZXW6YTBOI======") != 0) {*/
	if (test_base32_encode(data, data_len, "mzxw6ytboi======") != 0) {
		result = EXIT_FAILURE;
	}
/*	if (test_base32_decode("MZXW6YTBOI======", data, data_len) != 0) {*/
	if (test_base32_decode("mzxw6ytboi======", data, data_len) != 0) {
		result = EXIT_FAILURE;
	}
/*	if (test_base32_encode_extended_hex(data, data_len, "CPNMUOJ1E8======") != 0) {*/
	if (test_base32_encode_extended_hex(data, data_len, "cpnmuoj1e8======") != 0) {
		result = EXIT_FAILURE;
	}
/*	if (test_base32_decode_extended_hex("CPNMUOJ1E8======", data, data_len) != 0) {*/
	if (test_base32_decode_extended_hex("cpnmuoj1e8======", data, data_len) != 0) {
		result = EXIT_FAILURE;
	}
	free(data);

	/* BASE16("") = "" */

	/* BASE16("f") = "gg" */

	/* BASE16("fo") = "gggp" */

	/* BASE16("foo") = "gggpgp" */

	/* BASE16("foob") = "gggpgpgc" */

	/* BASE16("fooba") = "gggpgpgcgb" */

	/* BASE16("foobar") = "gggpgpgcgbhc" */


	/* some random stuff to see if (decode(encode(data)) works */
	data_len = 20;
	data = malloc(data_len);
	data[0] = 0x21;
	data[1] = 0x99;
	data[2] = 0x1f;
	data[3] = 0xc0;
	data[4] = 0xdf;
	data[5] = 0x02;
	data[6] = 0xd1;
	data[7] = 0xd5;
	data[8] = 0xb6;
	data[9] = 0xd0;
	data[10] = 0xf8;
	data[11] = 0xf4;
	data[12] = 0xff;
	data[13] = 0xfe;
	data[14] = 0x38;
	data[15] = 0xff;
	data[16] = 0x1e;
	data[17] = 0xae;
	data[18] = 0xc8;
	data[19] = 0x3a;
	if (test_base32_encode_extended_hex(data, data_len, "46chvg6v0b8tbdmgv3qfvvhovsfati1q") != 0) {
		result = EXIT_FAILURE;
	}
	if (test_base32_decode_extended_hex("46chvg6v0b8tbdmgv3qfvvhovsfati1q", data, data_len) != 0) {
		result = EXIT_FAILURE;
	}

	if (test_sha1("abc", "A9993E364706816ABA3E25717850C26C9CD0D89D") != 0) {
		result = EXIT_FAILURE;
	}
	if (test_sha1("", "da39a3ee5e6b4b0d3255bfef95601890afd80709") != 0) {
		result = EXIT_FAILURE;
	}
	if (test_sha1("Test vector from febooti.com", "a7631795f6d59cd6d14ebd0058a6394a4b93d868") != 0) {
		result = EXIT_FAILURE;
	}
	if (test_sha1("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "84983E441C3BD26EBAAE4AA1F95129E5E54670F1") != 0) {
		result = EXIT_FAILURE;
	}

	if (test_sha256("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") != 0) {
		result = EXIT_FAILURE;
	}
	if (test_sha256("Test vector from febooti.com", "077b18fe29036ada4890bdec192186e10678597a67880290521df70df4bac9ab") != 0) {
		result = EXIT_FAILURE;
	}
	free(data);

	if (test_duration())
		result = EXIT_FAILURE;

	printf("unit test is %s\n", result==EXIT_SUCCESS?"ok":"fail");
	exit(result);
}
