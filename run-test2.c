/* 
 * test2, read hexdump of file and print query
 *
 * reading code taken from drill, maybe put it in the library?
 * (rewritten cleanly of course, and with error checking)
 */

#include <config.h>
#include <ldns/ldns.h>
#include <ldns/str2host.h>
#include <ldns/host2str.h>
#include <ldns/host2wire.h>
#include <ldns/buffer.h>

#include "util.h"

#define MAX_PACKET 10000

/**
 * Converts a hex string to binary data
 * len is the length of the string
 * buf is the buffer to store the result in
 * offset is the starting position in the result buffer
 *
 * This function returns the length of the result
 */
size_t
hexstr2bin(char *hexstr, int len, uint8_t *buf, size_t offset)
{
	char c;
	int i; 
	uint8_t int8 = 0;
	int sec = 0;
	size_t bufpos = 0;
	
	if (len % 2 != 0) {
		return 0;
	}

	for (i=0; i<len; i++) {
		c = hexstr[i];

		/* case insensitive, skip spaces */
		if (c != ' ') {
			if (c >= '0' && c <= '9') {
				int8 += c & 0x0f;  
			} else if (c >= 'a' && c <= 'z') {
				int8 += (c & 0x0f) + 9;   
			} else if (c >= 'A' && c <= 'Z') {
				int8 += (c & 0x0f) + 9;   
			} else {
				printf("Error in reading hex data: \n");
				printf("%s ('%c' at %d, should read %d bytes)\n", hexstr, c, i, len);
				return 0;
			}
			 
			if (sec == 0) {
				int8 = int8 << 4;
				sec = 1;
			} else {

				buf[bufpos+offset] = int8;
				int8 = 0;
				sec = 0; 
				bufpos++;
			}
		}
                 
        }
        return bufpos;        
}


ldns_pkt *
file2pkt(const char *filename)
{
	ldns_pkt *pkt;
	FILE *fp = NULL;
	char c;
	ldns_status status;
	
	/* stat hack
	 * 0 = normal
	 * 1 = comment (skip to end of line)
	 * 2 = unprintable character found, read binary data directly
	 */
	int state = 0;
	size_t buflen = MAX_PACKET;
	uint8_t *hexbuf = XMALLOC(uint8_t, buflen);
	int hexbufpos = 0;
	size_t wirelen;
	uint8_t *wire = XMALLOC(uint8_t, buflen);
	
	if (strncmp(filename, "-", 2) == 0) {
		fp = stdin;
	} else {
		fp = fopen(filename, "r");
	}
	if (fp == NULL) {
		printf("Unable to open file for reading: %s\n", filename);
		return NULL;
	}

	printf("Opened %s\n", filename);
	
	c = fgetc(fp);
	while (c != EOF) {
		if (state < 2 && !isascii(c)) {
			printf("non ascii character found in file: (%d) switching to raw mode\n", c);
			state = 2;
		}
		switch (state) {
			case 0:
				if (	(c >= '0' && c <= '9') ||
					(c >= 'a' && c <= 'f') ||
					(c >= 'A' && c <= 'F') )
				{
					hexbuf[hexbufpos] = (uint8_t) c;
					hexbufpos++;
				} else if (c == ';') {
					state = 1;
				} else if (c == ' ' || c == '\t' || c == '\n') {
					/* skip whitespace */
				} 
				break;
			case 1:
				if (c == '\n' || c == EOF) {
					state = 0;
				}
				break;
			case 2:
				hexbuf[hexbufpos] = (uint8_t) c;
				hexbufpos++;
				break;
			default:
				printf("unknown state while reading file\n");
				return NULL;
				break;
		}
		c = fgetc(fp);

		if ((size_t) hexbufpos >= buflen) {
			buflen = buflen * 2;
			hexbuf = XREALLOC(hexbuf, uint8_t, buflen);
			wire = XREALLOC(wire, uint8_t, buflen);
		}
		
	}
	if (c == EOF) {
		if (state < 2) {
			printf("read:\n");
			printf("%s\n", (char *)hexbuf);
		} else {
			printf("Not printing wire because it contains non ascii data\n");
		}
	}
	/* lenient mode: length must be multiple of 2 */
	if (hexbufpos % 2 != 0) {
		hexbuf[hexbufpos] = (uint8_t) '0';
		hexbufpos++;
	}

	if (state < 2) {
		wirelen = hexstr2bin((char *) hexbuf, hexbufpos, wire, 0);
	} else {
		memcpy(wire, hexbuf, (size_t) hexbufpos);
		wirelen = (size_t) hexbufpos;
	}
	
	FREE(hexbuf);
	
	status = ldns_wire2pkt(&pkt, wire, wirelen);
	
	FREE(wire);
	
	if (status == LDNS_STATUS_OK) {
		return pkt;
	} else {
		printf("error in wire2pkt: %d\n", status);
		return NULL;
	}
}


int
main(int argc, char **argv)
{
	const char *file;
	ldns_pkt *pkt;
	uint8_t *target_buf;
	size_t len;
	uint16_t i;
	char *str;
	
	if (argc == 2) {
		file = argv[1];
	} else {
		file = "packetdump.txt";
	}
	
	pkt = file2pkt(file);
	if (pkt) {
		printf("packet:\n");
		str = ldns_pkt2str(pkt);
		printf("%s", str);
		FREE(str);
	} else {
		printf("\n");
	}

	if (!ldns_pkt_tsig_verify(pkt, "jelte.", "vBUWJnkgDw4YTobXtbUD6XED5Qg74tnghYX3tzKzfsI=", NULL)) {
		printf("Bad sig :(\n");
		exit(-1);
	} else {
		printf("SIG VERIFIED!\n");
	}
	
	printf("And back to wire:\n");
	/*buffer = ldns_buffer_new(65535);*/
	target_buf = ldns_pkt2wire(pkt, &len);

	printf("Buffer length: %u\n", (unsigned int) len);
	
	for (i=0; i<len; i++) {
		printf("%02x", (unsigned int) target_buf[i]);
	}
	printf("\n\n");

	ldns_pkt_free(pkt);
	FREE(target_buf);
	
	return 0;
}

