#define _GNU_SOURCE
#include "config.h"

#include <ldns/ldns.h>
#include <pcap.h>
#include <errno.h>

#define SEQUENCE 1
#define QDATA    2
#define ADATA    3
#define EMPTY    0
#define LINES    4

#ifndef HAVE_GETDELIM
ssize_t getdelim(char **lineptr, size_t *n, int delim, FILE *stream);
#endif

/* perform advance checking (not just string comparison on the input;
 * - sort packet sections
 */
bool advanced = true;

/* you can either dump the exact original packets as hex, or the
 * packet after it has been 'normalized'
 */
bool show_originals = true;

/* pcat diff can ameliorate its output so that it does not show
 * known differences (for example the version.bind answer, but
 * there are more advanced ones). It will keep a number of actual
 * differences it found and print that, as well as the number of
 * known differences and their origin
 *
 * THIS CHANGES THE PACKET! BE CAREFUL WHEN USING show_originals = false!
 */
bool ameliorate_output = true;
size_t differences = 0;
size_t do_bit = 0;
size_t version = 0;
size_t notimpl_notauth = 0;
size_t notauth_notimpl = 0;

struct dns_info
{
	size_t seq;      /* seq number */
	char *qdata;     /* query data in hex */
	char *adata;     /* answer data in hex */
};

/**
 * Converts a hex string to binary data
 * len is the length of the string
 * buf is the buffer to store the result in
 * offset is the starting position in the result buffer
 *
 * This function returns the length of the result
 */
size_t
hexstr2bin(char *hexstr, int len, uint8_t *buf, size_t offset, size_t buf_len)
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
				return 0;
			}
			 
			if (sec == 0) {
				int8 = int8 << 4;
				sec = 1;
			} else {
				if (bufpos + offset + 1 <= buf_len) {
					buf[bufpos+offset] = int8;
					int8 = 0;
					sec = 0; 
					bufpos++;
				} else {
					fprintf(stderr, "Buffer too small in hexstr2bin");
				}
			}
		}
        }
        return bufpos;
}

size_t
packetbuffromfile(char *hexbuf, uint8_t *wire)
{
	int c;
	
	/* stat hack
	 * 0 = normal
	 * 1 = comment (skip to end of line)
	 * 2 = unprintable character found, read binary data directly
	 */
	int state = 0;
	int hexbufpos = 0;
	size_t wirelen;
	
	while (hexbufpos < strlen(hexbuf) && hexbufpos < LDNS_MAX_PACKETLEN) {
		c = hexbuf[hexbufpos];
		if (state < 2 && !isascii(c)) {
			/*verbose("non ascii character found in file: (%d) switching to raw mode\n", c);*/
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
				fprintf(stderr, "unknown state while reading %s", hexbuf);
				return 0;
				break;
		}
	}

	if (c == EOF) {
		/*
		if (have_drill_opt && drill_opt->verbose) {
			verbose("END OF FILE REACHED\n");
			if (state < 2) {
				verbose("read:\n");
				verbose("%s\n", hexbuf);
			} else {
				verbose("Not printing wire because it contains non ascii data\n");
			}
		}
		*/
	}
	if (hexbufpos >= LDNS_MAX_PACKETLEN) {
		/*verbose("packet size reached\n");*/
	}
	
	/* lenient mode: length must be multiple of 2 */
	if (hexbufpos % 2 != 0) {
		hexbuf[hexbufpos] = (uint8_t) '0';
		hexbufpos++;
	}

	if (state < 2) {
		wirelen = hexstr2bin((char *) hexbuf, hexbufpos, wire, 0, LDNS_MAX_PACKETLEN);
	} else {
		memcpy(wire, hexbuf, (size_t) hexbufpos);
		wirelen = (size_t) hexbufpos;
	}
	return wirelen;
}	

ldns_pkt *
read_hex_pkt(char *hex_data)
{
	uint8_t *wire;
	size_t wiresize;
	ldns_status status = LDNS_STATUS_ERR;
	
	ldns_pkt *pkt = NULL;
	
	wire = malloc(LDNS_MAX_PACKETLEN);
	
	wiresize = packetbuffromfile(hex_data, wire);
	
	if (wiresize > 0) {
		status = ldns_wire2pkt(&pkt, wire, wiresize);
	}
	
	free(wire);
	
	if (status == LDNS_STATUS_OK) {
		return pkt;
	} else {
		return NULL;
	}
}

bool
dump_hex(FILE *fp, const ldns_pkt *pkt)
{
	uint8_t *wire;// = xmalloc((packet->udppacketsize)*21);
	size_t size, i;
	ldns_status status;
	
	status = ldns_pkt2wire(&wire, pkt, &size);
	
	if (status != LDNS_STATUS_OK) {
		fprintf(stdout, "= Unable to convert packet back to wire: error code %u", status);
		fprintf(stdout, "= original hex:\n");
		return false;
	}
	
	for (i = 0; i < size; i++) {
		fprintf(fp, "%02x", (unsigned int)wire[i]);
	}
	LDNS_FREE(wire);
	return true;
}


void
usage(FILE *fp)
{
	fprintf(fp, "pcat-diff FILE1 [FILE2]\n\n");
	fprintf(fp, "Show the difference between two pcat traces as generated by pcat.\n");
	fprintf(fp, "There are no options, is FILE2 is not given, standard input is read\n");
        fprintf(fp, "\nOUTPUT FORMAT:\n");
        fprintf(fp, "    Line based output format, each record consists of 4 lines:\n");
        fprintf(fp, "    1. xxx:yyy\t\tdecimal sequence numbers\n");
        fprintf(fp, "    2. hex dump\t\tquery in hex, network order\n");
        fprintf(fp, "    3. hex dump\t\tanswer of FILE 1 in hex, network order\n");
        fprintf(fp, "    4. hex dump\t\tanswer of FILE 2 in hex, network order\n\n");
        fprintf(fp, " If a difference in the query is spotted the sequence nmuber\n");
        fprintf(fp, " is prefixed by a 'q: ' and the query data is printed:\n");
        fprintf(fp, "    1. q: xxx:yyy\tdecimal sequence numbers\n");
        fprintf(fp, "    2. hex dump\t\tquery in hex, network order\n");
        fprintf(fp, "    3. hex dump\t\tquery of FILE 1 in hex, network order\n");
        fprintf(fp, "    4. hex dump\t\tquery of FILE 2 in hex, network order\n");
}

void
compare(struct dns_info *d1, struct dns_info *d2)
{
	ldns_pkt *p1, *p2;
	bool diff = false;
	char *pstr1, *pstr2;
	struct timeval now;

	gettimeofday(&now, NULL);
	
	if (strcmp(d1->qdata, d2->qdata) != 0) {
		fprintf(stderr, "Query differs!\n");
		fprintf(stdout, "q: %d:%d\n%s\n%s\n%s\n", (int)d1->seq, (int)d2->seq, 
			d1->qdata, d1->qdata, d2->qdata);
	} else {
		if (strcmp(d1->adata, d2->adata) != 0) {
			if (advanced) {
				/* try to read the packet and sort the sections */
				p1 = read_hex_pkt(d1->adata);
				p2 = read_hex_pkt(d2->adata);
				if (p1 && p2) {
ldns_pkt_set_timestamp(p1, now);
ldns_pkt_set_timestamp(p2, now);
					if (ldns_pkt_qdcount(p1) > 0) {
						ldns_rr_list2canonical(ldns_pkt_question(p1));
						ldns_rr_list_sort(ldns_pkt_question(p1));
					}
					if (ldns_pkt_ancount(p1) > 0) {
						ldns_rr_list2canonical(ldns_pkt_answer(p1));
						ldns_rr_list_sort(ldns_pkt_answer(p1));
					}
					if (ldns_pkt_nscount(p1) > 0) {
						ldns_rr_list2canonical(ldns_pkt_authority(p1));
						ldns_rr_list_sort(ldns_pkt_authority(p1));
					}
					if (ldns_pkt_arcount(p1) > 0) {
						ldns_rr_list2canonical(ldns_pkt_additional(p1));
						ldns_rr_list_sort(ldns_pkt_additional(p1));
					}
					if (ldns_pkt_qdcount(p2) > 0) {
						ldns_rr_list2canonical(ldns_pkt_question(p2));
						ldns_rr_list_sort(ldns_pkt_question(p2));
					}
					if (ldns_pkt_ancount(p2) > 0) {
						ldns_rr_list2canonical(ldns_pkt_answer(p2));
						ldns_rr_list_sort(ldns_pkt_answer(p2));
					}
					if (ldns_pkt_nscount(p2) > 0) {
						ldns_rr_list2canonical(ldns_pkt_authority(p2));
						ldns_rr_list_sort(ldns_pkt_authority(p2));
					}
					if (ldns_pkt_arcount(p2) > 0) {
						ldns_rr_list2canonical(ldns_pkt_additional(p2));
						ldns_rr_list_sort(ldns_pkt_additional(p2));
					}
					
					if (ameliorate_output) {
						/* extended checks */
						if (ldns_pkt_get_rcode(p1) == LDNS_RCODE_NOTIMPL && 
						    ldns_pkt_get_rcode(p2) == LDNS_RCODE_NOTAUTH) {
							differences++;
							notimpl_notauth++;
							ldns_pkt_set_rcode(p1, LDNS_RCODE_NOTAUTH);
						}
						if (ldns_pkt_get_rcode(p1) == LDNS_RCODE_NOTAUTH && 
						    ldns_pkt_get_rcode(p2) == LDNS_RCODE_NOTIMPL) {
							differences++;
							notimpl_notauth++;
							ldns_pkt_set_rcode(p1, LDNS_RCODE_NOTIMPL);
						}

						if (ldns_pkt_edns_do(p1) && 
						    !ldns_pkt_edns_do(p2)) {
						    	differences++;
						    	do_bit++;
						    	ldns_pkt_set_edns_do(p1, false);
						}
						if (!ldns_pkt_edns_do(p1) && 
						    ldns_pkt_edns_do(p2)) {
						    	differences++;
						    	do_bit++;
						    	ldns_pkt_set_edns_do(p1, true);
						}
						
					}

					/* simply do string comparison */
					pstr1 = ldns_pkt2str(p1);
					pstr2 = ldns_pkt2str(p2);
					if (strcmp(pstr1, pstr2) != 0) {
						diff = true;
					}
					
					if (diff) {
						if (show_originals) {
							fprintf(stdout, "%d:%d\n%s\n%s\n%s\n", (int)d1->seq, (int)d2->seq, 
								d1->qdata, d1->adata, d2->adata);
						} else {
							fprintf(stdout, "%d:%d\n", (int)d1->seq, (int)d2->seq);
							if (!dump_hex(stdout, p1)) {
								fprintf(stdout, "%s", d1->adata);
							}
							fprintf(stdout, "\n");
							if (!dump_hex(stdout, p2)) {
								fprintf(stdout, "%s", d2->adata);
							}
							fprintf(stdout, "\n");
						}
/*
ldns_pkt_print(stdout, p1);
ldns_pkt_print(stdout, p2);
*/
/*
printf(pstr1);
printf(pstr2);
printf("DIFF: %d\n", strcmp(pstr1, pstr2));
exit(0);
*/
					}
					LDNS_FREE(pstr1);
					LDNS_FREE(pstr2);
					ldns_pkt_free(p1);
					ldns_pkt_free(p2);
					
				} else {
					fprintf(stderr, "unable to parse string\n");
					fprintf(stdout, "= unable to parse string\n");
					fprintf(stdout, "%d:%d\n%s\n%s\n%s\n", (int)d1->seq, (int)d2->seq, 
						d1->qdata, d1->adata, d2->adata);
				}
			} else {
				fprintf(stdout, "%d:%d\n%s\n%s\n%s\n", (int)d1->seq, (int)d2->seq, 
					d1->qdata, d1->adata, d2->adata);
			}
		}
	}
}

int
main(int argc, char **argv)
{
	FILE *trace1;
	FILE *trace2;
	size_t i;
	ssize_t read1;
	size_t len1;
	char *line1;
	ssize_t read2;
	size_t len2;
	char *line2;

	struct dns_info d1;
	struct dns_info d2;

	i = 0;
	len1 = 0;
	line1 = NULL;
	len2 = 0;
	line2 = NULL;

	/* need two files */
	switch(argc) {
		case 1:
			usage(stdout);
			/* usage */
			exit(EXIT_FAILURE);
		case 2:
			if (!(trace1 = fopen(argv[1], "r"))) {
				fprintf(stderr, "Cannot open trace file `%s\'\n", argv[1]);
				exit(EXIT_FAILURE);
			}
			trace2 = stdin;
			break;
		case 3:
			if (!(trace1 = fopen(argv[1], "r"))) {
				fprintf(stderr, "Cannot open trace file `%s\'\n", argv[1]);
				exit(EXIT_FAILURE);
			}
			if (!(trace2 = fopen(argv[2], "r"))) {
				fprintf(stderr, "Cannot open trace file `%s\'\n", argv[1]);
				exit(EXIT_FAILURE);
			}
			break;
		default:
			exit(EXIT_FAILURE);
	}

	i = 1;

reread:
	read1 = getdelim(&line1, &len1, '\n', trace1);
	read2 = getdelim(&line2, &len2, '\n', trace2);
	if (read1 == -1 || read2 == -1) {
		fclose(trace1); fclose(trace2);
		exit(EXIT_SUCCESS);
	}
	if (read1 > 0) 
		line1[read1 - 1] = '\0';
	if (read2 > 0)
		line2[read2 - 1] = '\0';

	switch(i % LINES) {
		case SEQUENCE:
			d1.seq = atoi(line1);
			d2.seq = atoi(line2);
			break;
		case QDATA:
			d1.qdata = strdup(line1);
			d2.qdata = strdup(line2);
			break;
		case ADATA:
			d1.adata = strdup(line1);
			d2.adata = strdup(line2);
			break;
		case EMPTY:
			/* we now should have  */
			compare(&d1, &d2);
			free(d1.adata);
			free(d2.adata);
			free(d1.qdata);
			free(d2.qdata);
			break;
	}
	i++;
	goto reread;

	fclose(trace1);
	fclose(trace2);
	return 0;
}
