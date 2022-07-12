
#define _GNU_SOURCE
#include "config.h"

#include <ldns/ldns.h>
#include <pcap.h>
#include <errno.h>
#include <string.h>

#include <dirent.h>

#define SEQUENCE 1
#define QDATA    2
#define ADATA    3
#define EMPTY    0
#define LINES    4

#ifndef HAVE_GETDELIM
ssize_t getdelim(char **lineptr, size_t *n, int delim, FILE *stream);
#endif

#ifndef HAVE_STRNDUP
static char *
strndup(const char *s, size_t n)
{
	char *d;
	size_t l;
	if (!s) return NULL;
	l = strlen(s);
	if (n < l) l = n;
	d = malloc(l + 1);
	d[l] = '\0';
	memcpy(d, s, l);
	return d;
}
#endif

#define MAX_MATCH_WORDS 100
#define MAX_MATCH_FILES 1000

bool advanced_match = false;

/*
 * if this value is set, store all queries and answers that cause
 * known differences in a pcat hex file, named after the description:
 * <description>.knowndiff
 */
bool store_known_differences = false;

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

/* A match file contains 2 things, a short 1-line description, and
 * a packet specification
 */
struct match_file_struct {
	char *description;
	char *query_match;
	char *answer_match;
};

struct match_file_struct match_files[MAX_MATCH_FILES];
size_t match_file_count = 0;

int verbosity = 0;

int max_number = 0;
int min_number = 0;
size_t line_nr = 0;

size_t differences = 0;
size_t sames = 0;
size_t bytesames = 0;
size_t total_nr_of_packets = 0;
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


#define INITIAL_DIFFERENCES_SIZE 100
struct known_differences_struct
{
	char *descr;
	size_t count;
	FILE *file;
};
typedef struct known_differences_struct known_differences_count;

known_differences_count known_differences[INITIAL_DIFFERENCES_SIZE];
size_t known_differences_size = 0;

/*FILE *store_known_files[INITIAL_DIFFERENCES_SIZE];*/

size_t
add_known_difference(const char *diff)
{
	size_t i;

	char *store_file_name;
	FILE *store_file;
	
	for (i = 0; i < known_differences_size; i++) {
		if (strcmp(known_differences[i].descr, diff) == 0) {
			known_differences[i].count = known_differences[i].count + 1;

			return i;
		}
	}
	
	if (known_differences_size >= INITIAL_DIFFERENCES_SIZE) {
		fprintf(stderr, "err too much diffs\n");
		exit(1);
	} else {
		known_differences[known_differences_size].descr = strdup(diff);
		known_differences[known_differences_size].count = 1;

		if (store_known_differences) {
			store_file_name = malloc(strlen(diff) + 12);
			strcpy(store_file_name, "known.");
			strncpy(store_file_name + 6, diff, strlen(diff));
			strcpy(store_file_name + 6 + strlen(diff), ".pcat");
			if (verbosity > 3) {
				printf("Store packets in: '%s'\n", store_file_name);
			}
			store_file = fopen(store_file_name, "w");
			if (!store_file) {
				fprintf(stderr, "Error opening %s for writing: %s\n", store_file_name, strerror(errno));
				exit(errno);
			}
			known_differences[known_differences_size].file = store_file;
		}

		known_differences_size++;
		return known_differences_size - 1;
	}
}

int
compare_known_differences(const void *a, const void *b)
{
	known_differences_count *ac, *bc;
	
	if (!a || !b) {
		return 0;
	}
	
	ac = (known_differences_count *) a;
	bc = (known_differences_count *) b;
	
	return bc->count - ac->count;	
}

void
print_known_differences(FILE *output)
{
	size_t i;
	size_t difference_count = 0;
	size_t total;
	double percentage;
	
	qsort(known_differences, known_differences_size, sizeof(known_differences_count),
	      compare_known_differences);
	for (i = 0; i < known_differences_size; i++) {
		difference_count += known_differences[i].count;
	}

	total = difference_count + sames;

	for (i = 0; i < known_differences_size; i++) {
		percentage = (double) (((double) known_differences[i].count / (double)difference_count) * 100.0);
		fprintf(output, "%-48s", known_differences[i].descr);
		fprintf(output, "%8u\t(%02.2f%%)\n", (unsigned int) known_differences[i].count, percentage);
	}

	fprintf(output, "Total number of differences: %u (100%%)\n", (unsigned int) difference_count);
	fprintf(output, "Number of packets the same after normalization: %u\n", (unsigned int) sames);
	fprintf(output, "Number of packets exactly the same on the wire: %u\n", (unsigned int) bytesames);
	fprintf(output, "Total number of packets inspected: %u\n", (unsigned int) total);
}

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
	size_t hexbufpos = 0;
	size_t wirelen;
	
	while (hexbufpos < strlen(hexbuf) && hexbufpos < LDNS_MAX_PACKETLEN) {
		c = hexbuf[hexbufpos];
		if (state < 2 && !isascii(c)) {
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
		if (verbosity > 0) {
			fprintf(stderr, "Parse error: %s\n", ldns_get_errorstr_by_id(status));
			fprintf(stderr, "%s\n", hex_data);
		}
		return NULL;
	}
}

bool
dump_hex(FILE *fp, const ldns_pkt *pkt)
{
	uint8_t *wire;
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
	fprintf(fp, "pcat-diff [options] FILE1 [FILE2]\n\n");
	fprintf(fp, "Show the difference between two pcat traces as generated by pcat.\n");
	fprintf(fp, "There are no options, is FILE2 is not given, standard input is read\n");
	fprintf(fp, "\n");
	fprintf(fp, "Options:\n");
	fprintf(fp, "-d <dir>\tDirectory containing match files, this options sets\n\t\tthe advanced checking mode, see manpage\n");
	fprintf(fp, "-h\t\tshow this help\n");
	fprintf(fp, "-k\t\twhen also using -d, store all known differences in files\n\t\t(named known.<descr>.pcat in current directory)\n\t\tprintable with pcat-print\n");
	fprintf(fp, "-m <number>\tonly check up to <number> packets\n");
	fprintf(fp, "-o\t\tshow original packets when printing diffs (by default, \n\t\tpackets are normalized)\n");
	fprintf(fp, "-p <number>\tshow intermediate results every <number> packets\n");
	fprintf(fp, "-s <number>\tonly start checking after <number> packets\n");
	fprintf(fp, "-v\t\tVerbose mode\n");
	fprintf(fp, "\n");
        fprintf(fp, "\nOUTPUT FORMAT:\n");
        fprintf(fp, "    Line based output format, each record consists of 4 lines:\n");
        fprintf(fp, "    1. xxx:yyy\t\tdecimal sequence numbers\n");
        fprintf(fp, "    2. hex dump\t\tquery in hex, network order\n");
        fprintf(fp, "    3. hex dump\t\tanswer of FILE 1 in hex, network order\n");
        fprintf(fp, "    4. hex dump\t\tanswer of FILE 2 in hex, network order\n\n");
        fprintf(fp, " If a difference in the query is spotted the sequence number\n");
        fprintf(fp, " is prefixed by a 'q: ' and the query data is printed:\n");
        fprintf(fp, "    1. q: xxx:yyy\tdecimal sequence numbers\n");
        fprintf(fp, "    2. hex dump\t\tquery in hex, network order\n");
        fprintf(fp, "    3. hex dump\t\tquery of FILE 1 in hex, network order\n");
        fprintf(fp, "    4. hex dump\t\tquery of FILE 2 in hex, network order\n");
}

/*
 * file should contain text representation of dns packet
 *
 * packets must both match
 * * stands for 'match all until the first <number of stars> chars 
 * in match file match again
 * 
 * & the same, but packets must both be the same
 *
 * whitespace is always skipped
 *
 * Returns the description string from the first line of the file
 * that matches, or NULL if no matches are found
 */
 
int file_filter(const struct dirent *f)
{
	char *filename = (char *) f->d_name;
	char *dot;
	
	if (strncmp(filename, ".", 2) != 0 &&
	    strncmp(filename, "..", 3) != 0) {
		dot = strrchr(filename, '.');
		if (dot) {
			if (strcmp(dot, ".match") == 0) {
				return 1;
			}
		}
	}
	return 0;
}

#define MAX_DESCR_LEN 100

bool
compare_query(void)
{
	bool result = true;
	return result;
}

bool
compare_packets(void)
{
	bool result = true;
	return result;
}

char *
compare_to_file(ldns_pkt *qp, ldns_pkt *pkt1, ldns_pkt *pkt2)
{
	size_t iq, i1, i2, j, max_iq, max_i1, max_i2, max_j, k;
	char *pkt_str1 = ldns_pkt2str(pkt1);
	char *pkt_str2 = ldns_pkt2str(pkt2);
	char *pkt_query = ldns_pkt2str(qp);
	bool same = true;
	size_t match_count;

	char *match_words[MAX_MATCH_WORDS];
	size_t match_word_count;
	bool done;
	
	size_t cur_file_nr;
	
	char *description;
	char *query_match;
	char *answer_match;
	max_iq = strlen(pkt_query);
	max_i1 = strlen(pkt_str1);
	max_i2 = strlen(pkt_str2);
	
	if (verbosity > 3) {
		printf("PACKET 1:\n");
		ldns_pkt_print(stdout, pkt1);
		printf("\n\n\nPACKET 2:\n");
		ldns_pkt_print(stdout, pkt2);
		printf("\n\n\n");
	}

	for (cur_file_nr = 0; cur_file_nr < match_file_count; cur_file_nr++) {
		same = true;
		
		description = match_files[cur_file_nr].description;
		query_match = match_files[cur_file_nr].query_match;
		answer_match = match_files[cur_file_nr].answer_match;

		if (verbosity > 2) {
			printf("Trying: %s\n", description);\
		}
		if (verbosity > 3) {
			printf("MATCH TO:\n");
			printf("descr: %s\n", description);
			printf("QUERY:\n%s\n", query_match);
			printf("ANSWER:\n%s\n", answer_match);
		}

		/* first, try query match */
		
		/* special case for unparsable queries */
		if (!qp) {
			if (strncmp(query_match, "BADPACKET\n", 11) == 0 ||
			    strncmp(query_match, "*\n", 3) == 0
			   ) {
				same = true;
			} else {
				same = false;
			}
			goto querymatch;
		}
		
		max_j = strlen(query_match);
		iq = 0;
		j = 0;

		while (same && iq < max_iq && j < max_j) {
			if (pkt_query[iq] == ' ' ||
			    pkt_query[iq] == '\t' ||
			    pkt_query[iq] == '\n') {
				iq++;
			} else if (query_match[j] == ' ' ||
				   query_match[j] == '\t' ||
				   query_match[j] == '\n') {
				   j++;
			} else if (pkt_query[iq] == query_match[j]) {
				iq++;
				j++;
			} else if (query_match[j] == '*') {
				j++;
				match_count = 1;
				while (query_match[j] == '*') {
					match_count++;
					if (j + 1 < max_j) {
						j++;
					} else {
						goto querymatch;
					}
				}
				while (query_match[j] == ' ' ||
				       query_match[j] == '\n' ||
				       query_match[j] == '\t') {
					if (j + 1 < max_j) {
						j++;
					} else {
						goto querymatch;
					}
				}
				while (strncmp(&pkt_query[iq], &query_match[j], match_count) != 0) {
					if (iq < max_iq) {
						iq++;
					} else {
						if (verbosity > 1) {
							printf("End of query packet reached while doing a * check\n");
						}
						same = false;
						goto querymatch;
					}
				}
			} else if (query_match[j] == '[') {
				k = j + 1;
				done = false;
				match_word_count = 0;
				while (!done) {
					if (j < max_j) {
						j++;
					} else {
						fprintf(stderr, "Error: [ not closed\n");
						exit(2);
						same = false;
					}
					if (query_match[j] == '|' || query_match[j] == ']') {
						if (match_word_count < MAX_MATCH_WORDS) {
							match_words[match_word_count] =	strndup(&query_match[k], j - k);
							match_words[match_word_count][j-k] = 0;
							match_word_count++;
							k = j + 1;
						} else {
							fprintf(stderr, "Error, not more than %u match words (between [ and ]) allowed. Aborting\n", MAX_MATCH_WORDS);
							exit(3);
						}
						if (query_match[j] == ']') {
							done = true;
						}
						j++;
					}
				}
				
				while((pkt_query[iq] == ' ' ||
				      pkt_query[iq] == '\t' ||
				      pkt_query[iq] == '\n') &&
				      iq < max_iq) {
				      	if (iq < max_iq) {
					      	iq++;
					} else {
						if (verbosity > 1) {
							fprintf(stderr, "End query packet reached while looking for a match word ([])\n");
						}
						same = false;
						goto match_word_done_iq;
					}
				}
				
				for (k = 0; k < match_word_count; k++) {
					if (strncmp(&pkt_query[iq], match_words[k], strlen(match_words[k])) == 0) {
						/* ok */
						if (verbosity > 1) {
							printf("Found in 1, skipping\n");
						}
						iq += strlen(match_words[k]);
						goto found_iq;
					}
				}
				found_iq:
				if (k == match_word_count) {
					if (verbosity > 1) {
						fprintf(stderr, "no match word found in query packet. Rest of packet:\n");
						fprintf(stderr, "%s\n", &pkt_query[iq]);
					}
					same = false;
				}
				
				match_word_done_iq:
				for (k = 0; k < match_word_count; k++) {
					free(match_words[k]);
				}
				match_word_count = 0;
			} else if (query_match[j] == '?') {
				k = j + 1;
				while (query_match[j] != ' ' &&
				       query_match[j] != '\t' &&
				       query_match[j] != '\n' && 
				       j < max_j) {
					j++;
				}
				while((pkt_query[iq] == ' ' ||
				      pkt_query[iq] == '\t' ||
				      pkt_query[iq] == '\n') &&
				      iq < max_iq) {
				      	if (iq < max_iq) {
					      	iq++;
					}
				}
				if (iq + j - k < max_iq) {
					if (strncmp(&pkt_query[iq], &query_match[k], j - k) == 0) {
						iq += j - k;
					}
				}

			} else {
				if (verbosity > 1) {
					printf("Difference at iq: %u, j: %u, (%c != %c)\n", (unsigned int) iq, (unsigned int) j, pkt_query[iq], query_match[j]);
				}
				same = false;
			}
		}
		
		querymatch:
		
		if (same && verbosity > 0) {
			printf("query matches\n");
		}
		
		/* ok the query matches, now look at both answers */

		/* special case if one packet is null (ie. one server
		   answers and one doesn't) */
		if (same && (!pkt1 || !pkt2)) {
			if (strncmp(answer_match, "NOANSWER\n", 10) == 0 || 
			    strncmp(answer_match, "*\n", 3) == 0
			   ) {
				goto match;
			} else {
				same = false;
				if (verbosity > 4) {
					printf("no answer packet, no NOANSWER or * in spec.\n");
				}
			}
		}
		
		
		max_j = strlen(answer_match);
		i1 = 0;
		i2 = 0;
		j = 0;

		while (same && i1 < max_i1 && i2 < max_i2 && j < max_j) {
			if (pkt_str1[i1] == ' ' ||
			    pkt_str1[i1] == '\t' ||
			    pkt_str1[i1] == '\n') {
				i1++;
			} else if (pkt_str2[i2] == ' ' ||
				   pkt_str2[i2] == '\t' ||
				   pkt_str2[i2] == '\n') {
				i2++;
			} else if (answer_match[j] == ' ' ||
				   answer_match[j] == '\t' ||
				   answer_match[j] == '\n') {
				   j++;
			} else if (pkt_str1[i1] == pkt_str2[i2] && pkt_str2[i2] == answer_match[j]) {
				i1++;
				i2++;
				j++;
			} else if (answer_match[j] == '&') {
				j++;
				match_count = 1;
				while (answer_match[j] == '&') {
					match_count++;
					if (j + 1 < max_j) {
						j++;
					} else {
						/* TODO */
						/* check sameness to end*/
						if (verbosity >= 5) {
							printf("End of match reached in &\n");
						}
						goto match;
					}
				}
				while (answer_match[j] == ' ' ||
				       answer_match[j] == '\t' ||
				       answer_match[j] == '\n') {
				       	if (j + 1 < max_j) {
				       		j++;
					} else {
						/* TODO */
						/* check sameness to end*/
						if (verbosity >= 5) {
							printf("End of match reached in & (2)\n");
						}
						goto match;
					}
				}

/*
				while (((answer_match[j] == '?' && !(strncmp(&pkt_str1[i1], &answer_match[j+1], match_count) != 0 ||
				         strncmp(&pkt_str2[i2], &answer_match[j+1], match_count) != 0)) ||
				        (strncmp(&pkt_str1[i1], &answer_match[j], match_count) != 0 &&
				       strncmp(&pkt_str2[i2], &answer_match[j], match_count) != 0)) &&
				       same
*/
				while ((strncmp(&pkt_str1[i1], &answer_match[j], match_count) != 0 &&
				       strncmp(&pkt_str2[i2], &answer_match[j], match_count) != 0) &&
				       same
				      ) {

				        if (i1 < max_i1) {
						i1++;
						while ((pkt_str1[i1] == '\n' ||
						        pkt_str1[i1] == '\t' ||
						        pkt_str1[i1] == ' '
						       ) && i1 < max_i1) {
						       i1++;
						}
					} else {
						if (verbosity > 1) {
							printf("End of pkt1 reached while doing an & check\n");
						}
						same = false;
					}
					if (i2 < max_i2) {
						i2++;
						while ((pkt_str2[i2] == '\n' ||
						        pkt_str2[i2] == '\t' ||
						        pkt_str2[i2] == ' '
						       ) && i2 < max_i2) {
						       i2++;
						}
					} else {
						if (verbosity > 1) {
							printf("End of pkt2 reached while doing an & check\n");
						}
						same = false;
					}
					if (pkt_str1[i1] != pkt_str2[i2]) {
						if (verbosity > 1) {
							printf("Difference between the packets where they should be equal: %c != %c (%u, %u, & len: %u)\n", pkt_str1[i1], pkt_str2[i2], (unsigned int) i1, (unsigned int) i2, (unsigned int) match_count);
						}
						same = false;
					}
				}
			} else if (answer_match[j] == '*') {
				j++;
				match_count = 1;
				while (answer_match[j] == '*') {
					match_count++;
					if (j + 1 < max_j) {
						j++;
					} else {
						if (verbosity >= 5) {
							printf("End of match reached in *\n");
						}
						goto match;
					}
				}
				while (answer_match[j] == ' ' ||
				       answer_match[j] == '\n' ||
				       answer_match[j] == '\t') {
					if (j + 1 < max_j) {
						j++;
					} else {
						if (verbosity >= 5) {
							printf("End of match reached in * (2)\n");
						}
						goto match;
					}
				}
				while (strncmp(&pkt_str1[i1], &answer_match[j], match_count) != 0) {
					if (i1 < max_i1) {
						i1++;
					} else {
						if (verbosity > 1) {
							printf("End of pkt1 reached while doing a * check\n");
						}
						same = false;
						goto match;
					}
				}
				while ((answer_match[j] == '?' && strncmp(&pkt_str2[i2], &answer_match[j + 1], match_count) != 0)
				       || strncmp(&pkt_str2[i2], &answer_match[j], match_count) != 0) {
					if (i2 < max_i2) {
						i2++;
					} else {
						if (verbosity > 1) {
							printf("End of pkt2 reached while doing a * check\n");
						}
						same = false;
					}
				}
			} else if (answer_match[j] == '[') {
				k = j + 1;
				done = false;
				match_word_count = 0;
				while (!done) {
					if (j < max_j) {
						j++;
					} else {
						fprintf(stderr, "Error: no match found for [\n");
						exit(2);
						same = false;
					}
					if (answer_match[j] == '|' || answer_match[j] == ']') {
						if (match_word_count < MAX_MATCH_WORDS) {
							match_words[match_word_count] =	strndup(&answer_match[k], j - k);
							match_words[match_word_count][j-k] = 0;
							match_word_count++;
							k = j + 1;
						} else {
							fprintf(stderr, "Error, not more than %u match words (between [ and ]) allowed. Aborting\n", MAX_MATCH_WORDS);
							exit(3);
						}
						if (answer_match[j] == ']') {
							done = true;
						}
						j++;
					}
				}
				
				while((pkt_str1[i1] == ' ' ||
				      pkt_str1[i1] == '\t' ||
				      pkt_str1[i1] == '\n') &&
				      i1 < max_i1) {
				      	if (i1 < max_i1) {
					      	i1++;
					} else {
						if (verbosity > 1) {
							fprintf(stderr, "End of pkt 1 reached while looking for a match word ([])\n");
						}
						same = false;
						goto match_word_done;
					}
				}
				
				for (k = 0; k < match_word_count; k++) {
					if (strncmp(&pkt_str1[i1], match_words[k], strlen(match_words[k])) == 0) {
						/* ok */
						if (verbosity > 1) {
							printf("Found %s in 1, skipping\n", match_words[k]);
						}
						i1 += strlen(match_words[k]);
						goto found1;
					}
				}
				found1:
				if (k >= match_word_count) {
					if (verbosity > 1) {
						fprintf(stderr, "no match word found in packet 1. Rest of packet:\n");
						fprintf(stderr, "%s\n", &pkt_str1[i1]);
					}
					same = false;
				}
				
				while((pkt_str2[i2] == ' ' ||
				      pkt_str2[i2] == '\t' ||
				      pkt_str2[i2] == '\n') &&
				      i2 < max_i2) {
				      	if (i2 < max_i2) {
					      	i2++;
					} else {
						if (verbosity > 1) {
							fprintf(stderr, "End of pkt 2 reached while looking for a match word ([])\n");
						}
						same = false;
						goto match_word_done;
					}
				}
				
				for (k = 0; k < match_word_count; k++) {
					if (strncmp(&pkt_str2[i2], match_words[k], strlen(match_words[k])) == 0) {
						/* ok */
						if (verbosity > 1) {
							printf("Match word %s found in 2, skipping\n", match_words[k]);
						}
						i2 += strlen(match_words[k]);
						goto found2;
					}
				}
				found2:
				if (k >= match_word_count) {
					if (verbosity > 1) {
						fprintf(stdout, "no match word found in packet 2. Rest of packet:\n");
						fprintf(stdout, "%s\n", &pkt_str2[i2]);
					}
					same = false;
				}
				
				match_word_done:
				for (k = 0; k < match_word_count; k++) {
					free(match_words[k]);
				}
				match_word_count = 0;
			} else if (answer_match[j] == '?' &&
			           answer_match[j+1] == '&'
			          ) {
				j++;
				j++;
				k = j;
				while ((answer_match[j] != ' ' &&
				        answer_match[j] != '\t' &&
				        answer_match[j] != '\n'
				       ) && 
				       j < max_j) {
					j++;
				}
				while((pkt_str1[i1] == ' ' ||
				      pkt_str1[i1] == '\t' ||
				      pkt_str1[i1] == '\n') &&
				      i1 < max_i1) {
				      	if (i1 < max_i1) {
					      	i1++;
					}
				}

				while((pkt_str2[i2] == ' ' ||
				      pkt_str2[i2] == '\t' ||
				      pkt_str2[i2] == '\n') &&
				      i2 < max_i2) {
				      	if (i2 < max_i2) {
					      	i2++;
					}
				}
				if (i1 + j - k < max_i1 && i2 + j - k < max_i2) {
					if (strncmp(&pkt_str1[i1], &answer_match[k], j - k) == 0 &&
					    strncmp(&pkt_str2[i2], &answer_match[k], j - k) == 0
					   ) {
						i1 += j - k;
						i2 += j - k;
					}
				}
			} else if (answer_match[j] == '?') {
				j++;
				k = j;
				while ((answer_match[j] != ' ' &&
				        answer_match[j] != '\t' &&
				        answer_match[j] != '\n'
				       ) && 
				       j < max_j) {
					j++;
				}
				while((pkt_str1[i1] == ' ' ||
				      pkt_str1[i1] == '\t' ||
				      pkt_str1[i1] == '\n') &&
				      i1 < max_i1) {
				      	if (i1 < max_i1) {
					      	i1++;
					}
				}
				if (i1 + j - k < max_i1) {
					if (strncmp(&pkt_str1[i1], &answer_match[k], j - k) == 0) {
						i1 += j - k;
					}
				}

				while((pkt_str2[i2] == ' ' ||
				      pkt_str2[i2] == '\t' ||
				      pkt_str2[i2] == '\n') &&
				      i2 < max_i2) {
				      	if (i2 < max_i2) {
					      	i2++;
					}
				}
				if (i2 + j - k < max_i2) {
					if (strncmp(&pkt_str2[i2], &answer_match[k], j - k) == 0) {
						i2 += j - k;
					}
				}
			} else {
				if (verbosity > 1) {
					printf("Difference at i1: %u, i2: %u, j: %u (%c), (%c != %c)\n", (unsigned int) i1, (unsigned int) i2, (unsigned int) j, answer_match[j], pkt_str1[i1], pkt_str2[i2]);
					printf("rest of packet1:\n");
					printf("%s\n\n\n", &pkt_str1[i1]);
					printf("rest of packet 2:\n");
					printf("%s\n\n\n", &pkt_str2[i2]);
					printf("rest of match packet:\n");
					printf("%s\n\n\n", &answer_match[j]);
				}
				same = false;
			}
		}
		
		if (same) {
			if (verbosity >= 5) {
				printf("Big while loop ended, we have match\n");
			}
			goto match;
		} else {
			if (verbosity > 0) {
				printf("no match\n");
			}
			if (verbosity > 0) {
				printf("REST OF MATCH: %s\n", &answer_match[j]);
				printf("REST OF PKT1: %s\n", &pkt_str1[i1]);
				printf("REST OF PKT2: %s\n", &pkt_str2[i2]);
			}
		}
	}
	
	LDNS_FREE(pkt_str1);
	LDNS_FREE(pkt_str2);
	LDNS_FREE(pkt_query);
	
	if (verbosity > 0) {
		printf("<<<<<<< NO MATCH >>>>>>>>\n");
		printf("Query: %s\n", pkt_query);
		printf("Packet1:\n%s\n", pkt_str1);
		printf("Packet2:\n%s\n", pkt_str2);
	}
	return NULL;
	
	match:
	if (verbosity > 0) {
		printf("<<<<<<< MATCH!!! >>>>>>>>\n");
		printf("Query: %s\n", pkt_query);
		printf("Packet1:\n%s\n", pkt_str1);
		printf("Packet2:\n%s\n", pkt_str2);
		printf("MATCHES BECAUSE: %s\n", description);
		printf("-------------------------\n\n\n");
	}

	LDNS_FREE(pkt_str1);
	LDNS_FREE(pkt_str2);
	LDNS_FREE(pkt_query);
	return strdup(description);
}

void
compare(struct dns_info *d1, struct dns_info *d2)
{
	ldns_pkt *p1, *p2, *pq;
	bool diff = false;
	char *pstr1, *pstr2;
	struct timeval now;
	char *compare_result;
	size_t file_nr;

	gettimeofday(&now, NULL);
	if (verbosity > 0) {
		printf("Id: %u\n", (unsigned int) d1->seq);
	}
	
	if (strcmp(d1->qdata, d2->qdata) != 0) {
		fprintf(stderr, "Query differs!\n");
		fprintf(stdout, "q: %d:%d\n%s\n%s\n%s\n", (int)d1->seq, (int)d2->seq, 
			d1->qdata, d1->qdata, d2->qdata);
	} else {
		if (strcmp(d1->adata, d2->adata) != 0) {
			if (advanced_match) {
				/* try to read the packet and sort the sections */
				p1 = read_hex_pkt(d1->adata);
				p2 = read_hex_pkt(d2->adata);
				if (p1) {
					ldns_pkt_set_timestamp(p1, now);
				}
				if (p2) {
					ldns_pkt_set_timestamp(p2, now);
				}
				if (p1 && ldns_pkt_qdcount(p1) > 0) {
					ldns_rr_list2canonical(ldns_pkt_question(p1));
					ldns_rr_list_sort(ldns_pkt_question(p1));
				}
				if (p1 && ldns_pkt_ancount(p1) > 0) {
					ldns_rr_list2canonical(ldns_pkt_answer(p1));
					ldns_rr_list_sort(ldns_pkt_answer(p1));
				}
				if (p1 && ldns_pkt_nscount(p1) > 0) {
					ldns_rr_list2canonical(ldns_pkt_authority(p1));
					ldns_rr_list_sort(ldns_pkt_authority(p1));
				}
				if (p1 && ldns_pkt_arcount(p1) > 0) {
					ldns_rr_list2canonical(ldns_pkt_additional(p1));
					ldns_rr_list_sort(ldns_pkt_additional(p1));
				}
				if (p2 && ldns_pkt_qdcount(p2) > 0) {
					ldns_rr_list2canonical(ldns_pkt_question(p2));
					ldns_rr_list_sort(ldns_pkt_question(p2));
				}
				if (p2 && ldns_pkt_ancount(p2) > 0) {
					ldns_rr_list2canonical(ldns_pkt_answer(p2));
					ldns_rr_list_sort(ldns_pkt_answer(p2));
				}
				if (p2 && ldns_pkt_nscount(p2) > 0) {
					ldns_rr_list2canonical(ldns_pkt_authority(p2));
					ldns_rr_list_sort(ldns_pkt_authority(p2));
				}
				if (p2 && ldns_pkt_arcount(p2) > 0) {
					ldns_rr_list2canonical(ldns_pkt_additional(p2));
					ldns_rr_list_sort(ldns_pkt_additional(p2));
				}

				/* simply do string comparison first */
				pstr1 = ldns_pkt2str(p1);
				pstr2 = ldns_pkt2str(p2);
				if ((!p1 && !p2) || strcmp(pstr1, pstr2) != 0) {
					/* okay strings still differ, get the query and do a match for the match files */
					pq = read_hex_pkt(d1->qdata);
					compare_result = compare_to_file(pq, p1, p2);
					if (compare_result != NULL) {
						/*fprintf(stderr, compare_result);*/
						if (compare_result[strlen(compare_result)-1] == '\n') {
							compare_result[strlen(compare_result)-1] = 0;
						}
						file_nr = add_known_difference(compare_result);
						if (store_known_differences) {
							fprintf(known_differences[file_nr].file, "q: %d:%d\n%s\n%s\n%s\n", (int)d1->seq, (int)d2->seq, 
								d1->qdata, d1->adata, d2->adata);
						}
						
						free(compare_result);
						diff = false;
					} else {
						diff=false;
						printf("Error: Unknown difference in packet number %u:\n", (unsigned int) total_nr_of_packets);
						ldns_pkt_print(stdout, pq);
						printf("\n");
						ldns_pkt_print(stdout, p1);
						printf("\n");
						ldns_pkt_print(stdout, p2);
						
						printf("Quitting at packet %u\n", (unsigned int) d1->seq);
						exit(1);
					}
					ldns_pkt_free(pq);
				} else {
					sames++;
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
				}
				LDNS_FREE(pstr1);
				LDNS_FREE(pstr2);
				ldns_pkt_free(p1);
				ldns_pkt_free(p2);
			} else {
				fprintf(stdout, "%d:%d\n%s\n%s\n%s\n", (int)d1->seq, (int)d2->seq, 
					d1->qdata, d1->adata, d2->adata);
			}
		} else {
			sames++;
			bytesames++;
		}
	}
}

bool
read_match_files(char *directory)
{
	char *orig_cwd;
	char *cur_file_name;
	FILE *fp;
	struct dirent **files;
	int nr_of_files;
	int cur_file_nr;
	size_t j;
	char c;
	
	char *query_match;
	char *answer_match;
	char *description;

	nr_of_files = scandir(directory, &files, file_filter, alphasort);
	orig_cwd = malloc(100);
	(void) getcwd(orig_cwd, 100);
	if (chdir(directory) != 0) {
		fprintf(stderr, "Error opening directory %s: %s\n", directory, strerror(errno));
		exit(1);
	}
	if (nr_of_files < 1) {
		fprintf(stderr, "Warning: no match files found in %s\n", directory);
	}

	for (cur_file_nr = 0; cur_file_nr < nr_of_files; cur_file_nr++) {
	/* handle all files in dir */
		cur_file_name = files[cur_file_nr]->d_name;
		if (verbosity > 1) {
			printf("File: %s\n", cur_file_name);
		}
		description = LDNS_XMALLOC(char, MAX_DESCR_LEN);
		query_match = LDNS_XMALLOC(char, LDNS_MAX_PACKETLEN);
		answer_match = LDNS_XMALLOC(char, LDNS_MAX_PACKETLEN);

		for (j = 0; j < LDNS_MAX_PACKETLEN; j++) {
			query_match[j] = 0;
			answer_match[j] = 0;
		}
		
		fp = fopen(cur_file_name, "r");
		j = 0;
		if (!fp) {
			fprintf(stderr, "Unable to open %s for reading: %s\n", cur_file_name, strerror(errno));
			return false;
		} else {
			fgets(description, MAX_DESCR_LEN, fp);
			while ((c = getc(fp)) && c != '!' && c != EOF) {
				query_match[j] = c;
				j++;
			}
			if (j == 0) {
				fprintf(stderr, "Unable to read query match from %s; aborting\n", cur_file_name);
			}
			while ((c = getc(fp)) && c != '\n' && c != EOF) {
				/* skip line */
			}
			j = 0;
			while ((c = getc(fp)) && c != EOF) {
				answer_match[j] = c;
				j++;
			}
			if (j == 0) {
				fprintf(stderr, "Unable to read answer match from %s; aborting\n", cur_file_name);
			}			
			fclose(fp);
			match_files[match_file_count].description = description;
			fprintf(stderr, "read match file: %s\n", cur_file_name);
			match_files[match_file_count].query_match = query_match;
			match_files[match_file_count].answer_match = answer_match;
			match_file_count++;
		}
		free(files[cur_file_nr]);
	}
	free(files);
	chdir(orig_cwd);
	free(orig_cwd);
	return true;
}

void
free_match_files(void)
{
	size_t i;
	for (i = 0; i < match_file_count; i++) {
		LDNS_FREE(match_files[i].description);
		LDNS_FREE(match_files[i].query_match);
		LDNS_FREE(match_files[i].answer_match);
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
	char c;

	struct dns_info d1;
	struct dns_info d2;
	
	char *match_file_directory = NULL;

	int show_prelim_results = 0;
	
	i = 0;
	len1 = 0;
	line1 = NULL;
	len2 = 0;
	line2 = NULL;

	while ((c = getopt(argc, argv, "d:hkm:op:s:v:")) != -1) {
		switch (c) {
			case 'd':
				advanced_match = true;
				match_file_directory = optarg;
				break;
			case 'h':
				usage(stdout);
				exit(EXIT_SUCCESS);
				break;
			case 'k':
				store_known_differences = true;
				break;
			case 'm':
				max_number = atoi(optarg) - 1;
				break;
			case 'o':
				show_originals = true;
				break;
			case 'p':
				show_prelim_results = atoi(optarg);
				break;
			case 's':
				min_number = atoi(optarg) - 1;
				break;
			case 'v':
				verbosity = atoi(optarg);
				break;
		}
	}
	argc -= optind;
	argv += optind;
	
	/* need two files */
	switch(argc) {
		case 0:
			usage(stdout);
			/* usage */
			exit(EXIT_FAILURE);
		case 1:
			if (!(trace1 = fopen(argv[0], "r"))) {
				fprintf(stderr, "Cannot open trace file `%s\'\n", argv[1]);
				exit(EXIT_FAILURE);
			}
			trace2 = stdin;
			break;
		case 2:
			if (!(trace1 = fopen(argv[0], "r"))) {
				fprintf(stderr, "Cannot open trace file `%s\'\n", argv[1]);
				exit(EXIT_FAILURE);
			}
			if (!(trace2 = fopen(argv[1], "r"))) {
				fprintf(stderr, "Cannot open trace file `%s\'\n", argv[1]);
				exit(EXIT_FAILURE);
			}
			break;
		default:
			fprintf(stderr, "Too many arguments\n");
			exit(EXIT_FAILURE);
	}

	if (match_file_directory) {
		read_match_files(match_file_directory);
	}

	i = 1;

	while (max_number == 0 || total_nr_of_packets < max_number) {
		line_nr = i;
		read1 = getdelim(&line1, &len1, '\n', trace1);
		read2 = getdelim(&line2, &len2, '\n', trace2);
		if (read1 == -1 || read2 == -1) {
			print_known_differences(stdout);
			break;
		}
		if (read1 > 0) 
			line1[read1 - 1] = '\0';
		if (read2 > 0)
			line2[read2 - 1] = '\0';

		if (total_nr_of_packets >= min_number) {
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
				if (show_prelim_results > 0 && total_nr_of_packets % show_prelim_results == 0) {
					print_known_differences(stderr);
					fprintf(stderr, "\n");
				}
				total_nr_of_packets++;
				/* we now should have  */
				compare(&d1, &d2);
				free(d1.adata);
				free(d2.adata);
				free(d1.qdata);
				free(d2.qdata);
				break;
		}
		} else {
			if (i % LINES == EMPTY) {
				total_nr_of_packets++;
			}
		}
		i++;
	}

	free_match_files();
	free(line1);
	free(line2);
	fclose(trace1);
	fclose(trace2);
	print_known_differences(stdout);
	for (i = 0; i < known_differences_size; i++) {
		LDNS_FREE(known_differences[i].descr);
	}
	if (store_known_differences) {
		for (i = 0; i < known_differences_size; i++) {
			fclose(known_differences[i].file);
		}
	}
	return 0;
}
