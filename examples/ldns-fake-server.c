/*
 * ldnsd. Light-weight DNS daemon
 *
 * Tiny dns server to show how a real one could be built.
 *
 * (c) NLnet Labs, 2005
 * See the file LICENSE for the license
 */

#include "config.h"
#include <ldns/ldns.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/igmp.h>

#include <errno.h>

#define INBUF_SIZE 4096
#define MAX_ANSWERS 100

void usage(FILE *output)
{
	fprintf(output, "Usage: ldns-fake-server [options] <address> <port> <packetfile>\n");
	fprintf(output, "  Listens on the specified port and answers queries with answers specified\n");
	fprintf(output, "  in the given file (hex format). The file can contain more than one answer,\n");
	fprintf(output, "  seperated by the * character, in which case the answers are given ");
	fprintf(output, "  sequentially.\n");
	fprintf(output, "\nOptions:\n");
	fprintf(output, "-c\tcopy the query section to the answer\n");
	fprintf(output, "-h\tshow this help\n");
	fprintf(output, "-i\tigore query completely, just send the next answer on any udp packet\n");
	fprintf(output, "-l\tloop over answers in answer file\n");
	fprintf(output, "-r\tuse a random port number, all output will be repressed, and only\n\ttheused port will be printed to stdout.\n");
	fprintf(output, "-v <int>\tset verbosity (0-4, default 1)\n");
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
packetbuffromfile(FILE *fp, uint8_t *wire)
{
	int c;
	
	/* stat hack
	 * 0 = normal
	 * 1 = comment (skip to end of line)
	 * 2 = unprintable character found, read binary data directly
	 */
	int state = 0;
	uint8_t *hexbuf;
	int hexbufpos = 0;
	size_t wirelen;
	
	c = fgetc(fp);
	if (c == EOF) {
		return 0;
	}
	
	hexbuf = LDNS_XMALLOC(uint8_t, LDNS_MAX_PACKETLEN);
	while (c != EOF && hexbufpos < LDNS_MAX_PACKETLEN && c != '*') {
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
				fprintf(stderr, "unknown state while reading");
				LDNS_FREE(hexbuf);
				return 0;
				break;
		}
		c = fgetc(fp);
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
	LDNS_FREE(hexbuf);
	return wirelen;
}	

int
read_answer_file(uint8_t **pkt_list, size_t *pkt_sizes, const char *filename)
{
	FILE *fp = NULL;
	uint8_t *answer_buf;
	size_t answer_size;
	
	int answer_count = 0;
	if (strncmp(filename, "-", 2) == 0) {
		fp = stdin;
	} else {
		fp = fopen(filename, "r");
	}
	if (fp == NULL) {
		perror("Unable to open file for reading");
		return 0;
	}
	
	answer_buf = LDNS_XMALLOC(uint8_t, LDNS_MAX_PACKETLEN);
	answer_size = packetbuffromfile(fp, answer_buf);
	while(answer_size > 0) {
		pkt_list[answer_count] = answer_buf;
		pkt_sizes[answer_count] = answer_size;
		answer_count++;
		answer_buf = LDNS_XMALLOC(uint8_t, LDNS_MAX_PACKETLEN);
		answer_size = packetbuffromfile(fp, answer_buf);
	}
	LDNS_FREE(answer_buf);
	
	fclose(fp);
	return answer_count;
}


size_t
create_answer(uint8_t **result_wire,
              uint8_t *inbuf,
              ssize_t nb,
              uint8_t *answer_wire,
              size_t answer_size,
              bool copy_query_section,
              int verbosity)
{
	ldns_status status;
	ldns_pkt *query_pkt;
	ldns_pkt *answer_pkt;
	size_t result_size;
	
	if (!result_wire) {
		fprintf(stderr, "Nowhere to put answer, please fix code\n");
		return 0;
	}

	status = ldns_wire2pkt(&query_pkt, inbuf, (size_t) nb);
	if (status != LDNS_STATUS_OK) {
		fprintf(stderr, "Got bad packet: %s\n",
		        ldns_get_errorstr_by_id(status));
		return 0;
	} else {
		if (verbosity >= 3) {
			ldns_pkt_print(stdout, query_pkt);
		}
	}
	
	status = ldns_wire2pkt(&answer_pkt, answer_wire, answer_size);
	if (status != LDNS_STATUS_OK) {
		fprintf(stderr, "Can't parse answer packet: %s\n",
		        ldns_get_errorstr_by_id(status));
		ldns_pkt_free(query_pkt);
		return 0;
	}

	ldns_pkt_set_id(answer_pkt, ldns_pkt_id(query_pkt));
	
	if (copy_query_section) {
		if (ldns_pkt_qdcount(answer_pkt) > 0) {
			ldns_rr_list_deep_free(ldns_pkt_question(answer_pkt));
			ldns_pkt_set_question(answer_pkt, 
		            ldns_rr_list_clone(ldns_pkt_question(query_pkt)));
			ldns_pkt_set_qdcount(answer_pkt, 
			    ldns_rr_list_rr_count(ldns_pkt_question(query_pkt)));
		}
	}
	
	status = ldns_pkt2wire(result_wire, answer_pkt, &result_size);
	
	if (status != LDNS_STATUS_OK) {
		fprintf(stderr, "Unable to convert answer back to wire: %s\n",
		        ldns_get_errorstr_by_id(status));
		ldns_pkt_free(query_pkt);
		ldns_pkt_free(answer_pkt);
		return 0;
	}
	
	if (verbosity >= 4) {
		printf("Sending answer:\n");
		ldns_pkt_print(stdout, answer_pkt);
	}

	ldns_pkt_free(answer_pkt);
	ldns_pkt_free(query_pkt);

	return answer_size;
}

int run_fake_server(int port,
                    uint8_t **pkt_list,
                    size_t *pkt_sizes,
                    int answer_count,
                    bool copy_query_section,
                    bool ignore_query,
                    bool loop,
                    int verbosity)
{
	struct sockaddr_in *sock_server, *sock_client;
	int s;
	socklen_t socklen = (socklen_t) sizeof(struct sockaddr_in);

	int current_answer = 0;

	uint8_t inbuf[LDNS_MAX_PACKETLEN];
	ssize_t nb;
	
	uint8_t *answer_wire;
	size_t answer_size;
	
	int result = 0;
	
	sock_server = (struct sockaddr_in *) malloc( socklen );

	if ( !sock_server) {
		perror( "allocation failed" );
		return -1;
	}

	if ((s = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
		perror("socket()");
		free(sock_server);
		return -1;
	}

	sock_server->sin_family = AF_INET;
	sock_server->sin_addr.s_addr = htonl(INADDR_ANY);

	if (port > 0) {
		sock_server->sin_port = (in_port_t) htons((uint16_t) port);
	
		if ( bind(s, (struct sockaddr *) sock_server, socklen ) == -1) {
			perror("bind()");
			free(sock_server);
			return -1;
		}
	} else {
		while (1) {
			port = (random() % 64510) + 1025;
			sock_server->sin_port = (in_port_t) htons((uint16_t) port);
			if ( bind(s, (struct sockaddr *) sock_server, socklen ) == -1) {
				if (errno != EADDRINUSE) {
					perror("bind()");
					free(sock_server);
					return -1;
				}
			} else {
				printf("%d\n", port);
				fflush(stdout);
				break;
			}
		}
	}

	sock_client = (struct sockaddr_in *) malloc( socklen );
	if ( !sock_client) {
		perror( "allocation failed" );
		return -1;
	}


	while( 1 ) {
		nb = recvfrom(s, inbuf, INBUF_SIZE, 0,
			     (struct sockaddr *) sock_client, &socklen);
		if (nb == -1) {
		    perror("recvfrom()");
		    result = -1;
		    goto stop;
		}

		if (verbosity >= 1) {
			printf("Received packet from %s:%u\n", 
			    inet_ntoa(sock_client->sin_addr),
			    (unsigned int) ntohs(sock_client->sin_port));
		}

		if (ignore_query) {
			nb = sendto(s,
			            pkt_list[current_answer],
			            pkt_sizes[current_answer],
			            0,
			            (struct sockaddr *) sock_client,
			            socklen);
			if (nb < 0) {
				fprintf(stderr, "Error sending data: %s\n", strerror(errno));
			}
			if (verbosity >= 2) {
				printf("sent %u bytes of answer\n", (unsigned int) nb);
			}
		} else {
			answer_size = create_answer(&answer_wire,
			                            inbuf,
			                            nb,
			                            pkt_list[current_answer],
			                            pkt_sizes[current_answer],
			                            copy_query_section,
			                            verbosity);
			if (answer_size < 1) {
				fprintf(stderr, "Could not create answer\n");
				result = -1;
				goto stop;
			}
			nb = sendto(s,
			            answer_wire,
			            answer_size,
			            0,
			            (struct sockaddr *)	sock_client,
			            socklen);
			
			LDNS_FREE(answer_wire);
		}
		
		if (verbosity >= 2) {
			printf("sent %u bytes of answer\n", (unsigned int) nb);
		}
		current_answer++;
		if (current_answer >= answer_count) {
			if (loop) {
				current_answer = 0;
			} else {
				goto stop;
			}
		}
		
		
	}

	stop:
	free(sock_server);
	free(sock_client);
	close(s);
	return result;

}

int main(int argc, char **argv)
{
	/* behaviour vars */
	bool copy_query_section = false;
	bool ignore_query = false;
	bool loop = false;

	/* command line settings */
	char *answer_file;
	int port = -1;
	int verbosity = 1;

	/* internal vars */
	char c;
	int current_answer;
	int answer_count = 0;
	uint8_t *pkt_list[MAX_ANSWERS];
	size_t pkt_sizes[MAX_ANSWERS];

	int result;
	
	while ((c = getopt(argc, argv, "chilp:rv:")) != -1) {
		switch (c) {
			case 'c':
				if (ignore_query) {
					fprintf(stderr, "-c and -i conflict, use -h for help\n");
					exit(EXIT_FAILURE);
				}
				copy_query_section = true;
				break;
			case 'h':
				usage(stdout);
				exit(EXIT_SUCCESS);
				break;
			case 'i':
				if (copy_query_section) {
					fprintf(stderr, "-c and -i conflict, use -h for help\n");
					exit(EXIT_FAILURE);
				}
				ignore_query = true;
				break;
			case 'l':
				loop = true;
				break;
			case 'p':
				if (port > -1) {
					usage(stderr);
					exit(EXIT_FAILURE);
				}
				port = atoi(optarg);
				if (port < 1 || port > 65535) {
					fprintf(stderr, "Bad port number\n");
					exit(EXIT_FAILURE);
				}
				break;
			case 'r':
				if (port > -1) {
					usage(stderr);
					exit(EXIT_FAILURE);
				}
				port = 0;
				verbosity = 0;
				break;
			case 'v':
				verbosity = atoi(optarg);
				break;
		}
	}
	argc -= optind;
	argv += optind;
	
	if (argc < 1) {
		fprintf(stderr, "Too few arguments\n\n");
		usage(stdout);
		exit(EXIT_FAILURE);
	} else {
		answer_file = argv[0];
	}
	
	if (port < 0) {
		fprintf(stderr, "No port given\n");
		exit(EXIT_FAILURE);
	}

	answer_count = read_answer_file(pkt_list, pkt_sizes, answer_file);

	if (answer_count < 1) {
		fprintf(stderr, "Answer reader failed, aborting\n");
		exit(EXIT_FAILURE);
	} else {
		if (verbosity >= 1) {
			printf("Read %d packets in answer file\n", answer_count);
		}
	}

	result = run_fake_server(port,
	                         pkt_list,
	                         pkt_sizes,
	                         answer_count,
	                         copy_query_section,
	                         ignore_query,
	                         loop,
	                         verbosity);

	for (current_answer = 0; 
	     current_answer < answer_count;
	     current_answer++) {
		LDNS_FREE(pkt_list[current_answer]);
	}

	return result;
}

