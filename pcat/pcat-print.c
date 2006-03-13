#define _GNU_SOURCE

#include "config.h"

#include <ldns/dns.h>

#define SEQUENCE 1
#define QUERY    2
#define ANSWER1  3
#define ANSWER2  0
#define LINES    4

#ifndef HAVE_GETDELIM
ssize_t getdelim(char **lineptr, size_t *n, int delim, FILE *stream);
#endif

void
usage(FILE *fp)
{
        fprintf(fp, "pcat-print [-h] FILE\n\n");
        fprintf(fp, "Read the output of pcat-diff and try to convert the\n");
        fprintf(fp, "hex dump back in to DNS packets. Then print those packets\n");
	fprintf(fp, "to standard output or print the error in case the conversion failed.\n");
        fprintf(fp, "There are no options. If FILE is not given, standard input is read.\n");
        fprintf(fp, "\nOUTPUT FORMAT:\n");
        fprintf(fp, "  Each record consists of an index and then three packets.\n");
        fprintf(fp, "  Each packet is seperated by a line of '='s.\n");
        fprintf(fp, "    ==============\n");
        fprintf(fp, "    ==============\n");
        fprintf(fp, "    Index: xxx:xxx\n");
        fprintf(fp, "    ==============\n");
        fprintf(fp, "    query packet\n");
        fprintf(fp, "    ==============\n");
        fprintf(fp, "    first answer/query packet\n");
        fprintf(fp, "    ==============\n");
        fprintf(fp, "    second answer/query packet\n");
        fprintf(fp, "    ==============\n");
}

void
printf_bar(void)
{
	fprintf(stdout, "===================================================================\n");
}

int
main(int argc, char **argv)
{
	ssize_t read;
	char *line;
	size_t i, j, k, len;
	u_char pkt_buf[LDNS_MAX_PACKETLEN];
	ldns_pkt *p;
	ldns_status s;
	FILE *diff = stdin;

	i = 1;
	len = 0;
	line = NULL;

	/* -h option */
	if (argc > 1) {
		if (argv[1][0] == '-') {
			if (argv[1][1] == 'h') {
				usage(stdout);
				exit(EXIT_SUCCESS);
			} else {
				fprintf(stderr, "Uknown option '-%c\'\n", argv[1][1]);
				exit(EXIT_FAILURE);
			}
		} else {
			if (!(diff = fopen(argv[1], "r"))) {
                                fprintf(stderr, "Cannot open pcat diff file `%s\'\n", argv[1]);
                                exit(EXIT_FAILURE);
                        }
		}
	} 

	while((read = getdelim(&line, &len, '\n', diff)) != -1) {
		if (read < 2 || read > LDNS_MAX_PACKETLEN) {
			fprintf(stderr, "Under- or overflow - skipping line %zd\n", i);
			i++;
			continue;
		}
		
		line[read - 1] = '\0';
		switch(i % LINES) {
			case SEQUENCE:
				printf_bar();
				printf("Index: %s\n", line);
				printf_bar();
				break;
			case QUERY:
			case ANSWER1:
			case ANSWER2:
				k = 0;
				for(j = 0; j < read - 1; j += 2) {
					pkt_buf[k] = 
						ldns_hexdigit_to_int(line[j]) * 16 +
						ldns_hexdigit_to_int(line[j + 1]);
					k++;
				}
				s = ldns_wire2pkt(&p, pkt_buf, k);
				if (s != LDNS_STATUS_OK) {
					fprintf(stderr, "%s\n", ldns_get_errorstr_by_id(s));
				} else {
					ldns_pkt_print(stdout, p);
				}
				printf_bar();
				break;
		}
		i++;
		len = 0;
	}
	return 0;
}
