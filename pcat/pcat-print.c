#define _GNU_SOURCE

#include "config.h"

#include <ldns/ldns.h>

#define SEQUENCE 1
#define QUERY    2
#define ANSWER1  3
#define ANSWER2  0
#define LINES    4

#ifndef HAVE_GETDELIM
ssize_t getdelim(char **lineptr, size_t *n, int delim, FILE *stream);
#endif

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

	if (argc > 1) {
		if (!(diff = fopen(argv[1], "r"))) {
			fprintf(stderr, "Cannot open pcat diff file `%s\'\n", argv[1]);
			exit(EXIT_FAILURE);
		}
	} 

	while((read = getdelim(&line, &len, '\n', diff)) != -1) {
		if (read < 2 || read > LDNS_MAX_PACKETLEN) {
			if(read == 1) 
				fprintf(stdout, "NO ANSWER (line %d)\n", (int)i);
			else
				fprintf(stdout, "Under- or overflow (%d) - "
					"skipping line %d\n", (int)read, (int)i);
			i++;
			printf_bar();
			continue;
		}
		
		line[read - 1] = '\0';
		switch(i % LINES) {
			case SEQUENCE:
				printf_bar();
				fprintf(stdout, "Index: %s\n", line);
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
				fprintf(stdout, "=* %s\n", line);
				if (s != LDNS_STATUS_OK) {
					fprintf(stdout, "%s\n", ldns_get_errorstr_by_id(s));
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
