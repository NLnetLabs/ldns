/*
 * util.c
 *
 * some general memory functions
 *
 * a Net::DNS like library for C
 *
 * (c) NLnet Labs, 2004
 *
 * See the file LICENSE for the license
 */

#include <config.h>

#include <ldns/rdata.h>
#include <ldns/rr.h>
#include <util.h>
#include <strings.h>

#include <stdio.h>

/* put this here tmp. for debugging */
void
xprintf_rdf(ldns_rdf *rd)
{
	/* assume printable string */
	fprintf(stdout, "size\t:%u\n", (unsigned int)ldns_rdf_size(rd));
	fprintf(stdout, "type\t:%u\n", (unsigned int)ldns_rdf_get_type(rd));
	fprintf(stdout, "data\t:[%.*s]\n", (int)ldns_rdf_size(rd), (char*)ldns_rdf_data(rd));
}

void
xprintf_rr(ldns_rr *rr)
{
	/* assume printable string */
	uint16_t count, i;

	count = ldns_rr_rd_count(rr);

	for(i = 0; i < count; i++) {
		printf("print rd %u\n", (unsigned int) i);
		xprintf_rdf(rr->_rdata_fields[i]);
	}
}

ldns_lookup_table *
ldns_lookup_by_name(ldns_lookup_table *table, const char *name)
{
	while (table->name != NULL) {
		if (strcasecmp(name, table->name) == 0)
			return table;
		table++;
	}
	return NULL;
}

ldns_lookup_table *
ldns_lookup_by_id(ldns_lookup_table *table, int id)
{
	while (table->name != NULL) {
		if (table->id == id)
			return table;
		table++;
	}
	return NULL;
}

int 
get_bit(uint8_t bits[], size_t index)
{
	/*
	 * The bits are counted from left to right, so bit #0 is the
	 * left most bit.
	 */
	return (int) (bits[index / 8] & (1 << (7 - index % 8)));
}


int 
get_bit_r(uint8_t bits[], size_t index)
{
	/*
	 * The bits are counted from right to left, so bit #0 is the
	 * right most bit.
	 */
	return (int) bits[index / 8] & (1 << (index % 8));
}

inline long
power(long a, long b) {
	long result = 1;
	while (b > 0) {
		if (b & 1) {
			result *= a;
			if (b == 1) {
				return result;
			}
		}
		a *= a;
		b /= 2;
	}
	return result;
}

int
hexdigit_to_int(char ch)
{
	switch (ch) {
	case '0': return 0;
	case '1': return 1;
	case '2': return 2;
	case '3': return 3;
	case '4': return 4;
	case '5': return 5;
	case '6': return 6;
	case '7': return 7;
	case '8': return 8;
	case '9': return 9;
	case 'a': case 'A': return 10;
	case 'b': case 'B': return 11;
	case 'c': case 'C': return 12;
	case 'd': case 'D': return 13;
	case 'e': case 'E': return 14;
	case 'f': case 'F': return 15;
	default:
		abort();
	}
}

char 
int_to_hexdigit(int i)
{
	switch (i) {
	case 0: return '0';
	case 1: return '1';
	case 2: return '2';
	case 3: return '3';
	case 4: return '4';
	case 5: return '5';
	case 6: return '6';
	case 7: return '7';
	case 8: return '8';
	case 9: return '9';
	case 10: return 'a';
	case 11: return 'b';
	case 12: return 'c';
	case 13: return 'd';
	case 14: return 'e';
	case 15: return 'f';
	default:
		abort();
	}
}


uint32_t
strtottl(const char *nptr, const char **endptr)
{
        int sign = 0;
        uint32_t i = 0;
        uint32_t seconds = 0;

        for(*endptr = nptr; **endptr; (*endptr)++) {
                switch (**endptr) {
                case ' ':
                case '\t':
                        break;
                case '-':
                        if(sign == 0) {
                                sign = -1;
                        } else {
                                return (sign == -1) ? -seconds : seconds;
                        }
                        break;
                case '+':
                        if(sign == 0) {
                                sign = 1;
                        } else {
                                return (sign == -1) ? -seconds : seconds;
                        }
                        break;
                case 's':
                case 'S':
                        seconds += i;
                        i = 0;
                        break;
                case 'm':
                case 'M':
                        seconds += i * 60;
                        i = 0;
                        break;
                case 'h':
                case 'H':
                        seconds += i * 60 * 60;
                        i = 0;
                        break;
                case 'd':
                case 'D':
                        seconds += i * 60 * 60 * 24;
                        i = 0;
                        break;
                case 'w':
                case 'W':
                        seconds += i * 60 * 60 * 24 * 7;
                        i = 0;
                        break;
                case '0':
                case '1':
                case '2':
                case '3':
                case '4':
                case '5':
                case '6':
                case '7':
                case '8':
                case '9':
                        i *= 10;
                        i += (**endptr - '0');
                        break;
                default:
                        seconds += i;
                        return (sign == -1) ? -seconds : seconds;
                }
        }
        seconds += i;
        return (sign == -1) ? -seconds : seconds;
}
