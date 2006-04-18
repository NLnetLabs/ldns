/*
 * util.c
 *
 * some general memory functions
 *
 * a Net::DNS like library for C
 *
 * (c) NLnet Labs, 2004-2006
 *
 * See the file LICENSE for the license
 */

#include <ldns/config.h>

#include <ldns/rdata.h>
#include <ldns/rr.h>
#include <ldns/util.h>
#include <strings.h>

#include <stdio.h>

/* put this here tmp. for debugging */
void
xprintf_rdf(ldns_rdf *rd)
{
	/* assume printable string */
	fprintf(stderr, "size\t:%u\n", (unsigned int)ldns_rdf_size(rd));
	fprintf(stderr, "type\t:%u\n", (unsigned int)ldns_rdf_get_type(rd));
	fprintf(stderr, "data\t:[%.*s]\n", (int)ldns_rdf_size(rd), 
			(char*)ldns_rdf_data(rd));
}

void
xprintf_rr(ldns_rr *rr)
{
	/* assume printable string */
	uint16_t count, i;

	count = ldns_rr_rd_count(rr);

	for(i = 0; i < count; i++) {
		fprintf(stderr, "print rd %u\n", (unsigned int) i);
		xprintf_rdf(rr->_rdata_fields[i]);
	}
}

void xprintf_hex(uint8_t *data, size_t len)
{
	size_t i;
	for (i = 0; i < len; i++) {
		if (i > 0 && i % 20 == 0) {
			printf("\t; %u - %u\n", (unsigned int) i - 19, (unsigned int) i);
		}
		printf("%02x ", (unsigned int) data[i]);
	}
	printf("\n");
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
ldns_get_bit(uint8_t bits[], size_t index)
{
	/*
	 * The bits are counted from left to right, so bit #0 is the
	 * left most bit.
	 */
	return (int) (bits[index / 8] & (1 << (7 - index % 8)));
}

int 
ldns_get_bit_r(uint8_t bits[], size_t index)
{
	/*
	 * The bits are counted from right to left, so bit #0 is the
	 * right most bit.
	 */
	return (int) bits[index / 8] & (1 << (index % 8));
}

void
ldns_set_bit(uint8_t *byte, int bit_nr, bool value) 
{
	if (bit_nr >= 0 && bit_nr < 8) {
		if (value) {
			*byte = *byte | (0x01 << bit_nr);
		} else {
			*byte = *byte & !(0x01 << bit_nr);
		}
	}
}

int
ldns_hexdigit_to_int(char ch)
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
		return -1;
	}
}

char 
ldns_int_to_hexdigit(int i)
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

const char *
ldns_version(void)
{
	return (char*)LDNS_VERSION;
}

/* Number of days per month (except for February in leap years). */
static const int mdays[] = {
	31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
};

static int 
is_leap_year(int year)
{
	return year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
}

static int
leap_days(int y1, int y2)
{
	--y1;
	--y2;
	return (y2/4 - y1/4) - (y2/100 - y1/100) + (y2/400 - y1/400);
}

/*
 * Code adapted from Python 2.4.1 sources (Lib/calendar.py).
 */
time_t
mktime_from_utc(const struct tm *tm)
{
	int year = 1900 + tm->tm_year;
	time_t days = 365 * ((time_t) year - 1970) + leap_days(1970, year);
	time_t hours;
	time_t minutes;
	time_t seconds;
	int i;

	for (i = 0; i < tm->tm_mon; ++i) {
		days += mdays[i];
	}
	if (tm->tm_mon > 1 && is_leap_year(year)) {
		++days;
	}
	days += tm->tm_mday - 1;

	hours = days * 24 + tm->tm_hour;
	minutes = hours * 60 + tm->tm_min;
	seconds = minutes * 60 + tm->tm_sec;

	return seconds;
}
