/*
 * str2host.c
 *
 * conversion routines from the presentation format
 * to the host format
 *
 * a Net::DNS like library for C
 *
 * (c) NLnet Labs, 2004
 *
 * See the file LICENSE for the license
 */
#include <config.h>

#include <ldns/str2host.h>

#include "util.h"

#include <sys/socket.h>
#include <arpa/inet.h>
#include <limits.h>

/**
 * convert a short in to wireformat 
 */
ldns_status
zparser_conv_short(ldns_rdf *rd, const char *shortstr)
{
	char *end = NULL;      /* Used to parse longs, ttls, etc.  */
	
	uint16_t *r;

	r = MALLOC(uint16_t);
	
	*r = htons((uint16_t)strtol(shortstr, &end, 0));
	
	if(*end != 0) {
		return LDNS_STATUS_INT_EXP;
	} else {
		rd = ldns_rdf_new(2, LDNS_RDF_TYPE_INT16, (uint8_t*)r);
		return LDNS_STATUS_OK;
	}
}

#if 0

/**
 * convert a hex value to wireformat
 */
ldns_status
zparser_conv_hex(ldns_rdf *rd, const char *hex)
{
	uint16_t *rd = NULL;
	uint8_t *t;
	size_t len;
	int i;
	
	len = strlen(hex);
	if (len % 2 != 0) {
		return NULL;
	//	error_prev_line("number of hex digits must be a multiple of 2");
	} else if (len > MAX_RDLENGTH * 2) {
		//error_prev_line("hex data exceeds maximum rdata length (%d)", MAX_RDLENGTH);
		return NULL
	} else {
		/* the length part */
		r = (uint16_t *) XMALLOC(uint16, len/2);
		*r = len/2;
		t = (uint8_t *)(r + 1);
    
		/* Now process octet by octet... */
		while (*hex) {
			*t = 0;
			for (i = 16; i >= 1; i -= 15) {
				switch (*hex) {
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
					*t += (*hex - '0') * i;
					break;
				case 'a':
				case 'b':
				case 'c':
				case 'd':
				case 'e':
				case 'f':
					*t += (*hex - 'a' + 10) * i;
					break;
				case 'A':
				case 'B':
				case 'C':
				case 'D':
				case 'E':
				case 'F':
					*t += (*hex - 'A' + 10) * i;
					break;
				default:
					//error_prev_line("illegal hex character '%c'", (int)*hex);
					return NULL;
				}
				++hex;
			}
			++t;
		}
        }
	return r;
}

/**
 * convert a time value to wireformat 
 */
uint16_t *
zparser_conv_time(ldns_rdf *rd, const char *time)
{
	/* convert a time YYHM to wireformat */
	uint16_t *r = NULL;
	struct tm tm;
	uint32_t l;

	/* Try to scan the time... */
	/* [XXX] the cast fixes compile time warning */
	if((char*)strptime(time, "%Y%m%d%H%M%S", &tm) == NULL) {
		error_prev_line("Date and time is expected");
	} else {

		r = (uint16_t *) region_alloc(
			region, sizeof(uint32_t) + sizeof(uint16_t));
		l = htonl(timegm(&tm));
		memcpy(r + 1, &l, sizeof(uint32_t));
		*r = sizeof(uint32_t);
	}
	return r;
}

uint16_t *
zparser_conv_protocol(region_type *region, const char *protostr)
{
	/* convert a protocol in the rdata to wireformat */
	struct protoent *proto;
	uint16_t *r = NULL;
 
	if((proto = getprotobyname(protostr)) == NULL) {
		error_prev_line("Unknown protocol");
	} else {

		r = (uint16_t *) region_alloc(
			region, sizeof(uint16_t) + sizeof(uint8_t));
		*r = sizeof(uint8_t);
		*(uint8_t *) (r + 1) = proto->p_proto;
	} 
	return r;
}

uint16_t *
zparser_conv_services(region_type *region, const char *proto, char *servicestr)
{
	/*
	 * Convert a list of service port numbers (separated by
	 * spaces) in the rdata to wireformat
	 */
	uint16_t *r = NULL;
	uint8_t bitmap[65536/8];
	char sep[] = " ";
	char *word;
	int max_port = -8;

	memset(bitmap, 0, sizeof(bitmap));
	for (word = strtok(servicestr, sep);
	     word;
	     word = strtok(NULL, sep))
	{
		struct servent *service = getservbyname(word, proto);
		if (service == NULL) {
			error_prev_line("Unknown service");
		} else if (service->s_port < 0 || service->s_port > 65535) {
			error_prev_line("bad port number %d", service->s_port);
		} else {
			set_bit(bitmap, service->s_port);
			if (service->s_port > max_port)
				max_port = service->s_port;
		}
        }

	r = (uint16_t *) region_alloc(region,
				      sizeof(uint16_t) + max_port / 8 + 1);
	*r = max_port / 8 + 1;
	memcpy(r + 1, bitmap, *r);
	
	return r;
}

uint16_t *
zparser_conv_period(region_type *region, const char *periodstr)
{
	/* convert a time period (think TTL's) to wireformat) */

	uint16_t *r = NULL;
	uint32_t l;
	char *end; 

	/* Allocate required space... */
	r = (uint16_t *) region_alloc(
		region, sizeof(uint16_t) + sizeof(uint32_t));
	l = htonl((uint32_t)strtottl((char *)periodstr, &end));

        if(*end != 0) {
		error_prev_line("Time period is expected");
        } else {
		memcpy(r + 1, &l, sizeof(uint32_t));
		*r = sizeof(uint32_t);
        }
	return r;
}


uint16_t *
zparser_conv_long(region_type *region, const char *longstr)
{
	char *end;      /* Used to parse longs, ttls, etc.  */
	uint16_t *r = NULL;
	uint32_t l;

	r = (uint16_t *) region_alloc(region,
				      sizeof(uint16_t) + sizeof(uint32_t));
	l = htonl((uint32_t)strtol(longstr, &end, 0));

	if(*end != 0) {
		error_prev_line("Long decimal value is expected");
        } else {
		memcpy(r + 1, &l, sizeof(uint32_t));
		*r = sizeof(uint32_t);
	}
	return r;
}

uint16_t *
zparser_conv_byte(region_type *region, const char *bytestr)
{

	/* convert a byte value to wireformat */
	char *end;      /* Used to parse longs, ttls, etc.  */
	uint16_t *r = NULL;
 
        r = (uint16_t *) region_alloc(region,
				      sizeof(uint16_t) + sizeof(uint8_t));

        *((uint8_t *)(r+1)) = (uint8_t)strtol(bytestr, &end, 0);

        if(*end != 0) {
		error_prev_line("Decimal value is expected");
        } else {
		*r = sizeof(uint8_t);
        }
	return r;
}

uint16_t *
zparser_conv_algorithm(region_type *region, const char *algstr)
{
	/* convert a algoritm string to integer */
	uint16_t *r = NULL;
	const lookup_table_type *alg;

	alg = lookup_by_name(algstr, zalgs);

	if (!alg) {
		/* not a memonic */
		return zparser_conv_byte(region, algstr);
	}

        r = (uint16_t *) region_alloc(region,
				      sizeof(uint16_t) + sizeof(uint8_t));
	*((uint8_t *)(r+1)) = alg->symbol;
	*r = sizeof(uint8_t);
	return r;
}

uint16_t *
zparser_conv_certificate_type(region_type *region, const char *typestr)
{
	/* convert a algoritm string to integer */
	uint16_t *r = NULL;
	const lookup_table_type *type;

	type = lookup_by_name(typestr, certificate_types);

	if (!type) {
		/* not a memonic */
		return zparser_conv_short(region, typestr);
	}

        r = (uint16_t *) region_alloc(region,
				      sizeof(uint16_t) + sizeof(uint16_t));
	*r = sizeof(uint16_t);
	copy_uint16(r + 1, type->symbol);
	return r;
}

uint16_t *
zparser_conv_a(region_type *region, const char *a)
{
	/* convert a A rdata to wire format */
	in_addr_t pin;
	uint16_t *r = NULL;

	r = (uint16_t *) region_alloc(region,
				      sizeof(uint16_t) + sizeof(in_addr_t));
	if(inet_pton(AF_INET, a, &pin) > 0) {
		memcpy(r + 1, &pin, sizeof(in_addr_t));
		*r = sizeof(in_addr_t);
	} else {
		error_prev_line("Invalid ip address");
	}
	return r;
}

/*
 * XXX: add length parameter to handle null bytes, remove strlen
 * check.
 */
uint16_t *
zparser_conv_text(region_type *region, const char *txt, size_t len)
{
	/* convert text to wireformat */
	uint16_t *r = NULL;

	if(len > 255) {
		error_prev_line("Text string is longer than 255 charaters, try splitting in two");
        } else {

		/* Allocate required space... */
		r = (uint16_t *) region_alloc(region,
					      sizeof(uint16_t) + len + 1);

		*((char *)(r+1))  = len;
		memcpy(((char *)(r+1)) + 1, txt, len);

		*r = len + 1;
        }
	return r;
}

uint16_t *
zparser_conv_a6(region_type *region, const char *a6)
{
	/* convert ip v6 address to wireformat */
	char pin[IP6ADDRLEN];
	uint16_t *r = NULL;

	r = (uint16_t *) region_alloc(region, sizeof(uint16_t) + IP6ADDRLEN);

        /* Try to convert it */
        if (inet_pton(AF_INET6, a6, pin) != 1) {
		error_prev_line("invalid IPv6 address");
        } else {
		*r = IP6ADDRLEN;
		memcpy(r + 1, pin, IP6ADDRLEN);
        }
        return r;
}

uint16_t *
zparser_conv_b64(region_type *region, const char *b64)
{
	uint8_t buffer[B64BUFSIZE];
	/* convert b64 encoded stuff to wireformat */
	uint16_t *r = NULL;
	int i;

        /* Try to convert it */
        if((i = b64_pton(b64, buffer, B64BUFSIZE)) == -1) {
		error_prev_line("Base64 encoding failed");
        } else {
		r = (uint16_t *) region_alloc(region, i + sizeof(uint16_t));
		*r = i;
		memcpy(r + 1, buffer, i);
        }
        return r;
}

uint16_t *
zparser_conv_rrtype(region_type *region, const char *rr)
{
	/*
	 * get the official number for the rr type and return
	 * that. This is used by SIG in the type-covered field
	 */

	/* [XXX] error handling */
	uint16_t type = lookup_type_by_name(rr);
	uint16_t *r;

	if (type == 0) {
		error_prev_line("unrecognized type '%s'", rr);
		return NULL;
	}
	
	r = (uint16_t *) region_alloc(region,
				      sizeof(uint16_t) + sizeof(uint16_t));
	r[0] = sizeof(uint16_t);
	r[1] = htons(type);
	return r;
}

uint16_t *
zparser_conv_nxt(region_type *region, uint8_t nxtbits[])
{
	/* nxtbits[] consists of 16 bytes with some zero's in it
	 * copy every byte with zero to r and write the length in
	 * the first byte
	 */
	uint16_t *r = NULL;
	uint16_t i;
	uint16_t last = 0;

	for (i = 0; i < 16; i++) {
		if (nxtbits[i] != 0)
			last = i + 1;
	}

	r = (uint16_t *) region_alloc(
		region, sizeof(uint16_t) + (last * sizeof(uint8_t)) );
	*r = last;
	memcpy(r+1, nxtbits, last);

	return r;
}


/* we potentially have 256 windows, each one is numbered. empty ones
 * should be discarded
 */
uint16_t *
zparser_conv_nsec(region_type *region, uint8_t nsecbits[NSEC_WINDOW_COUNT][NSEC_WINDOW_BITS_SIZE])
{
	/* nsecbits contains up to 64K of bits which represent the
	 * types available for a name. Walk the bits according to
	 * nsec++ draft from jakob
	 */
	uint16_t *r;
	uint8_t *ptr;
	size_t i,j;
	uint16_t window_count = 0;
	uint16_t total_size = 0;

	int used[NSEC_WINDOW_COUNT]; /* what windows are used. */
	int size[NSEC_WINDOW_COUNT]; /* what is the last byte used in the window, the
		index of 'size' is the window's number*/

	/* used[i] is the i-th window included in the nsec 
	 * size[used[0]] is the size of window 0
	 */

	/* walk through the 256 windows */
	for (i = 0; i < NSEC_WINDOW_COUNT; ++i) {
		int empty_window = 1;
		/* check each of the 32 bytes */
		for (j = 0; j < NSEC_WINDOW_BITS_SIZE; ++j) {
			if (nsecbits[i][j] != 0) {
				size[i] = j + 1;
				empty_window = 0;
			}
		}
		if (!empty_window) {
			used[window_count] = i;
			window_count++;
		}
	}

	for (i = 0; i < window_count; ++i) {
		total_size += sizeof(uint16_t) + size[used[i]];
	}
	
	r = (uint16_t *) region_alloc(
		region, sizeof(uint16_t) + total_size * sizeof(uint8_t));
	*r = total_size;
	ptr = (uint8_t *) (r + 1);

	/* now walk used and copy it */
	for (i = 0; i < window_count; ++i) {
		ptr[0] = used[i];
		ptr[1] = size[used[i]];
		memcpy(ptr + 2, &nsecbits[used[i]], size[used[i]]);
		ptr += size[used[i]] + 2;
	}

	return r;
}

/* Parse an int terminated in the specified range. */
static int
parse_int(const char *str, char **end, int *result, const char *name, int min, int max)
{
	*result = (int) strtol(str, end, 10);
	if (*result < min || *result > max) {
		error_prev_line("%s must be within the [%d .. %d] range", name, min, max);
		return 0;
	} else {
		return 1;
	}
}

/* RFC1876 conversion routines */
static unsigned int poweroften[10] = {1, 10, 100, 1000, 10000, 100000,
				1000000,10000000,100000000,1000000000};

/*
 * Converts ascii size/precision X * 10**Y(cm) to 0xXY.
 * Sets the given pointer to the last used character.
 *
 */
static uint8_t 
precsize_aton (char *cp, char **endptr)
{
	unsigned int mval = 0, cmval = 0;
	uint8_t retval = 0;
	int exponent;
	int mantissa;

	while (isdigit(*cp))
		mval = mval * 10 + (*cp++ - '0');

	if (*cp == '.') {	/* centimeters */
		cp++;
		if (isdigit(*cp)) {
			cmval = (*cp++ - '0') * 10;
			if (isdigit(*cp)) {
				cmval += (*cp++ - '0');
			}
		}
	}

	cmval = (mval * 100) + cmval;

	for (exponent = 0; exponent < 9; exponent++)
		if (cmval < poweroften[exponent+1])
			break;

	mantissa = cmval / poweroften[exponent];
	if (mantissa > 9)
		mantissa = 9;

	retval = (mantissa << 4) | exponent;

	if(*cp == 'm') cp++;

	*endptr = cp;

	return (retval);
}

/*
 * Parses a specific part of rdata.
 *
 * Returns:
 *
 *	number of elements parsed
 *	zero on error
 *
 */
uint16_t *
zparser_conv_loc(region_type *region, char *str)
{
	uint16_t *r;
	int i;
	int deg = 0, min = 0, secs = 0, secfraq = 0, altsign = 0, altmeters = 0, altfraq = 0;
	uint32_t lat = 0, lon = 0, alt = 0;
	uint8_t vszhpvp[4] = {0, 0, 0, 0};

	for(;;) {
		/* Degrees */
		if (*str == '\0') {
			error_prev_line("Unexpected end of LOC data");
			return NULL;
		}

		if (!parse_int(str, &str, &deg, "degrees", 0, 180))
			return NULL;
		if (!isspace(*str)) {
			error_prev_line("Space expected after degrees");
			return NULL;
		}
		++str;
		
		/* Minutes? */
		if (isdigit(*str)) {
			if (!parse_int(str, &str, &min, "minutes", 0, 60))
				return NULL;
			if (!isspace(*str)) {
				error_prev_line("Space expected after minutes");
				return NULL;
			}
		}
		++str;
		
		/* Seconds? */
		if (isdigit(*str)) {
			if (!parse_int(str, &str, &secs, "seconds", 0, 60))
				return NULL;
			if (!isspace(*str) && *str != '.') {
				error_prev_line("Space expected after seconds");
				return NULL;
			}
		}

		if (*str == '.') {
			secfraq = (int) strtol(str + 1, &str, 10);
			if (!isspace(*str)) {
				error_prev_line("Space expected after seconds");
				return NULL;
			}
		}
		++str;
		
		switch(*str) {
		case 'N':
		case 'n':
			lat = ((unsigned)1<<31) + (((((deg * 60) + min) * 60) + secs)
				* 1000) + secfraq;
			deg = min = secs = secfraq = 0;
			break;
		case 'E':
		case 'e':
			lon = ((unsigned)1<<31) + (((((deg * 60) + min) * 60) + secs) * 1000)
				+ secfraq;
			deg = min = secs = secfraq = 0;
			break;
		case 'S':
		case 's':
			lat = ((unsigned)1<<31) - (((((deg * 60) + min) * 60) + secs) * 1000)
				- secfraq;
			deg = min = secs = secfraq = 0;
			break;
		case 'W':
		case 'w':
			lon = ((unsigned)1<<31) - (((((deg * 60) + min) * 60) + secs) * 1000)
				- secfraq;
			deg = min = secs = secfraq = 0;
			break;
		default:
			error_prev_line("Invalid latitude/longtitude");
			return NULL;
		}
		++str;
		
		if (lat != 0 && lon != 0)
			break;

		if (!isspace(*str)) {
			error_prev_line("Space expected after latitude/longitude");
			return NULL;
		}
		++str;
	}

	/* Altitude */
	if (*str == '\0') {
		error_prev_line("Unexpected end of LOC data");
		return NULL;
	}

	/* Sign */
	switch(*str) {
	case '-':
		altsign = -1;
	case '+':
		++str;
		break;
	}

	/* Meters of altitude... */
	altmeters = strtol(str, &str, 10);
	switch(*str) {
	case ' ':
	case '\0':
	case 'm':
		break;
	case '.':
		++str;
		altfraq = strtol(str + 1, &str, 10);
		if (!isspace(*str) && *str != 0 && *str != 'm') {
			error_prev_line("Altitude fraction must be a number");
			return NULL;
		}
		break;
	default:
		error_prev_line("Altitude must be expressed in meters");
		return NULL;
	}
	if (!isspace(*str) && *str != '\0')
		++str;
	
	alt = (10000000 + (altsign * (altmeters * 100 + altfraq)));

	if (!isspace(*str) && *str != '\0') {
		error_prev_line("Unexpected character after altitude");
		return NULL;
	}

	/* Now parse size, horizontal precision and vertical precision if any */
	for(i = 1; isspace(*str) && i <= 3; i++) {
		vszhpvp[i] = precsize_aton(str + 1, &str);

		if (!isspace(*str) && *str != '\0') {
			error_prev_line("Invalid size or precision");
			return NULL;
		}
	}

	/* Allocate required space... */
	r = (uint16_t *) region_alloc(region, sizeof(uint16_t) + 16);
	*r = 16;

	memcpy(r + 1, vszhpvp, 4);

	copy_uint32(r + 3, lat);
	copy_uint32(r + 5, lon);
	copy_uint32(r + 7, alt);

	return r;
}

/*
 * Convert an APL RR RDATA element.
 */
uint16_t *
zparser_conv_apl_rdata(region_type *region, char *str)
{
	int negated = 0;
	uint16_t address_family;
	uint8_t prefix;
	uint8_t maximum_prefix;
	uint8_t length;
	uint8_t address[IP6ADDRLEN];
	char *colon = strchr(str, ':');
	char *slash = strchr(str, '/');
	int af;
	int rc;
	uint16_t rdlength;
	uint16_t *r;
	uint8_t *t;
	char *end;
	long p;
	
	if (!colon) {
		error("address family separator is missing");
		return NULL;
	}
	if (!slash) {
		error("prefix separator is missing");
		return NULL;
	}

	*colon = '\0';
	*slash = '\0';
	
	if (*str == '!') {
		negated = 1;
		++str;
	}

	if (strcmp(str, "1") == 0) {
		address_family = 1;
		af = AF_INET;
		length = sizeof(in_addr_t);
		maximum_prefix = length * 8;
	} else if (strcmp(str, "2") == 0) {
		address_family = 2;
		af = AF_INET6;
		length = IP6ADDRLEN;
		maximum_prefix = length * 8;
	} else {
		error("invalid address family '%s'", str);
		return NULL;
	}

	rc = inet_pton(af, colon + 1, address);
	if (rc == 0) {
		error("invalid address '%s'",
		      colon + 1, (int) address_family);
	} else if (rc == -1) {
		error("inet_pton failed: %s", strerror(errno));
	}

	/* Strip trailing zero octets.  */
	while (length > 0 && address[length - 1] == 0)
		--length;

	
	p = strtol(slash + 1, &end, 10);
	if (p < 0 || p > maximum_prefix) {
		error("prefix not in the range 0 .. %ld", maximum_prefix);
	} else if (*end != '\0') {
		error("invalid prefix '%s'", slash + 1);
	}
	prefix = (uint8_t) p;

	rdlength = (sizeof(address_family) + sizeof(prefix) + sizeof(length)
		    + length);
	r = (uint16_t *) region_alloc(region, sizeof(uint16_t) + rdlength);
	*r = rdlength;
	t = (uint8_t *) (r + 1);
	
	memcpy(t, &address_family, sizeof(address_family));
	t += sizeof(address_family);
	memcpy(t, &prefix, sizeof(prefix));
	t += sizeof(prefix);
	memcpy(t, &length, sizeof(length));
	if (negated)
		*t |= 0x80;
	t += sizeof(length);
	memcpy(t, address, length);

	return r;
}
#endif
