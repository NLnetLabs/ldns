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
#include <ldns/dns.h>
#include <ldns/rdata.h>

#include "util.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>

#include <limits.h>
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

/**
 * convert a string to a int16 in wireformat
 * \param[in] rd the rdf where to put the data
 * \param[in] shortstr the string to be converted
 * \return ldns_status
 */
ldns_status
ldns_str2rdf_int16(ldns_rdf **rd, const char *shortstr)
{
	char *end = NULL;    
	uint16_t *r;
	r = MALLOC(uint16_t);
	
	*r = htons((uint16_t)strtol((char *)shortstr, &end, 0));
	
	if(*end != 0) {
		FREE(r);
		return LDNS_STATUS_INT_EXP;
	} else {
		*rd = ldns_rdf_new_frm_data(
			LDNS_RDF_TYPE_INT16, sizeof(uint16_t), r);
		FREE(r);
		return LDNS_STATUS_OK;
	}
}

/**
 * convert a time string to a time value in wireformat
 * \param[in] rd the rdf where to put the data
 * \param[in] time the string to be converted
 * \return ldns_status
 */
ldns_status
ldns_str2rdf_time(ldns_rdf **rd, const char *time)
{
	/* convert a time YYHM to wireformat */
	uint16_t *r = NULL;
	struct tm tm;
	uint32_t l;

	/* Try to scan the time... */
	r = (uint16_t*)MALLOC(uint32_t);

	if((char*)strptime(time, "%Y%m%d%H%M%S", &tm) == NULL) {
		FREE(r);
		return LDNS_STATUS_ERR;
	} else {
		l = htonl(timegm(&tm));
		memcpy(r, &l, sizeof(uint32_t));
		*rd = ldns_rdf_new_frm_data(
			LDNS_RDF_TYPE_TIME, sizeof(uint32_t), r);
		FREE(r);
		return LDNS_STATUS_OK;
	}
}

/* convert a time period (think TTL's) to wireformat) */
ldns_status
ldns_str2rdf_period(ldns_rdf **rd,const char *period)
{
        uint32_t p;
        const char *end;

        /* Allocate required space... */
        p = ldns_str2period(period, &end);

        if (*end != 0) {
		return LDNS_STATUS_ERR;
        } else {
                p = (uint32_t) htonl(p);
		*rd = ldns_rdf_new_frm_data(
			LDNS_RDF_TYPE_PERIOD, sizeof(uint32_t), &p);
        }
	return LDNS_STATUS_OK;
}

/**
 * convert a strings into a 4 byte int in wireformat
 * \param[in] rd the rdf where to put the data
 * \param[in] longstr the string to be converted
 * \return ldns_status
 */
ldns_status 
ldns_str2rdf_int32(ldns_rdf **rd, const char *longstr)
{
	char *end;  
	uint16_t *r = NULL;
	uint32_t l;

	r = (uint16_t*)MALLOC(uint32_t);
	l = htonl((uint32_t)strtol((char*)longstr, &end, 0));

	if(*end != 0) {
		FREE(r);
		return LDNS_STATUS_ERR;
        } else {
		memcpy(r, &l, sizeof(uint32_t));
		*rd = ldns_rdf_new_frm_data(
			LDNS_RDF_TYPE_INT32, sizeof(uint32_t), r);
		return LDNS_STATUS_OK;
	}
}

/**
 * convert a byte into wireformat
 * \param[in] rd the rdf where to put the data
 * \param[in] bytestr the string to be converted
 * \return ldns_status
 */
ldns_status
ldns_str2rdf_int8(ldns_rdf **rd, const char *bytestr)
{
	char *end;     
	uint8_t *r = NULL;

	r = MALLOC(uint8_t);
 
	*r = (uint8_t)strtol((char*)bytestr, &end, 0);

        if(*end != 0) {
		FREE(r);
		return LDNS_STATUS_ERR;
        } else {
		*rd = ldns_rdf_new_frm_data(
			LDNS_RDF_TYPE_INT8, sizeof(uint8_t), r);
		return LDNS_STATUS_OK;
        }
}

/**
 * convert a dname string into wireformat
 * \param[in] rd the rdf where to put the data
 * \param[in] str the string to be converted
 * \return ldns_status
 *
 * No special care is taken, all dots are translated into
 * label seperators.
 *
 * \todo make this more efficient...
 * we do 3 memcpy's in total...
 * label_chars2 is used for debugging. TODO: remove
 */
ldns_status
ldns_str2rdf_dname(ldns_rdf **d, const char *str)
{
	size_t len;

	uint8_t *s,*p,*q, *pq, val, label_len;
	uint8_t buf[MAX_DOMAINLEN + 1];
	*d = NULL;
	
	len = strlen((char*)str);
	if (len > MAX_DOMAINLEN) {
		return LDNS_STATUS_DOMAINNAME_OVERFLOW;
	}
	if (0 == len) {
		return LDNS_STATUS_DOMAINNAME_UNDERFLOW;
	} 
	
	/* root label */
	if (1 == len) {
		*d = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_DNAME, 1, "."); 
		return LDNS_STATUS_OK;
	}

	/* get on with the rest */

	/* s is on the current dot
	 * p on the previous one
	 * q builds the dname
	 */
	len = 0;
	q = buf+1;
	pq = buf;
	label_len = 0;
	for (s = p = (uint8_t *) str; *s; s++, q++) {
		*q = 0;
		switch (*s) {
		case '.':
			/* todo: check length (overflow und <1 */
			if (label_len > MAX_LABELLEN) {
				return LDNS_STATUS_LABEL_OVERFLOW;
			}
			if (label_len == 0) {
				return LDNS_STATUS_EMPTY_LABEL;
			}
			len += label_len + 1;
			*pq = label_len;
			label_len = 0;
			pq = q;
			p = s+1;
			break;
		case '\\':
			/* octet value or literal char */
			if (isdigit((int) s[1]) &&
			    isdigit((int) s[2]) &&
			    isdigit((int) s[3])) {
				val = (uint8_t) hexdigit_to_int((char) s[1]) * 100 +
				                hexdigit_to_int((char) s[2]) * 10 +
				                hexdigit_to_int((char) s[3]);
				*q = val;
				s += 3;
				s++;
				*q = *s;
			} else {
				s++;
				*q = *s;
			}
			label_len++;
			break;
		default:
			*q = *s;
			label_len++;
		}
	}

	/* add root label if last char was not '.' */
	if (str[strlen(str)-1] != '.') {
		len += label_len + 1;
		*pq = label_len;
		*q = 0;
	}
	len++;
	printf("len: %d\n", len);

	/* s - buf_str works because no magic is done in the above for-loop */
	*d = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_DNAME, len, buf); 
	return LDNS_STATUS_OK;
}

/**
 * convert str with an A record into wireformat
 * \param[in] rd the rdf where to put the data
 * \param[in] str the string to be converted
 * \return ldns_status
 */
ldns_status
ldns_str2rdf_a(ldns_rdf **rd, const char *str)
{
	in_addr_t address;
        if (inet_pton(AF_INET, (char*)str, &address) != 1) {
                return LDNS_STATUS_INVALID_IP4;
        } else {
		*rd = ldns_rdf_new_frm_data(
			LDNS_RDF_TYPE_A, sizeof(address), &address);
        }
	return LDNS_STATUS_OK;
}

/**
 * convert .... into wireformat
 * \param[in] rd the rdf where to put the data
 * \param[in] str the string to be converted
 * \return ldns_status
 */
ldns_status
ldns_str2rdf_aaaa(ldns_rdf **rd, const char *str)
{
	uint8_t address[LDNS_IP6ADDRLEN];

	if (inet_pton(AF_INET6, (char*)str, address) != 1) {
		return LDNS_STATUS_INVALID_IP6;
	} else {
		*rd = ldns_rdf_new_frm_data(
			LDNS_RDF_TYPE_AAAA, sizeof(address), &address);
	}
	return LDNS_STATUS_OK;
}

/**
 * convert a string into wireformat (think txt record)
 * \param[in] rd the rdf where to put the data
 * \param[in] str the string to be converted (NULL terminated)
 * \return ldns_status
 */
ldns_status
ldns_str2rdf_str(ldns_rdf **rd, const char *str)
{
	if (strlen(str) > 255) {
		return LDNS_STATUS_INVALID_STR;
	}
	*rd = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_STR, strlen(str), str);
	return LDNS_STATUS_OK;
}

/**
 * convert .... into wireformat
 * \param[in] rd the rdf where to put the data
 * \param[in] str the string to be converted
 * \return ldns_status
 */
ldns_status
ldns_str2rdf_apl(ldns_rdf **ATTR_UNUSED(rd), const char *ATTR_UNUSED(str))
{
	abort();
}

/**
 * convert .... into wireformat
 * \param[in] rd the rdf where to put the data
 * \param[in] str the string to be converted
 * \return ldns_status
 */
ldns_status
ldns_str2rdf_b64(ldns_rdf **rd, const char *str)
{
	uint8_t *buffer;
	int16_t i;
	
	buffer = XMALLOC(uint8_t, b64_ntop_calculate_size(strlen(str)));
	
	i = (uint16_t) b64_pton((const char*)str, buffer, 
	                        b64_ntop_calculate_size(strlen(str)));
	if (-1 == i) {
		return LDNS_STATUS_INVALID_B64;
	} else {
		*rd = ldns_rdf_new_frm_data(
			LDNS_RDF_TYPE_B64, (uint16_t) i, buffer);
	}
	FREE(buffer);
	return LDNS_STATUS_OK;
}

/**
 * convert a hex value into wireformat
 * \param[in] rd the rdf where to put the data
 * \param[in] str the string to be converted
 * \return ldns_status
 */
ldns_status
ldns_str2rdf_hex(ldns_rdf **rd, const char *str)
{
        uint8_t *t;
        int i;
	size_t len;

	len = strlen(str);

        if (len % 2 != 0) {
                return LDNS_STATUS_INVALID_HEX;
        } else if (len > MAX_RDFLEN * 2) {
		return LDNS_STATUS_LABEL_OVERFLOW;
        } else {
		t = XMALLOC(uint8_t, (len / 2));
    
                /* Now process octet by octet... */
                while (*str) {
                        *t = 0;
                        for (i = 16; i >= 1; i -= 15) {
                                if (isxdigit(*str)) {
                                        *t += hexdigit_to_int(*str) * i;
                                } else {
                                        return LDNS_STATUS_ERR;
                                }
                                ++str;
                        }
                        ++t;
                }
		*rd = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_HEX, len / 2, t);
        }
        return LDNS_STATUS_OK;
}

/**
 * convert .... into wireformat
 * \param[in] rd the rdf where to put the data
 * \param[in] str the string to be converted
 * \return ldns_status
 */
ldns_status
ldns_str2rdf_nsec(ldns_rdf **ATTR_UNUSED(rd), const char *ATTR_UNUSED(str))
{
	abort();
}

/**
 * convert a rrtype into wireformat
 * \param[in] rd the rdf where to put the data
 * \param[in] str the string to be converted
 * \return ldns_status
 */
ldns_status
ldns_str2rdf_type(ldns_rdf **rd, const char *str)
{
	uint16_t type;
	type = htons(ldns_get_rr_type_by_name(str));
	/* ldns_rr_type is a 16 bit value */
	*rd = ldns_rdf_new_frm_data(
		LDNS_RDF_TYPE_TYPE, sizeof(uint16_t), &type);
	return LDNS_STATUS_OK;
}

/**
 * convert .... into wireformat
 * \param[in] rd the rdf where to put the data
 * \param[in] str the string to be converted
 * \return ldns_status
 */
ldns_status
ldns_str2rdf_class(ldns_rdf **ATTR_UNUSED(rd), const char *str)
{
	uint16_t klass;
	klass = htons(ldns_get_rr_class_by_name(str));
	/* class is 16 bit */
	*rd = ldns_rdf_new_frm_data(
		LDNS_RDF_TYPE_CLASS, sizeof(uint16_t), &klass);
	return LDNS_STATUS_OK;
}

/**
 * convert .... into wireformat
 * \param[in] rd the rdf where to put the data
 * \param[in] str the string to be converted
 * \return ldns_status
 */
ldns_status
ldns_str2rdf_cert(ldns_rdf **ATTR_UNUSED(rd), const char *ATTR_UNUSED(str))
{
	abort();
}

/**
 * convert and algorithm value into wireformat
 * \param[in] rd the rdf where to put the data
 * \param[in] str the string to be converted
 * \return ldns_status
 */
/* An alg field can either be specified as a 8 bits number
 * or by its symbolic name. Handle both
 */
ldns_status
ldns_str2rdf_alg(ldns_rdf **rd, const char *str)
{
	ldns_lookup_table *lt;
	ldns_status st;

	lt = ldns_lookup_by_name(ldns_algorithms, str);
	st = LDNS_STATUS_OK;

	if (lt) {
		/* it was given as a integer */
		*rd = ldns_rdf_new_frm_data(
			LDNS_RDF_TYPE_INT8, sizeof(uint8_t), &lt->id);
		if (!*rd) {
			st = LDNS_STATUS_ERR;
		}
	} else {
		/* try as-is (a number) */
		st = ldns_str2rdf_int8(rd, str);
	}
	return st;
}
		
/**
 * convert .... into wireformat
 * \param[in] rd the rdf where to put the data
 * \param[in] str the string to be converted
 * \return ldns_status
 */
ldns_status
ldns_str2rdf_unknown(ldns_rdf **ATTR_UNUSED(rd), const char *ATTR_UNUSED(str))
{
	abort();
}

/**
 * convert .... into wireformat
 * \param[in] rd the rdf where to put the data
 * \param[in] str the string to be converted
 * \return ldns_status
 */
ldns_status
ldns_str2rdf_tsig(ldns_rdf **ATTR_UNUSED(rd), const char *ATTR_UNUSED(str))
{
	abort();
}

/**
 * convert .... into wireformat
 * \param[in] rd the rdf where to put the data
 * \param[in] str the string to be converted
 * \return ldns_status
 */
ldns_status
ldns_str2rdf_service(ldns_rdf **ATTR_UNUSED(rd), const char *ATTR_UNUSED(str))
{
	abort();
}

/**
 * convert .... into wireformat
 * \param[in] rd the rdf where to put the data
 * \param[in] str the string to be converted
 * \return ldns_status
 */
ldns_status
ldns_str2rdf_loc(ldns_rdf **ATTR_UNUSED(rd), const char *ATTR_UNUSED(str))
{
	abort();
}

/**
 * convert .... into wireformat
 * \param[in] rd the rdf where to put the data
 * \param[in] str the string to be converted
 * \return ldns_status
 */
ldns_status
ldns_str2rdf_wks(ldns_rdf **ATTR_UNUSED(rd), const char *ATTR_UNUSED(str))
{
	abort();
}

/**
 * convert .... into wireformat
 * \param[in] rd the rdf where to put the data
 * \param[in] str the string to be converted
 * \return ldns_status
 */
ldns_status
ldns_str2rdf_nsap(ldns_rdf **ATTR_UNUSED(rd), const char *ATTR_UNUSED(str))
{
	abort();
}



#if 0

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
	uint8_t address[LDNS_IP6ADDRLEN];
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
		length = LDNS_IP6ADDRLEN;
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
