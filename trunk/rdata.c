/*
 * rdata.c
 *
 * rdata implementation
 *
 * a Net::DNS like library for C
 *
 * (c) NLnet Labs, 2004
 *
 * See the file LICENSE for the license
 */

#include <config.h>

#include <ldns/rdata.h>
#include <ldns/error.h>
#include <ldns/str2host.h>
#include <ldns/dns.h>

#include "util.h"
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>


/*
 * Access functions 
 * do this as functions to get type checking
 */

/* read */
uint16_t
ldns_rdf_size(const ldns_rdf *rd)
{
	return rd->_size;
}

ldns_rdf_type
ldns_rdf_get_type(const ldns_rdf *rd)
{
	return rd->_type;
}

uint8_t *
ldns_rdf_data(const ldns_rdf *rd)
{
	return rd->_data;
}

/* write */
void
ldns_rdf_set_size(ldns_rdf *rd, uint16_t s)
{
	rd->_size = s;
}

void
ldns_rdf_set_type(ldns_rdf *rd, ldns_rdf_type t)
{
	rd->_type = t;
}

void
ldns_rdf_set_data(ldns_rdf *rd, void *d)
{
	/* only copy the pointer */
	rd->_data = d;
}


/* for types that allow it, return
 * the native/host order type */

/** return the native uint8_t repr. from the rdf
 * \param[in] rd the ldns_rdf to operate on
 * \return uint8_t the value extracted
 */
uint8_t
ldns_rdf2native_int8(ldns_rdf *rd)
{
	uint8_t data;
	
	switch(ldns_rdf_get_type(rd)) {
		case LDNS_RDF_TYPE_CLASS:
		case LDNS_RDF_TYPE_ALG:
		case LDNS_RDF_TYPE_INT8:
			memcpy(&data, ldns_rdf_data(rd), sizeof(data));
			return data;
		default:
			return 0;
	}
}

/** return the native uint16_t repr. from the rdf
 * \param[in] rd the ldns_rdf to operate on
 * \return uint16_t the value extracted
 */
uint16_t
ldns_rdf2native_int16(ldns_rdf *rd)
{
	uint16_t data;
	
	switch(ldns_rdf_get_type(rd)) {
		case LDNS_RDF_TYPE_INT16:
			memcpy(&data, ldns_rdf_data(rd), sizeof(data));
			return ntohs(data);
		default:
			return 0;
	}
}

/** return the native uint32_t repr. from the rdf
 * \param[in] rd the ldns_rdf to operate on
 * \return uint32_t the value extracted
 */
uint32_t
ldns_rdf2native_int32(ldns_rdf *rd)
{
	uint32_t data;
	
	switch(ldns_rdf_get_type(rd)) {
		case LDNS_RDF_TYPE_INT32:
			memcpy(&data, ldns_rdf_data(rd), sizeof(data));
			return ntohl(data);
		default:
			return 0;
	}
}

/** 
 * return the native sockaddr repr. from the rdf
 * \param[in] rd the ldns_rdf to operate on
 * \return struct sockaddr* the address in the format so other
 * functions can use it (sendto)
 */
struct sockaddr_storage *
ldns_rdf2native_sockaddr_storage(ldns_rdf *rd)
{
	struct sockaddr_storage *data;
	struct sockaddr_in  *data_in;
	struct sockaddr_in6 *data_in6;
	struct in_addr *b;
	
	b = (struct in_addr*)rd->_data;
	
	data = MALLOC(struct sockaddr_storage);

	switch(ldns_rdf_get_type(rd)) {
		case LDNS_RDF_TYPE_A:
			data->ss_family = AF_INET;
			data_in = (struct sockaddr_in*) data;
			data_in->sin_port = htons(LDNS_PORT); 
			memcpy(&(data_in->sin_addr), ldns_rdf_data(rd), ldns_rdf_size(rd));
			return data;
		case LDNS_RDF_TYPE_AAAA:
			data->ss_family = AF_INET6;
			data_in6 = (struct sockaddr_in6*) data;
			data_in6->sin6_port = htons(LDNS_PORT); 

			memcpy(&data_in6->sin6_addr, ldns_rdf_data(rd), ldns_rdf_size(rd));
			return data;
		default:
			FREE(data);
			printf("_aaaaa something is wrong, should not reached this\n\n");
			return NULL;
	}
}

/**
 * Returns an rdf that contains the given int8 value
 *
 * Because multiple rdf types can contain an int8, the
 * type must be specified
 */
ldns_rdf *
ldns_native2rdf_int8(ldns_rdf_type type, uint8_t value)
{
	return ldns_rdf_new_frm_data(type, 1, &value);
}

/**
 * Returns an rdf that contains the given int16 value
 *
 * Because multiple rdf types can contain an int16, the
 * type must be specified
 */
ldns_rdf *
ldns_native2rdf_int16(ldns_rdf_type type, uint16_t value)
{
	uint16_t *rdf_data = XMALLOC(uint16_t, 1);
	write_uint16(rdf_data, value);
	return ldns_rdf_new(2, type, rdf_data);
}

/**
 * Returns an rdf that contains the given int32 value
 *
 * Because multiple rdf types can contain an int32, the
 * type must be specified
 */
ldns_rdf *
ldns_native2rdf_int32(ldns_rdf_type type, uint32_t value)
{
	uint32_t *rdf_data = XMALLOC(uint32_t, 1);
	write_uint32(rdf_data, value);
	return ldns_rdf_new(4, type, rdf_data);
}

/**
 * Returns an int16_data rdf that contains the data in the
 * given array, preceded by an int16 specifying the length
 *
 * The memory is copied, and an LDNS_RDF_TYPE_INT16DATA is returned
 */
ldns_rdf *
ldns_native2rdf_int16_data(uint16_t size, uint8_t *data)
{
	uint8_t *rdf_data = XMALLOC(uint8_t, (size_t) size + 2);
	write_uint16(rdf_data, size);
	memcpy(rdf_data + 2, data, size);
	return ldns_rdf_new(size + 2, LDNS_RDF_TYPE_INT16_DATA, rdf_data);
}

/**
 * Allocate a new ldns_rdf structure 
 * fill it and return it
 */
ldns_rdf *
ldns_rdf_new(uint16_t s, ldns_rdf_type t, void *d)
{
	ldns_rdf *rd;
	rd = MALLOC(ldns_rdf);
	if (!rd) {
		return NULL;
	}
	ldns_rdf_set_size(rd, s);
	ldns_rdf_set_type(rd, t);
	ldns_rdf_set_data(rd, d);
	return rd;
}

/**
 * Allocate a new rdf structure and fill it.
 * This function _does_ copy the contents from
 * the buffer, unlinke ldns_rdf_new()
 * \param[in] s size of the buffer
 * \param[in] t type of the rdf
 * \param[in] buf pointer to the buffer to be copied
 * \return the new rdf structure or NULL on failure
 */
ldns_rdf *
ldns_rdf_new_frm_data(ldns_rdf_type type, uint16_t size, const void *data)
{
	ldns_rdf *rdf;
	rdf = MALLOC(ldns_rdf);
	if (!rdf) {
		return NULL;
	}
	rdf->_data = XMALLOC(uint8_t, size);
	if (!rdf->_data) {
		return NULL;
	}
	
	ldns_rdf_set_type(rdf, type);
	ldns_rdf_set_size(rdf, size);
	memcpy(rdf->_data, data, size);
	return rdf;
}

/**
 * clone a rdf structure. The data is copied
 * \param[in] r rdf to be copied
 * \return a new rdf structure
 */
ldns_rdf *
ldns_rdf_deep_clone(const ldns_rdf *r)
{
	return (ldns_rdf_new_frm_data(
				ldns_rdf_get_type(r),
				ldns_rdf_size(r), 
				ldns_rdf_data(r)));
}

/**
 * free a rdf structure _and_ free the
 * data. rdf should be created with _new_frm_data
 * \param[in] rd the rdf structure to be freed
 * \return void
 */
void
ldns_rdf_free_data(ldns_rdf *rd)
{
	FREE(rd->_data);
	FREE(rd);
}

/**
 * Free a rdf structure leave the 
 * data pointer intact
 * \param[in] rd the pointer to be freed
 * \return void
 */
void 
ldns_rdf_free(ldns_rdf *rd)
{
	if (rd) {
		if (rd->_data) {
			FREE(rd->_data);
		}
		FREE(rd);
	}
}

/**
 * Create a new rdf from a string
 * \param[in] str string to use
 * \param[in] t   type to use
 * \return ldns_rdf*
 */
ldns_rdf *
ldns_rdf_new_frm_str(ldns_rdf_type type, const char *str)
{
	ldns_rdf *rdf;
	ldns_status status;

	switch (type) {
	case LDNS_RDF_TYPE_DNAME:
		status = ldns_str2rdf_dname(&rdf, str);
		break;
	case LDNS_RDF_TYPE_INT8:
		status = ldns_str2rdf_int8(&rdf, str);
		break;
	case LDNS_RDF_TYPE_INT16:
		status = ldns_str2rdf_int16(&rdf, str);
		break;
	case LDNS_RDF_TYPE_INT32:
		status = ldns_str2rdf_int32(&rdf, str);
		break;
	case LDNS_RDF_TYPE_A:
		status = ldns_str2rdf_a(&rdf, str);
		break;
	case LDNS_RDF_TYPE_AAAA:
		status = ldns_str2rdf_aaaa(&rdf, str);
		break;
	case LDNS_RDF_TYPE_STR:
		status = ldns_str2rdf_str(&rdf, str);
		break;
	case LDNS_RDF_TYPE_APL:
		status = ldns_str2rdf_apl(&rdf, str);
		break;
	case LDNS_RDF_TYPE_B64:
		status = ldns_str2rdf_b64(&rdf, str);
		break;
	case LDNS_RDF_TYPE_HEX:
		status = ldns_str2rdf_hex(&rdf, str);
		break;
	case LDNS_RDF_TYPE_NSEC:
		status = ldns_str2rdf_nsec(&rdf, str);
		break;
	case LDNS_RDF_TYPE_TYPE:
		status = ldns_str2rdf_type(&rdf, str);
		break;
	case LDNS_RDF_TYPE_CLASS:
		status = ldns_str2rdf_class(&rdf, str);
		break;
	case LDNS_RDF_TYPE_CERT:
		status = ldns_str2rdf_cert(&rdf, str);
		break;
	case LDNS_RDF_TYPE_ALG:
		status = ldns_str2rdf_alg(&rdf, str);
		break;
	case LDNS_RDF_TYPE_UNKNOWN:
		status = ldns_str2rdf_unknown(&rdf, str);
		break;
	case LDNS_RDF_TYPE_TIME:
		status = ldns_str2rdf_time(&rdf, str);
		break;
	case LDNS_RDF_TYPE_PERIOD:
		status = ldns_str2rdf_period(&rdf, str);
		break;
	case LDNS_RDF_TYPE_TSIG:
		status = ldns_str2rdf_tsig(&rdf, str);
		break;
	case LDNS_RDF_TYPE_SERVICE:
		status = ldns_str2rdf_service(&rdf, str);
		break;
	case LDNS_RDF_TYPE_LOC:
		status = ldns_str2rdf_loc(&rdf, str);
		break;
	case LDNS_RDF_TYPE_WKS:
		status = ldns_str2rdf_wks(&rdf, str);
		break;
	case LDNS_RDF_TYPE_NSAP:
		status = ldns_str2rdf_nsap(&rdf, str);
		break;
	case LDNS_RDF_TYPE_NONE:
	default:
		/* default default ??? */
		status = LDNS_STATUS_ERR;
		break;
	}
	if (LDNS_STATUS_OK != status) {
		return NULL;
	} else {
		ldns_rdf_set_type(rdf, type);
		return rdf;
	}
}

/**
 * reverse an rdf, only actually usefull for AAAA and A records
 * the returned rdf has the type LDNS_RDF_TYPE_DNAME!
 * \param[in] *rdf rdf to be reversed
 * \return the reversed rdf (a newly created rdf)
 */
ldns_rdf *
ldns_rdf_address_reverse(ldns_rdf *rdf)
{
	uint8_t buf_4[LDNS_IP4ADDRLEN];
	uint8_t buf_6[LDNS_IP6ADDRLEN * 2];
	ldns_rdf *rev;
	ldns_rdf *in_addr;
	ldns_rdf *ret_dname;
	uint8_t octet;
	uint8_t nnibble;
	uint8_t nibble;
	uint8_t i, j;

	char *char_dname;
	int nbit;

	if (ldns_rdf_get_type(rdf) != LDNS_RDF_TYPE_A &&
			ldns_rdf_get_type(rdf) != LDNS_RDF_TYPE_AAAA) {
		return NULL;
	}

	in_addr = NULL;
	ret_dname = NULL;

	switch(ldns_rdf_get_type(rdf)) {
		case LDNS_RDF_TYPE_A:
			/* the length of the buffer is 4 */
			buf_4[3] = ldns_rdf_data(rdf)[0];
			buf_4[2] = ldns_rdf_data(rdf)[1];
			buf_4[1] = ldns_rdf_data(rdf)[2];
			buf_4[0] = ldns_rdf_data(rdf)[3];
			in_addr = ldns_dname_new_frm_str("in-addr.arpa.");
			if (!in_addr) {
				return NULL;
			}
			/* make a new rdf and convert that back  */
			rev = ldns_rdf_new_frm_data(
					LDNS_RDF_TYPE_A,
					LDNS_IP4ADDRLEN,
					(void*)&buf_4);

			/* convert rev to a string */
			char_dname = ldns_rdf2str(rev);
			if (!char_dname) {
				return NULL;
			}
			/* transform back to rdf with type dname */
			ret_dname = ldns_dname_new_frm_str(char_dname);
			if (!ret_dname) {
				return NULL;
			}
			/* not needed anymore */
			ldns_rdf_free(rev);
			FREE(char_dname);
			break;
		case LDNS_RDF_TYPE_AAAA:
			/* some foo magic to reverse the nibbles ... */

			for (nbit = 127; nbit >= 0; nbit = nbit - 4) {
				/* calculate octett (8 bit) */
				octet = ( ((unsigned int) nbit) & 0x78) >> 3;
				/* calculate nibble */
				nnibble = ( ((unsigned int) nbit) & 0x04) >> 2;
				/* extract nibble */
				nibble = (ldns_rdf_data(rdf)[octet] & ( 0xf << (4 * (1 - nnibble)) ) ) >> ( 4 * (1 - nnibble));
				buf_6[(LDNS_IP6ADDRLEN * 2 - 1) -
					(octet * 2 + nnibble)] = (uint8_t)int_to_hexdigit((int)nibble);
			}

			char_dname = XMALLOC(char, (LDNS_IP6ADDRLEN * 4));
			if (!char_dname) {
				return NULL;
			}
			char_dname[LDNS_IP6ADDRLEN * 4 - 1] = '\0'; /* closure */

			/* walk the string and add . 's */
			for (i = 0, j = 0; i < LDNS_IP6ADDRLEN * 2; i++, j = j + 2) {
				char_dname[j] = (char)buf_6[i];
				if (i != LDNS_IP6ADDRLEN * 2 - 1) {
					char_dname[j + 1] = '.';
				}
			}
			in_addr = ldns_dname_new_frm_str("ip6.arpa.");
			if (!in_addr) {
				return NULL;
			}
		
			/* convert rev to a string */
			ret_dname = ldns_dname_new_frm_str(char_dname);
			if (!ret_dname) {
				return NULL;
			}
			FREE(char_dname);
			break;
		default:
			break;
	}
	/* add the suffix */
	rev = ldns_dname_cat(ret_dname, in_addr);
	
	ldns_rdf_free(ret_dname);
	ldns_rdf_free(in_addr);
	return rev;
}


/**
 * remove \\DDD, \\[space] and other escapes from the input
 * See RFC 1035, section 5.1
 * \param[in] word what to check
 * \param[in] length the string
 * \return ldns_status mesg
 */
ldns_status
ldns_octet(char *word, size_t *length)
{
    char *s; char *p;
    *length = 0;

    for (s = p = word; *s != '\0'; s++,p++) {
        switch (*s) {
            case '.':
                if (s[1] == '.') {
                    fprintf(stderr,"Empty label");
		    return LDNS_STATUS_EMPTY_LABEL;
                }
                *p = *s;
                (*length)++;
                break;
            case '\\':
                if ('0' <= s[1] && s[1] <= '9' &&
                    '0' <= s[2] && s[2] <= '9' &&
                    '0' <= s[3] && s[3] <= '9')
                {
                    /* \DDD seen */
                    int val = ((s[1] - '0') * 100 +
                           (s[2] - '0') * 10 + (s[3] - '0'));

                    if (0 <= val && val <= 255) {
                        /* this also handles \0 */
                        s += 3;
                        *p = val;
                        (*length)++;
                    } else {
                        return LDNS_STATUS_DDD_OVERFLOW;
                    }
                } else {
                    /* an espaced character, like \<space> ? 
                    * remove the '\' keep the rest */
                    *p = *++s;
                    (*length)++;
                }
                break;
            case '\"':
                /* non quoted " Is either first or the last character in
                 * the string */

                *p = *++s; /* skip it */
                (*length)++;
		/* I'm not sure if this is needed in libdns... MG */
                if ( *s == '\0' ) {
                    /* ok, it was the last one */
                    *p  = '\0'; 
		    return LDNS_STATUS_OK;
                }
                break;
            default:
                *p = *s;
                (*length)++;
                break;
        }
    }
    *p = '\0';
    return LDNS_STATUS_OK;
}

/**
 * Compare two rdf's
 * \param[in] rd1 the first one
 * \parma[in] rd2 the second one
 * \return 0 if equal
 *         -1 if rd1 comes before rd2
 *         +1 if rd2 comes before rd1
 */
int
ldns_rdf_compare(const ldns_rdf *rd1, const ldns_rdf *rd2)
{
	uint16_t i1, i2, i;
	uint8_t *d1, *d2;
	i1 = ldns_rdf_size(rd1);
	i2 = ldns_rdf_size(rd1);

	if (i1 < i2) {
		return -1;
	} else if (i1 > i2) {
		return +1;
	} else {
		d1 = (uint8_t*)ldns_rdf_data(rd1);
		d2 = (uint8_t*)ldns_rdf_data(rd2);
		for(i = 0; i < i1; i++) {
			if (d1[i] < d2[i]) {
				return -1;
			} else if (d1[i] > d2[i]) {
				return +1;
			}
		}
	}
	return 0;
}

/**
 * convert a ttl value (5d2h) to a long
 * \param[in] nptr, the start of the string
 * \param[out] points to the last char in case of error
 * \return the convert duration value
 */
uint32_t
ldns_str2period(const char *nptr, const char **endptr)
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
					return seconds;
				}
				break;
			case '+':
				if(sign == 0) {
					sign = 1;
				} else {
					return seconds;
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
				/* disregard signedness */
				return seconds;
		}
	}
	seconds += i;
	/* disregard signedness */
	return seconds;
}

