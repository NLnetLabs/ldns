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
ldns_rdf_size(ldns_rdf *rd)
{
	return rd->_size;
}

ldns_rdf_type
ldns_rdf_get_type(ldns_rdf *rd)
{
	return rd->_type;
}

uint8_t *
ldns_rdf_data(ldns_rdf *rd)
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
			return data;
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
			return data;
		default:
			return 0;
	}
	return data;
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

	data = MALLOC(struct sockaddr_storage);

	switch(ldns_rdf_get_type(rd)) {
		case LDNS_RDF_TYPE_A:
			data->ss_family = AF_INET;
			data_in = (struct sockaddr_in*) data;
			data_in->sin_port = htons(53); /* default */
			
			memcpy(&data_in->sin_addr.s_addr, ldns_rdf_data(rd), ldns_rdf_size(rd));
			return data;
		case LDNS_RDF_TYPE_AAAA:
			data->ss_family = AF_INET6;
			data_in6 = (struct sockaddr_in6*) data;
			data_in6->sin6_port = htons(53); /* default */

			memcpy(&data_in6->sin6_addr.in6_u, ldns_rdf_data(rd), ldns_rdf_size(rd));
			return data;
		default:
			FREE(data);
			printf("_aaaaa something is wrong, should not reached this\n\n");
			return NULL;
	}
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
ldns_rdf_new_frm_data(uint16_t s, ldns_rdf_type t, void *buf)
{
	ldns_rdf *rd;
	rd = MALLOC(ldns_rdf);
	if (!rd) {
		return NULL;
	}
	rd->_data = XMALLOC(uint8_t, s);
	if (!rd->_data) {
		return NULL;
	}
	
	ldns_rdf_set_size(rd, s);
	ldns_rdf_set_type(rd, t);
	memcpy(rd->_data, buf, s);
	return rd;
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
	FREE(rd);
}

/**
 * Create a new rdf from a string
 * \param[in] str string to use
 * \param[in] t   type to use
 * \return ldns_rdf*
 */
ldns_rdf *
ldns_rdf_new_frm_str(const char *str, ldns_rdf_type t)
{
	ldns_rdf *rd;
	ldns_status stat;
	
	switch(t) {
        	case LDNS_RDF_TYPE_NONE:
			break;
	        case LDNS_RDF_TYPE_DNAME:
			stat = ldns_str2rdf_dname(&rd, (const uint8_t*) str);
			break;
        	case LDNS_RDF_TYPE_INT8:
			stat = ldns_str2rdf_int8(&rd, (const uint8_t*) str);
			break;
        	case LDNS_RDF_TYPE_INT16:
			stat = ldns_str2rdf_int16(&rd, (const uint8_t*) str);
			break;
		case LDNS_RDF_TYPE_INT32:
			stat = ldns_str2rdf_int32(&rd, (const uint8_t*) str);
			break;
		case LDNS_RDF_TYPE_A:
			stat = ldns_str2rdf_a(&rd, (const uint8_t*) str);
			break;
        	case LDNS_RDF_TYPE_AAAA:
			stat = ldns_str2rdf_aaaa(&rd, (const uint8_t*) str);
			break;
        	case LDNS_RDF_TYPE_STR:
			stat = ldns_str2rdf_str(&rd, (const uint8_t*) str);
			break;
        	case LDNS_RDF_TYPE_APL:
			stat = ldns_str2rdf_apl(&rd, (const uint8_t*) str);
			break;
        	case LDNS_RDF_TYPE_B64:
			stat = ldns_str2rdf_b64(&rd, (const uint8_t*) str);
			break;
        	case LDNS_RDF_TYPE_HEX:
			stat = ldns_str2rdf_hex(&rd, (const uint8_t*) str);
			break;
        	case LDNS_RDF_TYPE_NSEC:
			stat = ldns_str2rdf_nsec(&rd, (const uint8_t*) str);
			break;
        	case LDNS_RDF_TYPE_TYPE:
			stat = ldns_str2rdf_type(&rd, (const uint8_t*) str);
			break;
        	case LDNS_RDF_TYPE_CLASS:
			stat = ldns_str2rdf_class(&rd, (const uint8_t*) str);
			break;
        	case LDNS_RDF_TYPE_CERT:
			stat = ldns_str2rdf_cert(&rd, (const uint8_t*) str);
			break;
        	case LDNS_RDF_TYPE_ALG:
			stat = ldns_str2rdf_alg(&rd, (const uint8_t*) str);
			break;
        	case LDNS_RDF_TYPE_UNKNOWN:
			stat = ldns_str2rdf_unknown(&rd, (const uint8_t*) str);
			break;
        	case LDNS_RDF_TYPE_TIME:
			stat = ldns_str2rdf_time(&rd, (const uint8_t*) str);
			break;
        	case LDNS_RDF_TYPE_TSIGTIME:
			stat = ldns_str2rdf_tsigtime(&rd, (const uint8_t*) str);
			break;
       		case LDNS_RDF_TYPE_SERVICE:
			stat = ldns_str2rdf_service(&rd, (const uint8_t*) str);
			break;
        	case LDNS_RDF_TYPE_LOC:
			stat = ldns_str2rdf_loc(&rd, (const uint8_t*) str);
			break;
        	case LDNS_RDF_TYPE_WKS:
			stat = ldns_str2rdf_wks(&rd, (const uint8_t*) str);
			break;
       	 	case LDNS_RDF_TYPE_NSAP:
			stat = ldns_str2rdf_nsap(&rd, (const uint8_t*) str);
			break;
		default:
			/* default default ??? */
			break;
	}
	if (LDNS_STATUS_OK != stat) {
		return NULL;
	} else {
		ldns_rdf_set_type(rd, t);
		return rd;
	}
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
                *length++;
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
                        *length++;
                    } else {
                        return LDNS_STATUS_DDD_OVERFLOW;
                    }
                } else {
                    /* an espaced character, like \<space> ? 
                    * remove the '\' keep the rest */
                    *p = *++s;
                    *length++;
                }
                break;
            case '\"':
                /* non quoted " Is either first or the last character in
                 * the string */

                *p = *++s; /* skip it */
                *length++;
		/* I'm not sure if this is needed in libdns... MG */
                if ( *s == '\0' ) {
                    /* ok, it was the last one */
                    *p  = '\0'; 
		    return LDNS_STATUS_OK;
                }
                break;
            default:
                *p = *s;
                *length++;
                break;
        }
    }
    *p = '\0';
    return LDNS_STATUS_OK;
}
