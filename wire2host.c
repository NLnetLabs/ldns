/*
 * wire2host.c
 *
 * conversion routines from the wire to the host
 * format.
 * This will usually just a re-ordering of the
 * data (as we store it in network format)
 *
 * a Net::DNS like library for C
 *
 * (c) NLnet Labs, 2004
 *
 * See the file LICENSE for the license
 */
#include <config.h>

#include <limits.h>

#include <ldns/wire2host.h>

#include "util.h"


/*
 * Set of macro's to deal with the dns message header as specified
 * in RFC1035 in portable way.
 *
 */

/*
 *
 *                                    1  1  1  1  1  1
 *      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                      ID                       |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                    QDCOUNT                    |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                    ANCOUNT                    |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                    NSCOUNT                    |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                    ARCOUNT                    |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 */

/* The length of the header */
#define	HEADER_SIZE	12

/* First octet of flags */
#define	RD_MASK		0x01U
#define	RD_SHIFT	0
#define	RD(wirebuf)	(*(wirebuf+2) & RD_MASK)
#define	RD_SET(wirebuf)	(*(wirebuf+2) |= RD_MASK)
#define	RD_CLR(wirebuf)	(*(wirebuf+2) &= ~RD_MASK)

#define TC_MASK		0x02U
#define TC_SHIFT	1
#define	TC(wirebuf)	(*(wirebuf+2) & TC_MASK)
#define	TC_SET(wirebuf)	(*(wirebuf+2) |= TC_MASK)
#define	TC_CLR(wirebuf)	(*(wirebuf+2) &= ~TC_MASK)

#define	AA_MASK		0x04U
#define	AA_SHIFT	2
#define	AA(wirebuf)	(*(wirebuf+2) & AA_MASK)
#define	AA_SET(wirebuf)	(*(wirebuf+2) |= AA_MASK)
#define	AA_CLR(wirebuf)	(*(wirebuf+2) &= ~AA_MASK)

#define	OPCODE_MASK	0x78U
#define	OPCODE_SHIFT	3
#define	OPCODE(wirebuf)	((*(wirebuf+2) & OPCODE_MASK) >> OPCODE_SHIFT)
#define	OPCODE_SET(wirebuf, opcode) \
	(*(wirebuf+2) = ((*(wirebuf+2)) & ~OPCODE_MASK) | ((opcode) << OPCODE_SHIFT))

#define	QR_MASK		0x80U
#define	QR_SHIFT	7
#define	QR(wirebuf)	(*(wirebuf+2) & QR_MASK)
#define	QR_SET(wirebuf)	(*(wirebuf+2) |= QR_MASK)
#define	QR_CLR(wirebuf)	(*(wirebuf+2) &= ~QR_MASK)

/* Second octet of flags */
#define	RCODE_MASK	0x0fU
#define	RCODE_SHIFT	0
#define	RCODE(wirebuf)	(*(wirebuf+3) & RCODE_MASK)
#define	RCODE_SET(wirebuf, rcode) \
	(*(wirebuf+3) = ((*(wirebuf+3)) & ~RCODE_MASK) | (rcode))

#define	CD_MASK		0x10U
#define	CD_SHIFT	4
#define	CD(wirebuf)	(*(wirebuf+3) & CD_MASK)
#define	CD_SET(wirebuf)	(*(wirebuf+3) |= CD_MASK)
#define	CD_CLR(wirebuf)	(*(wirebuf+3) &= ~CD_MASK)

#define	AD_MASK		0x20U
#define	AD_SHIFT	5
#define	AD(wirebuf)	(*(wirebuf+3) & AD_MASK)
#define	AD_SET(wirebuf)	(*(wirebuf+3) |= AD_MASK)
#define	AD_CLR(wirebuf)	(*(wirebuf+3) &= ~AD_MASK)

#define	Z_MASK		0x40U
#define	Z_SHIFT		6
#define	Z(wirebuf)	(*(wirebuf+3) & Z_MASK)
#define	Z_SET(wirebuf)	(*(wirebuf+3) |= Z_MASK)
#define	Z_CLR(wirebuf)	(*(wirebuf+3) &= ~Z_MASK)

#define	RA_MASK		0x80U
#define	RA_SHIFT	7
#define	RA(wirebuf)	(*(wirebuf+3) & RA_MASK)
#define	RA_SET(wirebuf)	(*(wirebuf+3) |= RA_MASK)
#define	RA_CLR(wirebuf)	(*(wirebuf+3) &= ~RA_MASK)

/* Query ID */
#define	ID(wirebuf)			(read_uint16(wirebuf))

/* Counter of the question section */
#define QDCOUNT_OFF		4
/*
#define	QDCOUNT(wirebuf)		(ntohs(*(uint16_t *)(wirebuf+QDCOUNT_OFF)))
*/
#define	QDCOUNT(wirebuf)		(read_uint16(wirebuf+QDCOUNT_OFF))

/* Counter of the answer section */
#define ANCOUNT_OFF		6
#define	ANCOUNT(wirebuf)		(read_uint16(wirebuf+ANCOUNT_OFF))

/* Counter of the authority section */
#define NSCOUNT_OFF		8
#define	NSCOUNT(wirebuf)		(read_uint16(wirebuf+NSCOUNT_OFF))

/* Counter of the additional section */
#define ARCOUNT_OFF		10
#define	ARCOUNT(wirebuf)		(read_uint16(wirebuf+ARCOUNT_OFF))


/* TODO:
         status_type return and remove printfs
         #defines */
/* allocates memory to *dname! */
ldns_status
ldns_wire2dname(ldns_rdf **dname, const uint8_t *wire, size_t max, size_t *pos)
{
	uint8_t label_size;
	uint16_t pointer_target;
	uint8_t pointer_target_buf[2];
	size_t dname_pos = 0;
	size_t uncompressed_length = 0;
	size_t compression_pos = 0;
	uint8_t tmp_dname[MAXDOMAINLEN];
	uint8_t *dname_ar;
	unsigned int pointer_count = 0;
	
	if (*pos > max) {
		return LDNS_STATUS_PACKET_OVERFLOW;
	}
	
	label_size = wire[*pos];
	while (label_size > 0) {
		/* compression */
		if (label_size >= 192) {
			if (compression_pos == 0) {
				compression_pos = *pos + 2;
			}
			
			pointer_count++;
			
			/* remove first two bits */
			pointer_target_buf[0] = wire[*pos] & 63;
			pointer_target_buf[1] = wire[*pos + 1];
			pointer_target = read_uint16(pointer_target_buf);

			if (pointer_target == 0) {
				return LDNS_STATUS_INVALID_POINTER;
			} else if (pointer_target > max) {
				return LDNS_STATUS_INVALID_POINTER;
			} else if (pointer_count > MAXPOINTERS) {
				return LDNS_STATUS_INVALID_POINTER;
			}
			*pos = pointer_target;
			label_size = wire[*pos];
		}
		if (label_size > MAXLABELLEN) {
			return LDNS_STATUS_LABEL_OVERFLOW;
		}
		if (*pos + label_size > max) {
			return LDNS_STATUS_LABEL_OVERFLOW;
		}
		
		tmp_dname[dname_pos] = label_size;
		dname_pos++;
		*pos = *pos + 1;
		memcpy(&tmp_dname[dname_pos], &wire[*pos], label_size);
		uncompressed_length += label_size + 1;
		dname_pos += label_size;
		*pos = *pos + label_size;
		label_size = wire[*pos];
	}

	if (compression_pos > 0) {
		*pos = compression_pos;
	} else {
		*pos = *pos + 1;
	}

	tmp_dname[dname_pos] = 0;
	dname_pos++;
	
	dname_ar = XMALLOC(uint8_t, dname_pos);
	if (!dname_ar) {
		return LDNS_STATUS_MEM_ERR;
	}
	memcpy(dname_ar, tmp_dname, dname_pos);
	
	*dname = ldns_rdf_new((uint16_t) dname_pos, LDNS_RDF_TYPE_DNAME,
	                      dname_ar);
	if (!*dname) {
		FREE(dname_ar);
		return LDNS_STATUS_MEM_ERR;
	}
	
	return LDNS_STATUS_OK;
}

/* maybe make this a goto error so data can be freed or something/ */
#define STATUS_CHECK_RETURN(st) {if (st != LDNS_STATUS_OK) { printf("STR %d\n", __LINE__); return st; }}
#define STATUS_CHECK_GOTO(st, label) {if (st != LDNS_STATUS_OK) { printf("STG %s:%d: status code %d\n", __FILE__, __LINE__, st);  goto label; }}

/* TODO -doc,
 	-free on error
*/
ldns_status
ldns_wire2rdf(ldns_rr *rr, const uint8_t *wire,
              size_t max, size_t *pos)
{
	ldns_rdf *cur_rdf;
	ldns_rdf_type cur_rdf_type;
	size_t cur_rdf_length;
	uint8_t *data;
	uint16_t rd_length;
	size_t end;
	uint8_t rdf_index;
	const ldns_rr_descriptor *descriptor = 
	        ldns_rr_descript(ldns_rr_get_type(rr));
	ldns_status status;
	
	if (*pos > max) {
		return LDNS_STATUS_PACKET_OVERFLOW;
	}

	rd_length = read_uint16(&wire[*pos]);
	*pos = *pos + 2;

	if (*pos + rd_length > max) {
		return LDNS_STATUS_PACKET_OVERFLOW;
	}
	
	end = *pos + (size_t) rd_length;


	for (rdf_index = 0; 
	     rdf_index < ldns_rr_descriptor_maximum(descriptor);
	     rdf_index++) {
		if (*pos >= end) {
	     		break;
		}
		cur_rdf_length = 0;

		cur_rdf_type = ldns_rr_descriptor_field_type(descriptor,
		                                             rdf_index);
		/* handle special cases immediately, set length
		   for fixed length rdata and do them below */
		   /* TODO: constants */
		switch (cur_rdf_type) {
		case LDNS_RDF_TYPE_DNAME:
			status = ldns_wire2dname(&cur_rdf, wire, max,
						 pos);
			STATUS_CHECK_RETURN(status);
			break;
		case LDNS_RDF_TYPE_CLASS:
		case LDNS_RDF_TYPE_ALG:
		case LDNS_RDF_TYPE_INT8:
			cur_rdf_length = 1;
			break;
		case LDNS_RDF_TYPE_TYPE:
		case LDNS_RDF_TYPE_INT16:
		case LDNS_RDF_TYPE_CERT:
			cur_rdf_length = 2;
			break;
		case LDNS_RDF_TYPE_TIME:
		case LDNS_RDF_TYPE_INT32:
			cur_rdf_length = 4;
			break;
		case LDNS_RDF_TYPE_INT48:
			cur_rdf_length = 6;
			break;
		case LDNS_RDF_TYPE_A:
			cur_rdf_length = 4;
			break;
		case LDNS_RDF_TYPE_AAAA:
			cur_rdf_length = 32;
			break;
		case LDNS_RDF_TYPE_STR:
			/* len is stored in first byte */
			cur_rdf_length = (size_t) wire[*pos];
			*pos = *pos + 1;
			break;
		case LDNS_RDF_TYPE_APL:
			/* TODO */
		case LDNS_RDF_TYPE_B64:
		case LDNS_RDF_TYPE_HEX:
		case LDNS_RDF_TYPE_NSEC:
		case LDNS_RDF_TYPE_UNKNOWN:
		case LDNS_RDF_TYPE_SERVICE:
		case LDNS_RDF_TYPE_LOC:
		case LDNS_RDF_TYPE_NONE:
			cur_rdf_length = (size_t) rd_length;
			break;
		}
		/* fixed length rdata */
		if (cur_rdf_length > 0) {
			data = XMALLOC(uint8_t, rd_length);
			if (!data) {
				return LDNS_STATUS_MEM_ERR;
			}
			memcpy(data, &wire[*pos], cur_rdf_length);
			
			cur_rdf = ldns_rdf_new(cur_rdf_length,
			                       cur_rdf_type,
			                       data);
			*pos = *pos + cur_rdf_length;
		}	

		ldns_rr_push_rdf(rr, cur_rdf);
	}
	return LDNS_STATUS_OK;
}


/* TODO:
         can *pos be incremented at READ_INT? or maybe use something like
         RR_CLASS(wire)?
*/
ldns_status
ldns_wire2rr(ldns_rr **rr_p, const uint8_t *wire, size_t max, 
             size_t *pos, ldns_pkt_section section)
{
	ldns_rdf *owner;
	ldns_rr *rr = ldns_rr_new();
	ldns_status status;
	
	status = ldns_wire2dname(&owner, wire, max, pos);
	STATUS_CHECK_GOTO(status, status_error);

	ldns_rr_set_owner(rr, owner);
	
	ldns_rr_set_type(rr, read_uint16(&wire[*pos]));
	*pos = *pos + 2;

	ldns_rr_set_class(rr, read_uint16(&wire[*pos]));
	*pos = *pos + 2;

	if (section != LDNS_SECTION_QUESTION) {
		ldns_rr_set_ttl(rr, read_uint32(&wire[*pos]));	
		*pos = *pos + 4;
		status = ldns_wire2rdf(rr, wire, max, pos);
		STATUS_CHECK_GOTO(status, status_error);
	}

	*rr_p = rr;
	return LDNS_STATUS_OK;
	
	status_error:
	FREE(rr);
	return status;
}

static ldns_status
ldns_wire2pkt_hdr(ldns_pkt *packet,
			const uint8_t *wire,
			size_t max,
			size_t *pos)
{
	if (*pos + HEADER_SIZE > max) {
		return LDNS_STATUS_PACKET_OVERFLOW;
	} else {
		ldns_pkt_set_id(packet, ID(wire));
		ldns_pkt_set_qr(packet, QR(wire));
		ldns_pkt_set_opcode(packet, OPCODE(wire));
		ldns_pkt_set_aa(packet, AA(wire));
		ldns_pkt_set_tc(packet, TC(wire));
		ldns_pkt_set_rd(packet, RD(wire));
		ldns_pkt_set_ra(packet, RA(wire));
		ldns_pkt_set_ad(packet, AD(wire));
		ldns_pkt_set_cd(packet, CD(wire));
		ldns_pkt_set_rcode(packet, RCODE(wire));	 

		ldns_pkt_set_qdcount(packet, QDCOUNT(wire));
		ldns_pkt_set_ancount(packet, ANCOUNT(wire));
		ldns_pkt_set_nscount(packet, NSCOUNT(wire));
		ldns_pkt_set_arcount(packet, ARCOUNT(wire));

		*pos += HEADER_SIZE;

		return LDNS_STATUS_OK;
	}
}


ldns_status
ldns_wire2pkt(ldns_pkt **packet_p, const uint8_t *wire, size_t max)
{
	size_t pos = 0;
	uint16_t i;
	ldns_rr *rr;
	ldns_pkt *packet = ldns_pkt_new();
	ldns_status status = LDNS_STATUS_OK;
	
	status = ldns_wire2pkt_hdr(packet, wire, max, &pos);
	STATUS_CHECK_GOTO(status, status_error);
	
	for (i = 0; i < ldns_pkt_qdcount(packet); i++) {
		status = ldns_wire2rr(&rr, wire, max, &pos,
		                      LDNS_SECTION_QUESTION);
		if (!ldns_rr_list_push_rr(ldns_pkt_question(packet), rr)) {
			return LDNS_STATUS_INTERNAL_ERR;
		}
		STATUS_CHECK_GOTO(status, status_error);
	}
	for (i = 0; i < ldns_pkt_ancount(packet); i++) {
		status = ldns_wire2rr(&rr, wire, max, &pos,
		                      LDNS_SECTION_ANSWER);
		if (!ldns_rr_list_push_rr(ldns_pkt_answer(packet), rr)) {
			return LDNS_STATUS_INTERNAL_ERR;
		}
		STATUS_CHECK_GOTO(status, status_error);
	}
	for (i = 0; i < ldns_pkt_nscount(packet); i++) {
		status = ldns_wire2rr(&rr, wire, max, &pos,
		                      LDNS_SECTION_AUTHORITY);
		if (!ldns_rr_list_push_rr(ldns_pkt_authority(packet), rr)) {
			return LDNS_STATUS_INTERNAL_ERR;
		}
		STATUS_CHECK_GOTO(status, status_error);
	}
	for (i = 0; i < ldns_pkt_arcount(packet); i++) {
		status = ldns_wire2rr(&rr, wire, max, &pos,
		                      LDNS_SECTION_ADDITIONAL);
		if (!ldns_rr_list_push_rr(ldns_pkt_additional(packet), rr)) {
			return LDNS_STATUS_INTERNAL_ERR;
		}
		STATUS_CHECK_GOTO(status, status_error);
	}

	*packet_p = packet;
	return status;
	
	status_error:
	FREE(packet);
	return status;
}
