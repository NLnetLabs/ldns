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
#define	QHEADERSZ	12

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


/**
 * transform a wireformatted rdata to our
 * internal representation. We need to the
 * length, and the type and put the data in
 */
/*
ssize_t
rdata_buf_to_rdf(ldns_rdf *rd, ldns_rdf *buffer)
{
	switch(RDATA_TYPESS) {
		case RDF_TYPE_NONE:
			break;
		case RDF_TYPE_DNAME:
			break;
		case RDF_TYPE_INT8:
			break;
		case RDF_TYPE_INT16:
			break;
		case RDF_TYPE_INT32:
			break;
		case RDF_TYPE_INT48:
			break;
		case RDF_TYPE_A:     
			break;
		case RDF_TYPE_AAAA:
			break;
		case RDF_TYPE_STR:
			break;
		case RDF_TYPE_APL:
			break;
		case RDF_TYPE_B64:
			break;
		case RDF_TYPE_HEX:
			break;
		case RDF_TYPE_NSEC: 
			break;
		case RDF_TYPE_TYPE: 
			break;
		case RDF_TYPE_CLASS:
			break;
		case RDF_TYPE_CERT:
			break;
		case RDF_TYPE_ALG:
			break;
		case RDF_TYPE_UNKNOWN:
			break;
		case RDF_TYPE_TIME:
			break;
		case RDF_TYPE_SERVICE:
			break;
		case RDF_TYPE_LOC:
			break;
	}	

}
*/

/* TODO: general rdata2str or dname2str, with error
         checks and return status etc */
/* this is temp function for debugging wire2rr */
/* do NOT pass compressed data here :p */
void
ldns_dname2str(char *dest, ldns_rdf *dname)
{
	/* can we do with 1 pos var? or without at all? */
	uint8_t src_pos = 0;
	uint8_t dest_pos = 0;
	uint8_t len;
	len = dname->_data[src_pos];
	while (len > 0) {
		src_pos++;
		memcpy(&dest[dest_pos], &(dname->_data[src_pos]), len);
		dest_pos += len;
		src_pos += len;
		len = dname->_data[src_pos];
		dest[dest_pos] = '.';
		dest_pos++;
	}
	dest[dest_pos] = '\0';
}

/* TODO: is there a better place for this function?
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

	if (*pos > max) {
		/* TODO set error */
		return LDNS_STATUS_PACKET_OVERFLOW;
	}
	
	label_size = wire[*pos];
	while (label_size > 0) {
		/* compression */
		if (label_size >= 192) {
			if (compression_pos == 0) {
				compression_pos = *pos + 2;
			}

			/* remove first two bits */
			/* TODO: can this be done in a better way? */
			pointer_target_buf[0] = wire[*pos] & 63;
			pointer_target_buf[1] = wire[*pos + 1];
			pointer_target = read_uint16(pointer_target_buf);

			if (pointer_target == 0) {
				fprintf(stderr, "POINTER TO 0\n");
				return LDNS_STATUS_INVALID_POINTER;
			} else if (pointer_target > max) {
				fprintf(stderr, "POINTER TO OUTSIDE PACKET\n");
				return LDNS_STATUS_INVALID_POINTER;
			}
			*pos = pointer_target;
			label_size = wire[*pos];
		}
		
		if (label_size > MAXLABELLEN) {
			/* TODO error: label size too large */
			fprintf(stderr, "LABEL SIZE ERROR: %d\n",
			        (int) label_size);
			return LDNS_STATUS_LABEL_OVERFLOW;
		}
		if (*pos + label_size > max) {
			/* TODO error: out of packet data */
			fprintf(stderr, "MAX PACKET ERROR: %d\n",
			        (int) (*pos + label_size));
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

	*dname = MALLOC(ldns_rdf);
	(*dname)->_type = LDNS_RDF_TYPE_DNAME;
	(*dname)->_size = (uint16_t) dname_pos;
	(*dname)->_data = XMALLOC(uint8_t, dname_pos + 1);
	memcpy((*dname)->_data, tmp_dname, dname_pos);
	
	return LDNS_STATUS_OK;
}

/* maybe make this a goto error so data can be freed or something/ */
#define STATUS_CHECK_RETURN(st) {if (st != LDNS_STATUS_OK) { return st; }}

/* TODO: ldns_status_type and error checking 
         defines for constants?
         enum for sections? 
         remove owner print debug message
         can *pos be incremented at READ_INT? or maybe use something like
         RR_CLASS(wire)?
*/
ldns_status
ldns_wire2rr(ldns_rr *rr, const uint8_t *wire, size_t max, 
             size_t *pos, int section)
{
	ldns_rdf *owner;
	char *owner_str = XMALLOC(char, MAXDOMAINLEN);
	uint16_t rd_length;
	ldns_status status = LDNS_STATUS_OK;
	
	status = ldns_wire2dname(&owner, wire, max, pos);
/*	
	ldns_rr_set_owner(rr, owner);
*/
	ldns_dname2str(owner_str, owner);
	printf("owner: %s\n", owner_str);
	FREE(owner_str);	
	
	ldns_rr_set_class(rr, read_uint16(&wire[*pos]));
	*pos = *pos + 2;
	/*
	ldns_rr_set_type(rr, read_uint16(&wire[*pos]));
	*/
	*pos = *pos + 2;

	if (section > 0) {
		ldns_rr_set_ttl(rr, read_uint32(&wire[*pos]));	
		*pos = *pos + 4;
		rd_length = read_uint16(&wire[*pos]);
		*pos = *pos + 2;
		/* TODO: wire2rdata */
		*pos = *pos + rd_length;
	}

	return status;
}

static ldns_status
ldns_wire2pkt_hdr(ldns_pkt *packet,
			const uint8_t *wire,
			size_t max,
			size_t *pos)
{
	if (*pos + QHEADERSZ >= max) {
		/* TODO: set t_status error.  */
		return LDNS_STATUS_PACKET_OVERFLOW;
	} else {

		pkt_set_id(packet, ID(wire));
		pkt_set_qr(packet, QR(wire));
		pkt_set_opcode(packet, OPCODE(wire));
		pkt_set_aa(packet, AA(wire));
		pkt_set_tc(packet, TC(wire));
		pkt_set_rd(packet, RD(wire));
		pkt_set_ra(packet, RA(wire));
		pkt_set_ad(packet, AD(wire));
		pkt_set_cd(packet, CD(wire));
		pkt_set_rcode(packet, RCODE(wire));	 

		pkt_set_qdcount(packet, QDCOUNT(wire));
		pkt_set_ancount(packet, ANCOUNT(wire));
		pkt_set_nscount(packet, NSCOUNT(wire));
		pkt_set_arcount(packet, ARCOUNT(wire));

		*pos += QHEADERSZ;
		/* TODO t_status succ.  */
		return LDNS_STATUS_OK;
	}
}

/* TODO: error check, return status (of this and of wire2rrs) */
ldns_status
ldns_wire2pkt(ldns_pkt *packet, const uint8_t *wire, size_t max)
{
	size_t pos = 0;
	uint16_t i;
	ldns_rr *rr;
	ldns_status status = LDNS_STATUS_OK;
	
	status = ldns_wire2pkt_hdr(packet, wire, max, &pos);
	STATUS_CHECK_RETURN(status);
	
	/* TODO: section enum :) */
	for (i = 0; i < pkt_qdcount(packet); i++) {
		rr = ldns_rr_new();
		status = ldns_wire2rr(rr, wire, max, &pos, 0);
		STATUS_CHECK_RETURN(status);
	}
	for (i = 0; i < pkt_ancount(packet); i++) {
		rr = ldns_rr_new();
		status = ldns_wire2rr(rr, wire, max, &pos, 1);

		STATUS_CHECK_RETURN(status);
	}
	for (i = 0; i < pkt_nscount(packet); i++) {
		rr = ldns_rr_new();
		status = ldns_wire2rr(rr, wire, max, &pos, 2);
		STATUS_CHECK_RETURN(status);
	}
	for (i = 0; i < pkt_arcount(packet); i++) {
		rr = ldns_rr_new();
		status = ldns_wire2rr(rr, wire, max, &pos, 3);
		STATUS_CHECK_RETURN(status);
	}

	return status;
}

