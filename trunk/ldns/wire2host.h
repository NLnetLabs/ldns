#include <ldns/rdata.h>

#ifndef _LDNS_WIRE2HOST_H
#define _LDNS_WIRE2HOST_H

#include <ldns/common.h>
#include <ldns/error.h>
#include <ldns/rr.h>
#include <ldns/packet.h>

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



/**
 * Converts the data on the uint8_t bytearray (in wire format) to a DNS packet
 * The packet structure must be initialized with ldns_pkt_new().
 * 
 * @param packet pointer to the structure to hold the packet
 * @param data pointer to the buffer with the data
 * @param len the length of the data buffer (in bytes)
 * @return LDNS_STATUS_OK if everything succeeds, error otherwise
 */
ldns_status ldns_wire2pkt(ldns_pkt **packet, const uint8_t *data, size_t len);

/**
 * Converts the data on the uint8_t bytearray (in wire format) to a DNS 
 * rdata field
 * The rdf structure must be initialized with ldns_rdf_new().
 * The length of the wiredata of this rdf is added to the *pos value.
 *
 * @param dname pointer to the structure to hold the rdata value
 * @param wire pointer to the buffer with the data
 * @param max the length of the data buffer (in bytes)
 * @param pos the position of the rdf in the buffer (ie. the number of bytes 
 *            from the start of the buffer)
 * @return LDNS_STATUS_OK if everything succeeds, error otherwise
 */
ldns_status ldns_wire2dname(ldns_rdf **dname, const uint8_t *wire, size_t max, 
                       size_t *pos);

/**
 * Converts the data on the uint8_t bytearray (in wire format) to a DNS 
 * resource records
 * The rr structure must be initialized with ldns_rr_new().
 * The length of the wiredata of this rr is added to the *pos value.
 * 
 * @param rr pointer to the structure to hold the rdata value
 * @param wire pointer to the buffer with the data
 * @param max the length of the data buffer (in bytes)
 * @param pos the position of the rr in the buffer (ie. the number of bytes 
 *            from the start of the buffer)
 * @param section the section in the packet the rr is meant for
 * @return LDNS_STATUS_OK if everything succeeds, error otherwise
 */
ldns_status ldns_wire2rr(ldns_rr **rr, const uint8_t *wire, size_t max,
                    size_t *pos, ldns_pkt_section section);

#endif

