/*
 * host2wire.c
 *
 * conversion routines from the host to the wire format.
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
#include <ldns/host2wire.h>

/* TODO 
  add a pointer to a 'possiblecompression' structure
  to all the needed functions?
  something like an array of name, pointer values?
  every dname part could be added to it
*/

/* TODO dname must still be handled as an rdf? */
ldns_status
ldns_dname2buffer_wire(ldns_buffer *buffer, ldns_rdf *name)
{
	if (ldns_buffer_reserve(buffer, ldns_rdf_size(name))) {
		ldns_buffer_write(buffer,
		                  ldns_rdf_data(name),
		                  ldns_rdf_size(name));
	}
	return ldns_buffer_status(buffer);
}

ldns_status
ldns_rdf2buffer_wire(ldns_buffer *buffer, const ldns_rdf *rdf)
{
	if (ldns_buffer_reserve(buffer, ldns_rdf_size(rdf))) {
		ldns_buffer_write(buffer,
		                  ldns_rdf_data(rdf),
		                  ldns_rdf_size(rdf));
	}
	return ldns_buffer_status(buffer);
}

/* convert a rr list to wireformat */
ldns_status
ldns_rr_list2buffer_wire(ldns_buffer *buffer, ldns_rr_list *rr_list)
{
	uint16_t rr_count;
	uint16_t i;

	rr_count = ldns_rr_list_rr_count(rr_list);
	for(i = 0; i < rr_count; i++) {
		(void)ldns_rr2buffer_wire(buffer, ldns_rr_list_rr(rr_list, i), LDNS_SECTION_ANY);
	}
	return ldns_buffer_status(buffer);
}

ldns_status
ldns_rr2buffer_wire(ldns_buffer *buffer, const ldns_rr *rr, int section)
{
	uint16_t i;
	uint16_t rdl_pos = 0;
	
	if (ldns_rr_owner(rr)) {
		(void) ldns_dname2buffer_wire(buffer, ldns_rr_owner(rr));
	}
	
	if (ldns_buffer_reserve(buffer, 4)) {
		(void) ldns_buffer_write_u16(buffer, ldns_rr_get_type(rr));
		(void) ldns_buffer_write_u16(buffer, ldns_rr_get_class(rr));
	}

	if (section != LDNS_SECTION_QUESTION) {
		if (ldns_buffer_reserve(buffer, 6)) {
			ldns_buffer_write_u32(buffer, ldns_rr_ttl(rr));
			/* remember pos for later */
			rdl_pos = ldns_buffer_position(buffer);
			ldns_buffer_write_u16(buffer, 0);
		}	

		for (i = 0; i < ldns_rr_rd_count(rr); i++) {
			(void) ldns_rdf2buffer_wire(buffer, ldns_rr_rdf(rr, i));
		}
		
		if (rdl_pos != 0) {
			ldns_buffer_write_u16_at(buffer,
			                         rdl_pos,
			                         ldns_buffer_position(buffer)
		        	                   - rdl_pos
		                	           - 2
		                	           );
		}
	}
	return ldns_buffer_status(buffer);
}

/**
 * convert a rrsig to wireformat BUT EXCLUDE the rrsig rdata
 * This is needed in DNSSEC verification
 * \param[out] *buffer buffer where to put the result
 * \param[in] *rr sigrr to operate on
 */
ldns_status
ldns_rrsig2buffer_wire(ldns_buffer *buffer, ldns_rr *rr)
{
	uint16_t i;

	/* it must be a sig RR */
	if (ldns_rr_get_type(rr) != LDNS_RR_TYPE_RRSIG) {
		return LDNS_STATUS_ERR;
	}
	
	/* Convert all the rdfs, except the actual signature data
	 * rdf number 8  - the last, hence: -1 */
	for (i = 0; i < ldns_rr_rd_count(rr) - 1; i++) {
		(void) ldns_rdf2buffer_wire(buffer, ldns_rr_rdf(rr, i));
	}

	return ldns_buffer_status(buffer);
}

/**
 * convert a rr's rdata to wireformat, while excluding
 * the ownername and all the crap before the rdata.
 * This is needed in DNSSEC keytag calculation and maybe
 * elsewhere.
 * \param[out] *buffer buffer where to put the result
 * \param[in] *rr rr to operate on
 */
ldns_status
ldns_rr_rdata2buffer_wire(ldns_buffer *buffer, ldns_rr *rr)
{
	uint16_t i;
#if 0
	if (ldns_rr_owner(rr)) {
		(void) ldns_dname2buffer_wire(buffer, ldns_rr_owner(rr));
	}
	
	if (ldns_buffer_reserve(buffer, 4)) {
		(void) ldns_buffer_write_u16(buffer, ldns_rr_get_type(rr));
		(void) ldns_buffer_write_u16(buffer, ldns_rr_get_class(rr));
	}

	if (ldns_buffer_reserve(buffer, 6)) {
		ldns_buffer_write_u32(buffer, ldns_rr_ttl(rr));
		/* remember pos for later */
		rdl_pos = ldns_buffer_position(buffer);
		ldns_buffer_write_u16(buffer, 0);
	}	
#endif

	/* convert all the rdf */
	for (i = 0; i < ldns_rr_rd_count(rr); i++) {
		(void) ldns_rdf2buffer_wire(buffer, ldns_rr_rdf(rr, i));
	}

	return ldns_buffer_status(buffer);
}

/**
 * Copy the packet header data to the buffer in wire format
 */
static ldns_status
ldns_hdr2buffer_wire(ldns_buffer *buffer, const ldns_pkt *packet)
{
	uint8_t flags;

	if (ldns_buffer_reserve(buffer, 12)) {
		ldns_buffer_write_u16(buffer, ldns_pkt_id(packet));
		
		flags = ldns_pkt_qr(packet) << 7
		        | ldns_pkt_opcode(packet) << 6
		        | ldns_pkt_aa(packet) << 2
		        | ldns_pkt_tc(packet) << 1
		        | ldns_pkt_rd(packet);
		ldns_buffer_write_u8(buffer, flags);
		
		flags = ldns_pkt_ra(packet) << 7
		        /*| ldns_pkt_z(packet) << 6*/
		        | ldns_pkt_rcode(packet);
		ldns_buffer_write_u8(buffer, flags);
		
		ldns_buffer_write_u16(buffer, ldns_pkt_qdcount(packet));
		ldns_buffer_write_u16(buffer, ldns_pkt_ancount(packet));
		ldns_buffer_write_u16(buffer, ldns_pkt_nscount(packet));
		/* add TSIG to additional if it is there */
		if (ldns_pkt_tsig(packet)) {
			ldns_buffer_write_u16(buffer, ldns_pkt_arcount(packet)+1);
		} else {
			ldns_buffer_write_u16(buffer, ldns_pkt_arcount(packet));
		}
	}
	
	return ldns_buffer_status(buffer);
}

/**
 * Copy the packet data to the buffer in wire format
 */
ldns_status
ldns_pkt2buffer_wire(ldns_buffer *buffer, const ldns_pkt *packet)
{
	ldns_rr_list *rr_list;
	uint16_t i;
	
	(void) ldns_hdr2buffer_wire(buffer, packet);

	rr_list = ldns_pkt_question(packet);
	if (rr_list) {
		for (i = 0; i < ldns_rr_list_rr_count(rr_list); i++) {
			(void) ldns_rr2buffer_wire(buffer, 
			             ldns_rr_list_rr(rr_list, i), 
			             LDNS_SECTION_QUESTION);
		}
	}
	rr_list = ldns_pkt_answer(packet);
	if (rr_list) {
		for (i = 0; i < ldns_rr_list_rr_count(rr_list); i++) {
			(void) ldns_rr2buffer_wire(buffer, 
			             ldns_rr_list_rr(rr_list, i), 
			             LDNS_SECTION_ANSWER);
		}
	}
	rr_list = ldns_pkt_authority(packet);
	if (rr_list) {
		for (i = 0; i < ldns_rr_list_rr_count(rr_list); i++) {
			(void) ldns_rr2buffer_wire(buffer, 
			             ldns_rr_list_rr(rr_list, i), 
			             LDNS_SECTION_AUTHORITY);
		}
	}
	rr_list = ldns_pkt_additional(packet);
	if (rr_list) {
		for (i = 0; i < ldns_rr_list_rr_count(rr_list); i++) {
			(void) ldns_rr2buffer_wire(buffer, 
			             ldns_rr_list_rr(rr_list, i), 
			             LDNS_SECTION_ADDITIONAL);
		}
	}

	/* add TSIG to additional if it is there */
	if (ldns_pkt_tsig(packet)) {
		(void) ldns_rr2buffer_wire(buffer,
		                           ldns_pkt_tsig(packet),
					   LDNS_SECTION_ADDITIONAL);
	}
	
	return LDNS_STATUS_OK;
}

/**
 * Allocates an array of uint8_t, and puts the wireformat of the
 * given rdf in that array. The result_size value contains the
 * length of the array, if it succeeds, and 0 otherwise (in which case
 * the function also returns NULL)
 */
uint8_t *
ldns_rdf2wire(const ldns_rdf *rdf, size_t *result_size)
{
	ldns_buffer *buffer = ldns_buffer_new(MAX_PACKETLEN);
	uint8_t *result = NULL;
	*result_size = 0;
	if (ldns_rdf2buffer_wire(buffer, rdf) == LDNS_STATUS_OK) {
		*result_size =  ldns_buffer_position(buffer);
		result = (uint8_t *) ldns_buffer_export(buffer);
	} else {
		/* TODO: what about the error? */
	}
	ldns_buffer_free(buffer);
	return result;
}

/**
 * Allocates an array of uint8_t, and puts the wireformat of the
 * given rr in that array. The result_size value contains the
 * length of the array, if it succeeds, and 0 otherwise (in which case
 * the function also returns NULL)
 *
 * If the section argument is LDNS_SECTION_QUESTION, data like ttl and rdata
 * are not put into the result
 */
uint8_t *
ldns_rr2wire(const ldns_rr *rr, int section, size_t *result_size)
{
	ldns_buffer *buffer = ldns_buffer_new(MAX_PACKETLEN);
	uint8_t *result = NULL;
	*result_size = 0;
	if (ldns_rr2buffer_wire(buffer, rr, section) == LDNS_STATUS_OK) {
		*result_size =  ldns_buffer_position(buffer);
		result = (uint8_t *) ldns_buffer_export(buffer);
	} else {
		/* TODO: what about the error? */
	}
	ldns_buffer_free(buffer);
	return result;
}

/**
 * Allocates an array of uint8_t, and puts the wireformat of the
 * given packet in that array. The result_size value contains the
 * length of the array, if it succeeds, and 0 otherwise (in which case
 * the function also returns NULL)
 */
uint8_t *
ldns_pkt2wire(const ldns_pkt *packet, size_t *result_size)
{
	ldns_buffer *buffer = ldns_buffer_new(MAX_PACKETLEN);
	uint8_t *result2 = NULL;
	uint8_t *result = NULL;
	*result_size = 0;
	if (ldns_pkt2buffer_wire(buffer, packet) == LDNS_STATUS_OK) {
		*result_size =  ldns_buffer_position(buffer);
		result = (uint8_t *) ldns_buffer_export(buffer);
	} else {
		/* TODO: what about the error? */
	}
	
	if (result) {
		result2 = XMALLOC(uint8_t, ldns_buffer_position(buffer));
		memcpy(result2, result, ldns_buffer_position(buffer));
	}
	
	ldns_buffer_free(buffer);
	return result2;
}

