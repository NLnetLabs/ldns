/*
 * host2wire.c
 *
 * conversion routines from the host to the wire format.
 * This will usually just a re-ordering of the
 * data (as we store it in network format)
 *
 * XXX not sure if we need to keep this around
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
ldns_rdf2buffer_wire(ldns_buffer *buffer, ldns_rdf *rdf)
{
	if (ldns_buffer_reserve(buffer, ldns_rdf_size(rdf))) {
		ldns_buffer_write(buffer,
		                  ldns_rdf_data(rdf),
		                  ldns_rdf_size(rdf));
	}
	return ldns_buffer_status(buffer);
}

ldns_status
ldns_rr2buffer_wire(ldns_buffer *buffer, ldns_rr *rr, int section)
{
	uint16_t i;
	uint16_t rdl_pos = 0;
	
	if (ldns_rr_owner(rr)) {
		ldns_dname2buffer_wire(buffer, ldns_rr_owner(rr));
	}
	
	if (ldns_buffer_reserve(buffer, 4)) {
		ldns_buffer_write_u16(buffer, ldns_rr_get_type(rr));
		ldns_buffer_write_u16(buffer, ldns_rr_get_class(rr));
	}

	if (section != LDNS_SECTION_QUESTION) {
		if (ldns_buffer_reserve(buffer, 6)) {
			ldns_buffer_write_u32(buffer, ldns_rr_ttl(rr));
			/* remember pos for later */
			rdl_pos = ldns_buffer_position(buffer);
			ldns_buffer_write_u16(buffer, 0);
		}	

		for (i = 0; i < ldns_rr_rd_count(rr); i++) {
			ldns_rdf2buffer_wire(buffer, ldns_rr_rdf(rr, i));
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
 * Copy the packet header data to the buffer in wire format
 */
ldns_status
ldns_hdr2buffer_wire(ldns_buffer *buffer, ldns_pkt *packet)
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
		ldns_buffer_write_u16(buffer, ldns_pkt_arcount(packet));
	}
	
	return ldns_buffer_status(buffer);
}

/**
 * Copy the packet data to the buffer in wire format
 */
ldns_status
ldns_pkt2buffer_wire(ldns_buffer *buffer, ldns_pkt *packet)
{
	ldns_rr_list *rr_list;
	uint16_t i;
	
	ldns_hdr2buffer_wire(buffer, packet);

	rr_list = ldns_pkt_question(packet);
	if (rr_list) {
		for (i = 0; i < ldns_rr_list_rr_count(rr_list); i++) {
			ldns_rr2buffer_wire(buffer, 
			             ldns_rr_list_rr(rr_list, i), 
			             LDNS_SECTION_QUESTION);
		}
	}
	rr_list = ldns_pkt_answer(packet);
	if (rr_list) {
		for (i = 0; i < ldns_rr_list_rr_count(rr_list); i++) {
			ldns_rr2buffer_wire(buffer, 
			             ldns_rr_list_rr(rr_list, i), 
			             LDNS_SECTION_ANSWER);
		}
	}
	rr_list = ldns_pkt_authority(packet);
	if (rr_list) {
		for (i = 0; i < ldns_rr_list_rr_count(rr_list); i++) {
			ldns_rr2buffer_wire(buffer, 
			             ldns_rr_list_rr(rr_list, i), 
			             LDNS_SECTION_AUTHORITY);
		}
	}
	rr_list = ldns_pkt_additional(packet);
	if (rr_list) {
		for (i = 0; i < ldns_rr_list_rr_count(rr_list); i++) {
			ldns_rr2buffer_wire(buffer, 
			             ldns_rr_list_rr(rr_list, i), 
			             LDNS_SECTION_ADDITIONAL);
		}
	}
	
	return LDNS_STATUS_OK;
}


