/*
 * host2wire.c
 *
 * conversion routines from the host to the wire format.
 * This will usually just a re-ordering of the
 * data (as we store it in network format)
 *
 * a Net::DNS like library for C
 *
 * (c) NLnet Labs, 2004-2006
 *
 * See the file LICENSE for the license
 */

#include <ldns/config.h>

#include <ldns/ldns.h>

ldns_status
ldns_dname2buffer_wire(ldns_buffer *buffer, const ldns_rdf *name)
{
	return ldns_dname2buffer_wire_compress(buffer, name, NULL);
}

ldns_status
ldns_dname2buffer_wire_compress(ldns_buffer *buffer, const ldns_rdf *name, ldns_llnode_t *compression_data)
{
	ldns_llnode_t *node_ref, *node = compression_data;
	size_t len, som = 0; /* size of match from the end */

	/* If no tree, just add the data */
	if(!compression_data)
	{
		if (ldns_buffer_reserve(buffer, ldns_rdf_size(name)))
		{
			ldns_buffer_write(buffer, ldns_rdf_data(name), ldns_rdf_size(name));
		}
		return ldns_buffer_status(buffer);
	}

	/* Not sure if "owner" below is guaranteed of TYPE_DNAME */
	if (ldns_rdf_get_type(name) != LDNS_RDF_TYPE_DNAME) return LDNS_STATUS_INVALID_RDF_TYPE;

	if (ldns_rdf_size(name) > 256) return LDNS_STATUS_DOMAINNAME_OVERFLOW;

	for (ldns_llnode_t *n; (n = node->next) != NULL; node = n)
	{
		char  *lp1, *lp2, *lps;

		if (node->som != som) continue; /* som is a stitching point */

		/* for an early dname we first scan backward from the som point */
		lp1 = lps = node->dname + node->dsize - som;

		lp2 = (char*) ldns_rdf_data(name) + ldns_rdf_size(name) - som;

		while (node->dname <= --lp1 && (char*) ldns_rdf_data(name) <= --lp2)
		{
			if (LDNS_DNAME_NORMALIZE((int) *lp1)  !=
			    LDNS_DNAME_NORMALIZE((int) *lp2)) break;
		}
		lp1++;

		/* secondly, we parse early dname forward to get label boundary right */
		for (lp2 = node->dname; lp2 < lp1; ) lp2 += *(uint8_t*) lp2 + 1;

		if (lps - lp2 > 1) /* growing som: update */
		{
			som += lps - lp2;
			node_ref = node;
		}
	}
	/* populate the node, and the buffer */
	node->som = som;
	node->dsize = ldns_rdf_size(name);
	node->buffer_start = ldns_buffer_position(buffer);
	memcpy(node->dname, ldns_rdf_data(name), ldns_rdf_size(name));

	if ( (node->next = LDNS_CALLOC(ldns_llnode_t, 1)) == NULL) return LDNS_STATUS_MEM_ERR;

	len = ldns_rdf_size(name) - som;
	if (ldns_buffer_reserve(buffer, len))
	{
		/* if som = 0 => final 0 is included */
		ldns_buffer_write(buffer, ldns_rdf_data(name), len);
	}
	if (som)
	{
		uint16_t position = (uint16_t) (node_ref->buffer_start + 
		                                node_ref->dsize - som) | 0xC000;
		if (ldns_buffer_reserve(buffer, 2))
		{
			ldns_buffer_write_u16(buffer, position);
		}
	}
	return ldns_buffer_status(buffer);
}

ldns_status
ldns_rdf2buffer_wire(ldns_buffer *buffer, const ldns_rdf *rdf)
{
	return ldns_rdf2buffer_wire_compress(buffer, rdf, NULL);
}

ldns_status
ldns_rdf2buffer_wire_compress(ldns_buffer *buffer, const ldns_rdf *rdf, ldns_llnode_t *compression_data)
{
	/* If it's a DNAME, call that function to get compression */
	if(compression_data && ldns_rdf_get_type(rdf) == LDNS_RDF_TYPE_DNAME)
	{
		return ldns_dname2buffer_wire_compress(buffer,rdf,compression_data);
	}

	if (ldns_buffer_reserve(buffer, ldns_rdf_size(rdf))) {
		ldns_buffer_write(buffer, ldns_rdf_data(rdf), ldns_rdf_size(rdf));
	}
	return ldns_buffer_status(buffer);
}

ldns_status
ldns_rdf2buffer_wire_canonical(ldns_buffer *buffer, const ldns_rdf *rdf)
{
	size_t i;
	uint8_t *rdf_data;

	if (ldns_rdf_get_type(rdf) == LDNS_RDF_TYPE_DNAME) {
		if (ldns_buffer_reserve(buffer, ldns_rdf_size(rdf))) {
			rdf_data = ldns_rdf_data(rdf);
			for (i = 0; i < ldns_rdf_size(rdf); i++) {
				ldns_buffer_write_u8(buffer,
				    (uint8_t) LDNS_DNAME_NORMALIZE((int)rdf_data[i]));
			}
		}
	} else {
		/* direct copy for all other types */
		if (ldns_buffer_reserve(buffer, ldns_rdf_size(rdf))) {
			ldns_buffer_write(buffer,
						   ldns_rdf_data(rdf),
						   ldns_rdf_size(rdf));
		}
	}
	return ldns_buffer_status(buffer);
}

/* convert a rr list to wireformat */
ldns_status
ldns_rr_list2buffer_wire(ldns_buffer *buffer,const ldns_rr_list *rr_list)
{
	uint16_t rr_count;
	uint16_t i;

	rr_count = ldns_rr_list_rr_count(rr_list);
	for(i = 0; i < rr_count; i++) {
		(void)ldns_rr2buffer_wire(buffer, ldns_rr_list_rr(rr_list, i), 
					  LDNS_SECTION_ANY);
	}
	return ldns_buffer_status(buffer);
}


ldns_status
ldns_rr2buffer_wire_canonical(ldns_buffer *buffer,
						const ldns_rr *rr,
						int section)
{
	uint16_t i;
	uint16_t rdl_pos = 0;
	bool pre_rfc3597 = false;
	switch (ldns_rr_get_type(rr)) {
	case LDNS_RR_TYPE_NS:
	case LDNS_RR_TYPE_MD:
	case LDNS_RR_TYPE_MF:
	case LDNS_RR_TYPE_CNAME:
	case LDNS_RR_TYPE_SOA:
	case LDNS_RR_TYPE_MB:
	case LDNS_RR_TYPE_MG:
	case LDNS_RR_TYPE_MR:
	case LDNS_RR_TYPE_PTR:
	case LDNS_RR_TYPE_HINFO:
	case LDNS_RR_TYPE_MINFO:
	case LDNS_RR_TYPE_MX:
	case LDNS_RR_TYPE_RP:
	case LDNS_RR_TYPE_AFSDB:
	case LDNS_RR_TYPE_RT:
	case LDNS_RR_TYPE_SIG:
	case LDNS_RR_TYPE_PX:
	case LDNS_RR_TYPE_NXT:
	case LDNS_RR_TYPE_NAPTR:
	case LDNS_RR_TYPE_KX:
	case LDNS_RR_TYPE_SRV:
	case LDNS_RR_TYPE_DNAME:
	case LDNS_RR_TYPE_A6:
	case LDNS_RR_TYPE_RRSIG:
		pre_rfc3597 = true;
		break;
	default:
		break;
	}
	
	if (ldns_rr_owner(rr)) {
		(void) ldns_rdf2buffer_wire_canonical(buffer, ldns_rr_owner(rr));
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
			if (pre_rfc3597) {
				(void) ldns_rdf2buffer_wire_canonical(
					buffer, ldns_rr_rdf(rr, i));
			} else {
				(void) ldns_rdf2buffer_wire(
					buffer, ldns_rr_rdf(rr, i));
			}
		}
		if (rdl_pos != 0) {
			ldns_buffer_write_u16_at(buffer, rdl_pos,
			                         ldns_buffer_position(buffer)
		        	                   - rdl_pos - 2);
		}
	}
	return ldns_buffer_status(buffer);
}

ldns_status
ldns_rr2buffer_wire(ldns_buffer *buffer, const ldns_rr *rr, int section)
{
	return ldns_rr2buffer_wire_compress(buffer,rr,section,NULL);
}

ldns_status
ldns_rr2buffer_wire_compress(ldns_buffer *buffer, const ldns_rr *rr, int section, ldns_llnode_t *compression_data)
{
	uint16_t i;
	uint16_t rdl_pos = 0;

	if (ldns_rr_owner(rr)) {
		(void) ldns_dname2buffer_wire_compress(buffer, ldns_rr_owner(rr), compression_data);
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
		if (LDNS_RR_COMPRESS ==
		    ldns_rr_descript(ldns_rr_get_type(rr))->_compress) {

			for (i = 0; i < ldns_rr_rd_count(rr); i++) {
				(void) ldns_rdf2buffer_wire_compress(buffer,
				    ldns_rr_rdf(rr, i), compression_data);
			}
		} else {
			for (i = 0; i < ldns_rr_rd_count(rr); i++) {
				(void) ldns_rdf2buffer_wire(
				    buffer, ldns_rr_rdf(rr, i));
			}
		}
		if (rdl_pos != 0) {
			ldns_buffer_write_u16_at(buffer, rdl_pos,
			                         ldns_buffer_position(buffer)
		        	                   - rdl_pos - 2);
		}
	}
	return ldns_buffer_status(buffer);
}

ldns_status
ldns_rrsig2buffer_wire(ldns_buffer *buffer, const ldns_rr *rr)
{
	uint16_t i;

	/* it must be a sig RR */
	if (ldns_rr_get_type(rr) != LDNS_RR_TYPE_RRSIG) {
		return LDNS_STATUS_ERR;
	}
	
	/* Convert all the rdfs, except the actual signature data
	 * rdf number 8  - the last, hence: -1 */
	for (i = 0; i < ldns_rr_rd_count(rr) - 1; i++) {
		(void) ldns_rdf2buffer_wire_canonical(buffer, 
				ldns_rr_rdf(rr, i));
	}

	return ldns_buffer_status(buffer);
}

ldns_status
ldns_rr_rdata2buffer_wire(ldns_buffer *buffer, const ldns_rr *rr)
{
	uint16_t i;

	/* convert all the rdf's */
	for (i = 0; i < ldns_rr_rd_count(rr); i++) {
		(void) ldns_rdf2buffer_wire(buffer, ldns_rr_rdf(rr,i));
	}
	return ldns_buffer_status(buffer);
}

/*
 * Copies the packet header data to the buffer in wire format
 */
static ldns_status
ldns_hdr2buffer_wire(ldns_buffer *buffer, const ldns_pkt *packet)
{
	uint8_t flags;
	uint16_t arcount;

	if (ldns_buffer_reserve(buffer, 12)) {
		ldns_buffer_write_u16(buffer, ldns_pkt_id(packet));
		
		flags = ldns_pkt_qr(packet) << 7
		        | ldns_pkt_get_opcode(packet) << 3
		        | ldns_pkt_aa(packet) << 2
		        | ldns_pkt_tc(packet) << 1 | ldns_pkt_rd(packet);
		ldns_buffer_write_u8(buffer, flags);
		
		flags = ldns_pkt_ra(packet) << 7
		        /*| ldns_pkt_z(packet) << 6*/
		        | ldns_pkt_ad(packet) << 5
		        | ldns_pkt_cd(packet) << 4
			| ldns_pkt_get_rcode(packet);
		ldns_buffer_write_u8(buffer, flags);
		
		ldns_buffer_write_u16(buffer, ldns_pkt_qdcount(packet));
		ldns_buffer_write_u16(buffer, ldns_pkt_ancount(packet));
		ldns_buffer_write_u16(buffer, ldns_pkt_nscount(packet));
		/* add EDNS0 and TSIG to additional if they are there */
		arcount = ldns_pkt_arcount(packet);
		if (ldns_pkt_tsig(packet)) {
			arcount++;
		}
		if (ldns_pkt_edns(packet)) {
			arcount++;
		}
		ldns_buffer_write_u16(buffer, arcount);
	}
	
	return ldns_buffer_status(buffer);
}

ldns_status
ldns_pkt2buffer_wire(ldns_buffer *buffer, const ldns_pkt *packet)
{
	ldns_status status;

	ldns_llnode_t *compression_data = LDNS_CALLOC(ldns_llnode_t, 1);
	if (!compression_data) return LDNS_STATUS_MEM_ERR;

	status = ldns_pkt2buffer_wire_compress(buffer, packet, compression_data);

	for (ldns_llnode_t *ptr; compression_data; compression_data = ptr)
	{
		ptr = compression_data->next;
		LDNS_FREE(compression_data);
	}

	return status;
}

ldns_status
ldns_pkt2buffer_wire_compress(ldns_buffer *buffer, const ldns_pkt *packet, ldns_llnode_t *compression_data)
{
	ldns_rr_list *rr_list;
	uint16_t i;

	/* edns tmp vars */
	ldns_rr *edns_rr;
	uint8_t edata[4];

	(void) ldns_hdr2buffer_wire(buffer, packet);

	rr_list = ldns_pkt_question(packet);
	if (rr_list) {
		for (i = 0; i < ldns_rr_list_rr_count(rr_list); i++) {
			(void) ldns_rr2buffer_wire_compress(buffer, 
			             ldns_rr_list_rr(rr_list, i), LDNS_SECTION_QUESTION, compression_data);
		}
	}
	rr_list = ldns_pkt_answer(packet);
	if (rr_list) {
		for (i = 0; i < ldns_rr_list_rr_count(rr_list); i++) {
			(void) ldns_rr2buffer_wire_compress(buffer, 
			             ldns_rr_list_rr(rr_list, i), LDNS_SECTION_ANSWER, compression_data);
		}
	}
	rr_list = ldns_pkt_authority(packet);
	if (rr_list) {
		for (i = 0; i < ldns_rr_list_rr_count(rr_list); i++) {
			(void) ldns_rr2buffer_wire_compress(buffer, 
			             ldns_rr_list_rr(rr_list, i), LDNS_SECTION_AUTHORITY, compression_data);
		}
	}
	rr_list = ldns_pkt_additional(packet);
	if (rr_list) {
		for (i = 0; i < ldns_rr_list_rr_count(rr_list); i++) {
			(void) ldns_rr2buffer_wire_compress(buffer, 
			             ldns_rr_list_rr(rr_list, i), LDNS_SECTION_ADDITIONAL, compression_data);
		}
	}
	
	/* add EDNS to additional if it is needed */
	if (ldns_pkt_edns(packet)) {
		edns_rr = ldns_rr_new();
		if(!edns_rr) return LDNS_STATUS_MEM_ERR;
		ldns_rr_set_owner(edns_rr,
				ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, "."));
		ldns_rr_set_type(edns_rr, LDNS_RR_TYPE_OPT);
		ldns_rr_set_class(edns_rr, ldns_pkt_edns_udp_size(packet));
		edata[0] = ldns_pkt_edns_extended_rcode(packet);
		edata[1] = ldns_pkt_edns_version(packet);
		ldns_write_uint16(&edata[2], ldns_pkt_edns_z(packet));
		ldns_rr_set_ttl(edns_rr, ldns_read_uint32(edata));
		/* don't forget to add the edns rdata (if any) */
		if (packet->_edns_data)
			ldns_rr_push_rdf (edns_rr, packet->_edns_data);
		(void)ldns_rr2buffer_wire_compress(buffer, edns_rr, LDNS_SECTION_ADDITIONAL, compression_data);
		/* take the edns rdata back out of the rr before we free rr */
		if (packet->_edns_data)
			(void)ldns_rr_pop_rdf (edns_rr);
		ldns_rr_free(edns_rr);
	}
	
	/* add TSIG to additional if it is there */
	if (ldns_pkt_tsig(packet)) {
		(void) ldns_rr2buffer_wire_compress(buffer,
		                           ldns_pkt_tsig(packet), LDNS_SECTION_ADDITIONAL, compression_data);
	}

	return LDNS_STATUS_OK;
}

ldns_status
ldns_rdf2wire(uint8_t **dest, const ldns_rdf *rdf, size_t *result_size)
{
	ldns_buffer *buffer = ldns_buffer_new(LDNS_MAX_PACKETLEN);
	ldns_status status;
	*result_size = 0;
	*dest = NULL;
	if(!buffer) return LDNS_STATUS_MEM_ERR;
	
	status = ldns_rdf2buffer_wire(buffer, rdf);
	if (status == LDNS_STATUS_OK) {
		*result_size =  ldns_buffer_position(buffer);
		*dest = (uint8_t *) ldns_buffer_export(buffer);
	}
	ldns_buffer_free(buffer);
	return status;
}

ldns_status
ldns_rr2wire(uint8_t **dest, const ldns_rr *rr, int section, size_t *result_size)
{
	ldns_buffer *buffer = ldns_buffer_new(LDNS_MAX_PACKETLEN);
	ldns_status status;
	*result_size = 0;
	*dest = NULL;
	if(!buffer) return LDNS_STATUS_MEM_ERR;
	
	status = ldns_rr2buffer_wire(buffer, rr, section);
	if (status == LDNS_STATUS_OK) {
		*result_size =  ldns_buffer_position(buffer);
		*dest = (uint8_t *) ldns_buffer_export(buffer);
	}
	ldns_buffer_free(buffer);
	return status;
}

ldns_status
ldns_pkt2wire(uint8_t **dest, const ldns_pkt *packet, size_t *result_size)
{
	ldns_buffer *buffer = ldns_buffer_new(LDNS_MAX_PACKETLEN);
	ldns_status status;
	*result_size = 0;
	*dest = NULL;
	if(!buffer) return LDNS_STATUS_MEM_ERR;
	
	status = ldns_pkt2buffer_wire(buffer, packet);
	if (status == LDNS_STATUS_OK) {
		*result_size =  ldns_buffer_position(buffer);
		*dest = (uint8_t *) ldns_buffer_export(buffer);
	}
	ldns_buffer_free(buffer);
	return status;
}
