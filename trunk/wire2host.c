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

/**
 * transform a wireformatted rdata to our
 * internal representation
 */
ssize_t
rdata_buf_to_rdf(ldns_rdf *rd, ldns_buf *buffer)
{
        size_t end = buffer_position(packet) + data_size;
        ssize_t i;
        rdata_atom_type temp_rdatas[MAXRDATALEN];
        rrtype_descriptor_type *descriptor = rrtype_descriptor_by_type(rrtype);
        region_type *temp_region;
        
        assert(descriptor->maximum <= MAXRDATALEN);

        if (!buffer_available(packet, data_size)) {
                return -1;
        }
        
        temp_region = region_create(xalloc, free);
        
        for (i = 0; i < descriptor->maximum; ++i) {
                int is_domain = 0;
                size_t length = 0;

                if (buffer_position(packet) == end) {
                        if (i < descriptor->minimum) {
                                region_destroy(temp_region);
                                return -1;
                        } else {
                                break;
                        }
                }
                
                switch (rdata_atom_wireformat_type(rrtype, i)) {
                case RDATA_WF_COMPRESSED_DNAME:
                case RDATA_WF_UNCOMPRESSED_DNAME:
                        is_domain = 1;
                        break;
                case RDATA_WF_BYTE:
                        length = sizeof(uint8_t);
                        break;
                case RDATA_WF_SHORT:
                        length = sizeof(uint16_t);
                        break;
                case RDATA_WF_LONG:
                        length = sizeof(uint32_t);
                        break;
                case RDATA_WF_TEXT:
                        /* Length is stored in the first byte.  */
                        length = 1 + buffer_current(packet)[0];
                        break;
                case RDATA_WF_A:
                        length = sizeof(in_addr_t);
                        break;
                case RDATA_WF_AAAA:
                        length = IP6ADDRLEN;
                        break;
                case RDATA_WF_BINARY:
                        /* Remaining RDATA is binary.  */
                        length = end - buffer_position(packet);
                        break;
                case RDATA_WF_APL:
                        length = (sizeof(uint16_t)    /* address family */
                                  + sizeof(uint8_t)   /* prefix */
                                  + sizeof(uint8_t)); /* length */
                        if (buffer_position(packet) + length <= end) {
                                length += (buffer_current(packet)[sizeof(uint16_t) + sizeof(uint8_t)
]) & 0x7f;
                        }

                        break;
                }

                if (is_domain) {
                        const dname_type *dname = dname_make_from_packet(
                                temp_region, packet, 1, 1);
                        if (!dname) {
                                region_destroy(temp_region);
                                return -1;
                        }
                        temp_rdatas[i].domain
                        temp_rdatas[i].domain
                                = domain_table_insert(owners, dname);
                } else {
                        if (buffer_position(packet) + length > end) {
/*                              zc_error_prev_line("unknown RDATA is truncated"); */
                                region_destroy(temp_region);
                                return -1;
                        }
                        
                        temp_rdatas[i].data = (uint16_t *) region_alloc(
                                region, sizeof(uint16_t) + length);
                        temp_rdatas[i].data[0] = length;
                        buffer_read(packet, temp_rdatas[i].data + 1, length);
                }
        }

        if (buffer_position(packet) < end) {
/*              zc_error_prev_line("unknown RDATA has trailing garbage"); */
                region_destroy(temp_region);
                return -1;
        }

        *rdatas = (rdata_atom_type *) region_alloc_init(
                region, temp_rdatas, i * sizeof(rdata_atom_type));
        region_destroy(temp_region);
        return i;
}

