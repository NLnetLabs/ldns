#include "config.h"
#include "process.h"
#include "zones.h"
#include "zinfo.h"
#include "server.h"

ldns_pkt_rcode 
process_pkts(struct socket_service* sv, ldns_pkt* q, ldns_pkt* r,
	struct zones_t* zones)
{
	if(ldns_pkt_edns(q)) {
		ldns_pkt_set_edns_do(r, ldns_pkt_edns_do(q));
		ldns_pkt_set_edns_udp_size(r, 4096);
	}
	if(ldns_pkt_tsig(q)) {
		printf("tsig todo\n");
	}

	switch(ldns_pkt_get_opcode(q)) {
	case LDNS_PACKET_QUERY:
		return process_pkt_query(sv, q, r, zones);
	case LDNS_PACKET_NOTIFY:
		return process_pkt_notify(sv, q, r, zones);
	default:
		return LDNS_RCODE_NOTIMPL;
	}
}

ldns_pkt_rcode 
process_pkt_notify(struct socket_service* sv, ldns_pkt* q, ldns_pkt* r,
	struct zones_t* zones)
{
	(void)(sv); (void)(q); (void)(r); (void)zones;
	return LDNS_RCODE_NOTIMPL;
}

ldns_pkt_rcode 
process_pkt_query(struct socket_service* sv, ldns_pkt* q, ldns_pkt* r,
	struct zones_t* zones)
{
	ldns_rr *qrr;
	struct zone_entry_t* entry ;

	if(ldns_pkt_qdcount(q) != 1) /* one question */
		return LDNS_RCODE_FORMERR;
	qrr = ldns_rr_list_rr(ldns_pkt_question(q), 0);

	/* find query name zone */
	entry = zones_find_rdf(zones, ldns_rr_owner(qrr), 
		ldns_rr_get_class(qrr));
	if(!entry) {
		return LDNS_RCODE_REFUSED;
	}
	printf("Got zone for q. %s\n", entry->zstr);

	/* copy question */
	ldns_pkt_push_rr(r, LDNS_SECTION_QUESTION, ldns_rr_clone(qrr));

	switch(ldns_rr_get_type(qrr)) {
	case LDNS_RR_TYPE_ANY:
		ldns_pkt_set_aa(r, false);
	case LDNS_RR_TYPE_SOA:
		return process_pkt_soa(sv, q, r, entry);
	case LDNS_RR_TYPE_AXFR:
		return process_pkt_axfr(sv, entry);
	case LDNS_RR_TYPE_IXFR:
		return process_pkt_ixfr(sv, q, r, entry);
	default:
		return LDNS_RCODE_REFUSED;
	}
}

ldns_pkt_rcode 
process_pkt_soa(struct socket_service* sv, ldns_pkt* q, ldns_pkt* r,
	struct zone_entry_t* entry)
{
	ldns_rr_list* soa = ldns_rr_list_clone(entry->zinfo->last_soa);
	(void)sv; (void)q;
	if(!soa) /* have zone but not soa; no data for zone */
		return LDNS_RCODE_SERVFAIL;
	/* put the answer into the packet */
	ldns_pkt_push_rr_list(r, LDNS_SECTION_ANSWER, soa);
	return LDNS_RCODE_NOERROR;
}

ldns_pkt_rcode 
process_pkt_ixfr(struct socket_service* sv, ldns_pkt* q, ldns_pkt* r,
	struct zone_entry_t* entry)
{
	uint32_t serial_from, serial_to;
	ldns_rr_list *rr_add=0, *rr_remove=0;
	ldns_rr *soa_from=0; 
	ldns_rr_list *soa_to=0;

	if(ldns_pkt_nscount(q) != 1 ||
		ldns_rr_get_type(ldns_rr_list_rr(ldns_pkt_authority(q), 0))
		!= LDNS_RR_TYPE_SOA) {
		printf("ixfr without serial indication\n");
		return LDNS_RCODE_FORMERR;
	}
	if(!entry->zinfo->is_present) {
		printf("ixfr request for zone without data\n");
		return LDNS_RCODE_SERVFAIL;
	}

	serial_to = entry->zinfo->last_serial;
	serial_from = ldns_rdf2native_int32(ldns_rr_rdf(
		ldns_rr_list_rr(ldns_pkt_authority(q), 0), 2));

	soa_to = ldns_rr_list_clone(entry->zinfo->last_soa);
	if(!soa_to) {
		return LDNS_RCODE_SERVFAIL;
	}

	if(serial_to == serial_from) {
		printf("ixfr request for latest version\n");
		ldns_pkt_push_rr_list(r, LDNS_SECTION_ANSWER, soa_to);
		return LDNS_RCODE_NOERROR;
	}

	/* if UDP - reply with SOA and TC indication */
	if(!sv->is_tcp) {
		ldns_pkt_set_tc(r, true);
		ldns_pkt_push_rr_list(r, LDNS_SECTION_ANSWER, soa_to);
		return LDNS_RCODE_NOERROR;
	}

	zinfo_get_zone_diff(entry, serial_from, serial_to, &rr_remove,
		&rr_add, &soa_from, &soa_to);
	if(!rr_remove || !rr_add || !soa_from || !soa_to) {
		printf("get_zone_diff failed, fallback to AXFR\n");
		return process_pkt_axfr(sv, entry);
	}

	/* create rrlist for reply */
	if(sv->reply)
		ldns_rr_list_deep_free(sv->reply);
	sv->reply = ldns_rr_list_new();
	if(!sv->reply) {
		printf("out of memory\n");
		return LDNS_RCODE_SERVFAIL;
	}
	/* a 'condensed' IXFR zone transfer (see RFC 1995) */
	ldns_rr_list_push_rr(sv->reply, ldns_rr_clone(soa_to));
	ldns_rr_list_push_rr(sv->reply, soa_from);
	/* deletes */
	ldns_rr_list_cat(sv->reply, rr_remove);
	ldns_rr_list_push_rr(sv->reply, ldns_rr_clone(soa_to));
	/* adds */
	ldns_rr_list_cat(sv->reply, rr_add);
	ldns_rr_list_push_rr(sv->reply, soa_to);

	/* not deep free since rrs moved to the answer */
	ldns_rr_list_free(rr_remove);
	ldns_rr_list_free(rr_add);
	/* do not need to delete soa_from, soa_to: they are in rrlist. */

	return LDNS_RCODE_NOERROR;
}

ldns_pkt_rcode 
process_pkt_axfr(struct socket_service* sv, struct zone_entry_t* entry)
{
	uint32_t serial;
	ldns_zone* z = 0;

	serial = entry->zinfo->last_serial;
	zinfo_get_zone_full(entry, serial, &z);
	if(!z) {
		/* no data for this zone! */
		printf("Could not get latest zone info for zone %s %u\n",
			entry->zstr, serial);
		return LDNS_RCODE_SERVFAIL;
	}

	/* create list of RRs in sv->rrlist */
	if(sv->reply)
		ldns_rr_list_deep_free(sv->reply);
	sv->reply = ldns_rr_list_new();
	if(!sv->reply) {
		printf("out of memory\n");
		return LDNS_RCODE_SERVFAIL;
	}
	/* move zone contents over */
	ldns_rr_list_push_rr(sv->reply, ldns_rr_clone(ldns_zone_soa(z))); 
	ldns_rr_list_cat(sv->reply, ldns_zone_rrs(z)); 
	ldns_rr_list_push_rr(sv->reply, ldns_rr_clone(ldns_zone_soa(z)));

	ldns_rr_list_set_rr_count(ldns_zone_rrs(z), 0);
	ldns_zone_deep_free(z);

	return LDNS_RCODE_NOERROR;
}
