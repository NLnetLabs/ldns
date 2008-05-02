/*
 * process.h, process queries to determine the answer RRs and packets.
*/

#ifndef PROCESS_H
#define PROCESS_H

struct socket_service;
struct zones_t;
struct zone_entry_t;

/**
 * Calculate the reply for the query in q. Put answer in packet p.
 * P is an empty packet on routine start, with header.
 */
ldns_pkt_rcode process_pkts(struct socket_service* sv, 
	ldns_pkt* q, ldns_pkt* r, struct zones_t* zones);

/**
 * Process QUERY
 */
ldns_pkt_rcode process_pkt_query(struct socket_service* sv, 
	ldns_pkt* q, ldns_pkt* r, struct zones_t* zones);

/**
 * Process NOTIFY
 */
ldns_pkt_rcode process_pkt_notify(struct socket_service* sv, 
	ldns_pkt* q, ldns_pkt* r, struct zones_t* zones);

/**
 * Process SOA queries
 * pass correct zone entry.
 */
ldns_pkt_rcode process_pkt_soa(struct socket_service* sv, 
	ldns_pkt* q, ldns_pkt* r, struct zone_entry_t* entry);

/**
 * Process IXFR
 * pass correct zone entry.
 */
ldns_pkt_rcode process_pkt_ixfr(struct socket_service* sv, 
	ldns_pkt* q, ldns_pkt* r, struct zone_entry_t* entry);

/**
 * Process AXFR
 * pass correct zone entry.
 */
ldns_pkt_rcode process_pkt_axfr(struct socket_service* sv, 
	struct zone_entry_t* entry);
#endif /* PROCESS_H */
