/**
 * An example ldns program
 *
 * Setup a resolver
 * Query a nameserver
 * Print the result
 */

#include <config.h>
#include <ldns/ldns.h>
#include <ldns/dname.h>

void
print_usage(char *file)
{
	printf("AXFR example\n");
	printf("Usage: %s <domain> <server ip>\n", file);
	printf("ipv4 only atm\n");
	exit(0);
}

int
main(int argc, char **argv)
{       
        ldns_rdf *nameserver;

        ldns_pkt *query;
        ldns_buffer *query_wire;
        
        ldns_pkt *pkt;
        int soa_count;
        int connection;

        struct sockaddr_storage *ns;
        struct sockaddr_in *ns4;
        struct sockaddr_in6 *ns6;
        int ns_len = 0;

        char *server_ip = NULL;
        char *name = NULL;

        ldns_rr_list *rr_list;
        ldns_rr *cur_rr;
        char *rr_str;
        uint16_t i;
        
	/* Get the domain and the nameserver from the command line */
        if (argc < 3) {
        	print_usage(argv[0]);
	} else {
		name = argv[1];
		server_ip = argv[2];
	}

        nameserver  = ldns_rdf_new_frm_str(server_ip, LDNS_RDF_TYPE_A);
	if (!nameserver) {
		printf("Bad server ip\n");
		return -1;
	}

        /* Create the query */
	query = ldns_pkt_query_new_frm_str(name,
	                                   LDNS_RR_TYPE_AXFR,
	                                   LDNS_RR_CLASS_IN,
	                                   0);
	                                    
	/* For AXFR, we have to make the connection ourselves */
	ns = ldns_rdf2native_sockaddr_storage(nameserver);

        ldns_rdf_free(nameserver);

	/* Determine the address size.
	 * This is a nice one for a convenience funtion
	 */
	switch(ns->ss_family) {
		case AF_INET:
			ns4 = (struct sockaddr_in*) ns;
			ns4->sin_port = htons(53);
			ns_len = (socklen_t)sizeof(struct sockaddr_in);
			break;
		case AF_INET6:
			ns6 = (struct sockaddr_in6*) ns;
			ns6->sin6_port = htons(53);
			ns_len = (socklen_t)sizeof(struct sockaddr_in6);
			break;
                default:
                	printf("unkown inet family\n");
                	return -1;
	}

	connection = ldns_tcp_connect(ns, ns_len);
	if (connection == 0) {
		return -1;
	}
	
	/* Convert the query to a buffer
	 * Is this necessary?
	 */
	query_wire = ldns_buffer_new(MAX_PACKETLEN);
	if (ldns_pkt2buffer_wire(query_wire, query) != LDNS_STATUS_OK) {
		printf("Unable to create wire data for query\n");
		return -1;
	}
	
	/* Send the query */
	ldns_tcp_send_query(query_wire, connection, ns, ns_len);
	
        ldns_pkt_free(query);
        ldns_buffer_free(query_wire);

	/* Print all the resource records we receive.
	 * The AXFR is done once the second SOA record is sent
	 */
	soa_count = 0;
	while (soa_count < 2) {
		pkt = ldns_tcp_read_packet(connection);
		
		if (!pkt)  {
			printf("error reading packet\n");
		} else {
			rr_list = ldns_pkt_answer(pkt);
			
			/* Counting the number of certain types of rrs might
			 * be another good convenience function */
			for (i = 0; i < ldns_rr_list_rr_count(rr_list); i++) {
				cur_rr = ldns_rr_list_rr(rr_list, i);
				if (ldns_rr_get_type(cur_rr) == LDNS_RR_TYPE_SOA) {
					soa_count++;
				}
				rr_str = ldns_rr2str(cur_rr);
				printf("%s\n", rr_str);
				FREE(rr_str);
			}
			ldns_pkt_free(pkt);
		}
	}

	/* Don't forget to close the connection */
	close(connection);

        return 0;
}
