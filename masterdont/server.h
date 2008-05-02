/*
	server.h	masterdont server, serves IXFR, AXFR, SOA queries.
*/

#ifndef SERVER_H
#define SERVER_H

struct zones_t;

/**
 * Socket that is being serviced by the server.
 */
struct socket_service {
	/* socket */
	int s;
	/* true if a tcp socket */
	int is_tcp;
	/* tcp state: listening, reading, or writing. */
	enum {svr_tcp_listen, svr_tcp_read, svr_tcp_write} tcp_state;
	/* bytes processed for tcp */
	size_t bytes_done;

	/* peer address */
	struct sockaddr_storage peer;
	socklen_t peerlen;

	/* buffer for input/output */
	ldns_buffer* buffer;

	/* rrs for the reply. If not null, these RRs are part of the answer. */
	ldns_rr_list* reply;

	/* next in linked list */
	struct socket_service* next;
};

struct server_info_t {
	/* zones */
	struct zones_t* zones;
	/* config */
	struct config_file* cfg;

	/* number of open tcp connections */
	int num_tcp;
	/* socket list */
	struct socket_service* sock_list;

	/* select data, max fd */
	int maxfd;
	/* fd sets to select on, copied from. */
	fd_set rset, wset, eset;
};

/**
 * start the server, give zones, configfile (already read) 
 * and portnumber to bind.
 * returns true if it needs to reload, false for exit.
*/
int server_start(const char* config);

/**
 * free service list
*/
void server_free(struct server_info_t* s);

/**
 * create service sockets on specified port.
*/
void server_bind(struct server_info_t* sinfo, int port);

/**
 * create servicing struct from addr. socket, bind, (listen).
 * NULL on error.
*/
struct socket_service* server_service_create(struct addrinfo *ai);

/**
 * free the service, close the socket
*/
void server_service_free(struct socket_service* svr);

/**
 * Perform a select and handle the events on the sockets.
*/
void server_handle_net(struct server_info_t *sinfo);

/**
 * Handle read possible on serviced socket.
 * Sets delete to true if connection should be closed (for tcp).
 */
void handle_read(struct server_info_t *sinfo, struct socket_service* sv,
	int *del, struct zones_t* zones);

/**
 * Handle write possible on serviced socket.
 * Sets delete to true if connection should be closed (for tcp).
 */
void handle_write(struct server_info_t *sinfo, struct socket_service* sv,
	int *del);

/**
 * Handle tcp listen. Creates new socket service after accepting.
*/
void handle_listen(struct server_info_t *sinfo, struct socket_service* sv);

/**
 * read tcp query from socket.
 * returns true when query is finished OK. del is true on error.
*/
int read_tcp_query(struct socket_service *sv, int* del);

/**
 * read udp query from socket.
 * returns true when query is read OK.
*/
int read_udp_query(struct socket_service *sv);

/**
 * process query.
 * First result packet is in the buffer.
 * More results can be found in the rrlist.
 * return false if query should be dropped (no reply).
*/
int process_query(struct socket_service* sv, struct zones_t* zones);

/**
 * send udp answer back to sender.
*/
void send_udp_answer(struct socket_service* sv);

/**
 * send (part of) tcp answer.
 * del is true when tcp should be closed up.
*/
void write_tcp_answer(struct socket_service* sv, int* del);

/**
 * Dump RRs into the answer to get more reply. Makes new reply buffer.
 * reply becomes NULL when last buffer is filled.
*/
void fill_r_up(struct socket_service* sv);

/**
 * Dumps RRs into the answer section of the pkt.
*/
void fill_r_up_pkt(struct socket_service* sv, ldns_pkt* in_here);

#endif /* SERVER_H */
