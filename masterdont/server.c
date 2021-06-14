#include "config.h"
#include "config_file.h"
#include "server.h"
#include "zones.h"
#include "process.h"

/* global variables set by signals */
static int work = 1;
static int hupped = 0;

/* signal handler for server */
void server_handle_signal(int sig)
{
	switch(sig) {
	case SIGHUP:
		hupped = 1;
		work = 0;
		break;
	case SIGTERM:
	case SIGINT:
	case SIGQUIT:
		work = 0;
		break;
	default:
		printf("unhandled signal %d\n", sig);
		break;
	}
}

int server_start(const char* config)
{
	struct server_info_t* sinfo = (struct server_info_t*)calloc(1,
		sizeof(struct server_info_t));
	if(!sinfo) {
		printf("out of memory\n");
		return 0;
	}
	FD_ZERO(&sinfo->rset);
	FD_ZERO(&sinfo->wset);
	FD_ZERO(&sinfo->eset);
	work = 1;
	hupped = 0;
	signal(SIGHUP, server_handle_signal);
	signal(SIGQUIT, server_handle_signal);
	signal(SIGTERM, server_handle_signal);
	signal(SIGINT, server_handle_signal);
	signal(SIGPIPE, SIG_IGN);
	sinfo->zones = zones_create();
	sinfo->cfg = config_file_create(config);
	config_file_read(sinfo->cfg, config, sinfo->zones);
	zones_read(sinfo->zones);

	server_bind(sinfo, sinfo->cfg->port);
	if(!sinfo->sock_list) {
		printf("Could not start server.\n");
		server_free(sinfo);
		return 0;
	}
	printf("service for %d zones (%s) on port %d\n", 
		(int)sinfo->zones->ztree->count, config, sinfo->cfg->port);
	printf("Masterdont started pid %d\n", (int)getpid());

	while(work) {
		server_handle_net(sinfo);
	}
	
	server_free(sinfo);
	return hupped;
}

void server_handle_net(struct server_info_t *sinfo)
{
	struct socket_service* p, **prevp;
	int delete_me;
	fd_set rset, wset, eset;
	rset = sinfo->rset;
	wset = sinfo->wset;
	eset = sinfo->eset;
	if(select(sinfo->maxfd+1, &rset, &wset, &eset, NULL) == -1) {
		if(errno==EINTR)
			return;
		printf("select: %s\n", strerror(errno));
		return;
	}
	
	p = sinfo->sock_list;
	prevp = &sinfo->sock_list;
	while(p) {
		delete_me = 0;
		if(FD_ISSET(p->s, &rset))
			handle_read(sinfo, p, &delete_me, sinfo->zones);
		if(!delete_me && FD_ISSET(p->s, &wset))
			handle_write(sinfo, p, &delete_me);
		/* eset ignored */
		if(delete_me) {
			printf("delete me\n");
			FD_CLR(p->s, &sinfo->rset);
			FD_CLR(p->s, &sinfo->wset);
			FD_CLR(p->s, &sinfo->eset);
			if(p->is_tcp)
				sinfo->num_tcp --;
			/* cannot lower maxfd */
			*prevp = p->next; /* snip out of list */
			server_service_free(p);
			p = *prevp; /* go to next */
		} else {
			prevp = &p->next;
			p = p->next;
		}
	}
}

void server_free(struct server_info_t* sinfo)
{
	struct socket_service* p = sinfo->sock_list, *np=0;
	config_file_delete(sinfo->cfg);
	zones_free(sinfo->zones);
	while(p) {
		np = p->next;
		server_service_free(p);
		p = np;
	}
	free(sinfo);
}

void server_bind(struct server_info_t* sinfo, int port)
{
	struct addrinfo hints;
	struct addrinfo *res = 0;
	struct addrinfo *p = 0;
	int err=0;
	char service[16];
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_flags = AI_PASSIVE 
#ifdef AI_NUMERICSERV
	| AI_NUMERICSERV
#endif
	;
	sprintf(service, "%d", port);
	
	if((err=getaddrinfo(NULL, service, &hints, &res)) != 0) {
		printf("getaddrinfo: %s\n", gai_strerror(err));
		return;
	}

	p = res;
	while(p)
	{
		/* only TCP and UDP */
		if(p->ai_protocol == IPPROTO_TCP || 
		   p->ai_protocol == IPPROTO_UDP) {
			struct socket_service* sv;
			sv = server_service_create(p);
			if(!sv) {
				err=errno;
			} else {
				sv->next = sinfo->sock_list;
				sinfo->sock_list = sv;
				FD_SET(sv->s, &sinfo->rset);
				if(sv->s > sinfo->maxfd)
					sinfo->maxfd = sv->s;
			}
		}
		p = p->ai_next;
	}
	if(!sinfo->sock_list) {
		printf("Fatal: No interfaces could be initialized: %s\n",
			strerror(err));
	}

	if(res) freeaddrinfo(res);
}

struct socket_service* server_service_create(struct addrinfo *ai)
{
	struct socket_service* svr;
	int s;
	const int on = 1;
	
	s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	if(s == -1) {
		return 0;
	}
	if(setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
		goto error;
	}
#ifdef IPV6_V6ONLY
	if(ai->ai_protocol == AF_INET6 &&
		setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)) < 0) {
		goto error;
	}
#endif
	if(bind(s, ai->ai_addr, ai->ai_addrlen) == -1) {
		goto error;
	}
	if(ai->ai_socktype == SOCK_STREAM &&
	   listen(s, TCP_LISTEN_BACKLOG) == -1) {
		goto error;
	}

	/* create service struct */
	svr = (struct socket_service*)malloc(sizeof(struct socket_service));
	if(!svr) {
		errno = ENOMEM;
		goto error;
	}
	memset(svr, 0, sizeof(struct socket_service));
	svr->tcp_state = svr_tcp_listen;
	svr->s = s;
	if(ai->ai_socktype == SOCK_STREAM)
		svr->is_tcp = 1;
	svr->buffer = ldns_buffer_new(SERVER_BUFFER_SIZE);
	if(!svr->buffer) {
		errno = ENOMEM;
		free(svr);
		goto error;
	}
	return svr;

error:
	close(s);
	return 0;
}

void server_service_free(struct socket_service* svr)
{
	close(svr->s);
	if(svr->reply)
		ldns_rr_list_deep_free(svr->reply);
	if(svr->buffer)
		ldns_buffer_free(svr->buffer);
	free(svr);
}

void 
handle_listen(struct server_info_t *sinfo, struct socket_service* listen_v)
{
	struct socket_service* sh;
	int newfd;

	if(sinfo->num_tcp >= MAX_TCP) {
		printf("Error: incoming tcp query, but MAX_TCP reached (%d)\n",
			MAX_TCP);
		return;
	}

	if((newfd=accept(listen_v->s, NULL, NULL)) == -1) {
		printf("Error tcp accept: %s", strerror(errno));
		return;
	}
	if(fcntl(newfd, F_SETFL, O_NONBLOCK) == -1) {
		printf("Error fcntl: %s\n", strerror(errno));
		close(newfd);
		return;
	}
	sh = (struct socket_service*)malloc(sizeof(struct socket_service));
	if(!sh) {
		printf("out of memory\n");
		close(newfd);
		return;
	}
	memset(sh, 0, sizeof(struct socket_service));
	sh->tcp_state = svr_tcp_read;
	sh->s = newfd;
	sh->buffer = ldns_buffer_new(SERVER_BUFFER_SIZE);
	sh->is_tcp = 1;
	if(!sh->buffer) {
		printf("out of memory\n");
		close(newfd);
		free(sh);
		return;
	}
	ldns_buffer_clear(sh->buffer);
	if(sh->s > sinfo->maxfd)
		sinfo->maxfd = sh->s;
	FD_SET(sh->s, &sinfo->rset);
	sinfo->num_tcp++;

	/* put after the current service */
	sh->next = listen_v->next;
	listen_v->next = sh;
}

void handle_read(struct server_info_t *sinfo, struct socket_service* sv,
        int *del, struct zones_t* zones)
{
	printf("handle_read %s %s\n", sv->is_tcp?"tcp":"udp",
		sv->tcp_state==svr_tcp_listen?"listen":"");
	/* get the data */
	if(sv->is_tcp) {
		if(sv->tcp_state == svr_tcp_listen) {
			handle_listen(sinfo, sv);
			return;
		}
		if(sv->tcp_state != svr_tcp_read) {
			FD_CLR(sv->s, &sinfo->rset);
			return;
		}
		/* read some more from channel */
		if(!read_tcp_query(sv, del))
			return; /* continue later */
	} else {
		/* udp recv */
		if(!read_udp_query(sv))
			return;
	}

	/* handle request */
	if(!process_query(sv, zones))
		return;

	if(!sv->is_tcp) {
		/* sendto */
		send_udp_answer(sv);
	} else {
		/* change socket tcp to writing mode */
		sv->tcp_state = svr_tcp_write;
		sv->bytes_done = 0;
		FD_CLR(sv->s, &sinfo->rset);
		FD_SET(sv->s, &sinfo->wset);
	}
}

void handle_write(struct server_info_t *sinfo, struct socket_service* sv,
        int *del)
{
	if(sv->is_tcp) {
		if(sv->tcp_state != svr_tcp_write) {
			FD_CLR(sv->s, &sinfo->wset);
			return;
		}
		write_tcp_answer(sv, del);
	} else {
		FD_CLR(sv->s, &sinfo->wset);
	}
}

int read_tcp_query(struct socket_service *sv, int* del)
{
	ssize_t ret;
	uint16_t len;
	printf("read tcp query %d\n", (int)sv->bytes_done);
	if(sv->bytes_done < sizeof(len)) {
		ret = read(sv->s, ldns_buffer_current(sv->buffer),
			sizeof(len)-ldns_buffer_position(sv->buffer));
		printf("read tcp query got %d\n", (int)ret);
		if(ret == 0) {
			*del = 1;
			return 0;
		}
		if(ret == -1) {
			*del = 1;
			printf("read: %s\n", strerror(errno));
			return 0;
		}
		ldns_buffer_skip(sv->buffer, ret);
		if(ldns_buffer_position(sv->buffer) < sizeof(len))
			return 0; /* more later */
		len = ldns_buffer_read_u16_at(sv->buffer, 0);
		printf("so len is %d\n", len);
		ldns_buffer_clear(sv->buffer);
		ldns_buffer_set_limit(sv->buffer, len);
		sv->bytes_done = sizeof(len);
	}

	ret = read(sv->s, ldns_buffer_current(sv->buffer),
		ldns_buffer_remaining(sv->buffer));
	printf("read tcp query content got %d\n", (int)ret);
	if(ret == 0) {
		*del = 1;
		return 0;
	}
	if(ret == -1) {
		*del = 1;
		printf("read: %s\n", strerror(errno));
		return 0;
	}
	ldns_buffer_skip(sv->buffer, ret);
	if(ldns_buffer_remaining(sv->buffer) > 0) {
		return 0;
	}
	ldns_buffer_flip(sv->buffer);
	return 1;
}

int read_udp_query(struct socket_service *sv)
{
	ssize_t sz;
	ldns_buffer_clear(sv->buffer);
	printf("udp read\n");
	sv->peerlen = sizeof(sv->peer);
	sz = recvfrom(sv->s, ldns_buffer_begin(sv->buffer),
		ldns_buffer_capacity(sv->buffer),
		0, (struct sockaddr*)&sv->peer, &sv->peerlen);
	printf("udp read %d\n", (int)sz);
	if(sz == -1) {
		printf("recvfrom: %s\n", strerror(errno));
		return 0;
	}
	if(sz == 0)
		return 0;
	ldns_buffer_skip(sv->buffer, sz);
	ldns_buffer_flip(sv->buffer);	
	return 1;
}

static void set_error(struct socket_service* sv, ldns_pkt_rcode rcode)
{
	LDNS_QR_SET(ldns_buffer_begin(sv->buffer));
	LDNS_TC_CLR(ldns_buffer_begin(sv->buffer));
	LDNS_RCODE_SET(ldns_buffer_begin(sv->buffer), rcode);
}

int process_query(struct socket_service* sv, struct zones_t* zones)
{
	ldns_pkt* q = 0, *r = 0;
	ldns_status status;
	ldns_pkt_rcode rcode = LDNS_RCODE_NOERROR;

	/* if QR bit is set drop packet */
	if(ldns_buffer_limit(sv->buffer) < LDNS_HEADER_SIZE ||
		LDNS_QR_WIRE(ldns_buffer_begin(sv->buffer)))
		return 0;

	status = ldns_wire2pkt(&q, ldns_buffer_begin(sv->buffer),
		ldns_buffer_limit(sv->buffer));
	if(status != LDNS_STATUS_OK || !q) {
		/* form error */
		printf("bad packet: %s\n", ldns_get_errorstr_by_id(status));
		if(q) 
			ldns_pkt_free(q);
		set_error(sv, LDNS_RCODE_FORMERR);
		return 1;
	}
	if(1) {
		printf("Got query:\n");
		ldns_pkt_print(stdout, q);
	}
	
	r = ldns_pkt_new();
	ldns_pkt_set_id(r, ldns_pkt_id(q));
	ldns_pkt_set_qr(r, true);
	ldns_pkt_set_aa(r, true);
	ldns_pkt_set_rd(r, ldns_pkt_rd(q));

	rcode = process_pkts(sv, q, r, zones);
	
	if(rcode != LDNS_RCODE_NOERROR) {
		printf("answer error %d\n", rcode);
		ldns_pkt_free(q);
		ldns_pkt_free(r);
		set_error(sv, rcode);
		return 1;
	}

	if(sv->reply)
		fill_r_up_pkt(sv, r);

	if(1) {
		printf("Got answer %s:\n", sv->reply?"(head, more to follow)":"pkt");
		ldns_pkt_print(stdout, r);
	}

	ldns_buffer_clear(sv->buffer);
	status = ldns_pkt2buffer_wire(sv->buffer, r);
	if(status != LDNS_STATUS_OK) {
		printf("could not wireformat pkt: %s\n",
			ldns_get_errorstr_by_id(status));
		ldns_pkt_free(q);
		ldns_pkt_free(r);
		return 0;
	}
	ldns_buffer_flip(sv->buffer);

	ldns_pkt_free(q);
	ldns_pkt_free(r);
	return 1;
}

void send_udp_answer(struct socket_service* sv)
{
	ssize_t sz = sendto(sv->s, ldns_buffer_begin(sv->buffer),
		ldns_buffer_limit(sv->buffer), 0,
		(struct sockaddr*)&sv->peer, sv->peerlen);
	if(sz == -1) {
		printf("sendto: %s\n", strerror(errno));
		return;
	}
	if(sz < (int)ldns_buffer_limit(sv->buffer)) {
		printf("sendto: message not completely sent.\n");
		return;
	}
}

void write_tcp_answer(struct socket_service* sv, int* del)
{
	uint16_t len = htons(ldns_buffer_limit(sv->buffer));
	ssize_t ret;
	if(sv->bytes_done < sizeof(len)) {
		ret = write(sv->s, 
			((uint8_t*)&len) + ldns_buffer_position(sv->buffer),
			sizeof(len)-ldns_buffer_position(sv->buffer));
		if(ret == 0) {
			*del = 1;
			return;
		}
		if(ret == -1) {
			printf("write: %s\n", strerror(errno));
			*del = 1;
			return;
		}
		ldns_buffer_skip(sv->buffer, ret);
		if(ldns_buffer_position(sv->buffer) < sizeof(len))
			return; /* later */
		sv->bytes_done = sizeof(len);
		ldns_buffer_set_position(sv->buffer, 0);
	}
	ret = write(sv->s, ldns_buffer_current(sv->buffer),
		ldns_buffer_remaining(sv->buffer));
	if(ret == 0) {
		*del = 1;
		return;
	}
	if(ret == -1) {
		printf("write: %s\n", strerror(errno));
		*del = 1;
		return;
	}
	ldns_buffer_skip(sv->buffer, ret);
	if(ldns_buffer_remaining(sv->buffer) > 0)
		return; /* later */

	/* finished TCP packet, more? */
	if(sv->reply) {
		fill_r_up(sv);
		/* write that next time */
		return;
	}
	*del = 1;
	return;
}

void fill_r_up_pkt(struct socket_service* sv, ldns_pkt* in_here)
{
	size_t max = 512; /* max bytes in packet */
	size_t now = 0;
	size_t i;
	size_t added = 0;
	if(sv->is_tcp)
		max = TCP_PKT_SIZE;
	else {
		/* EDNS 0 */
	}

	if(!sv->reply)
		return;

	now = LDNS_HEADER_SIZE;
	for(i=0; i<ldns_pkt_qdcount(in_here); i++)
		now += ldns_rr_uncompressed_size(ldns_rr_list_rr(
			ldns_pkt_question(in_here), i));

	/* add until the max is reached */
	for(i=0; i<ldns_rr_list_rr_count(sv->reply); i++)
	{
		now += ldns_rr_uncompressed_size(ldns_rr_list_rr(
			sv->reply, i));
		if(now >= max) {
			/* TCP: always add one, maybe more */
			/* UDP: never cross limit. */
			if(!sv->is_tcp || added != 0)
				break;
		}
		ldns_pkt_push_rr(in_here, LDNS_SECTION_ANSWER,
			ldns_rr_list_rr(sv->reply, i));
		ldns_rr_list_set_rr(sv->reply, NULL, i);
		added++;
	}

	/* fixup the rrlist */
	memmove(sv->reply->_rrs, sv->reply->_rrs+added, 
		sizeof(ldns_rr*)*(sv->reply->_rr_count-added));
	sv->reply->_rr_count -= added;

	if(ldns_rr_list_rr_count(sv->reply) == 0) {
		ldns_rr_list_free(sv->reply);
		sv->reply = 0;
	}
	if(!sv->is_tcp && sv->reply) {
		ldns_pkt_set_tc(in_here, true);
		ldns_rr_list_deep_free(sv->reply);
		sv->reply = 0;
	}
}

void fill_r_up(struct socket_service* sv)
{
	ldns_pkt* p = ldns_pkt_new();
	ldns_status status;
	if(!p) {
		printf("out of memory\n");
		LDNS_RCODE_SET(ldns_buffer_begin(sv->buffer), 
			LDNS_RCODE_SERVFAIL);
		ldns_buffer_set_limit(sv->buffer, LDNS_HEADER_SIZE);
		ldns_rr_list_deep_free(sv->reply);
		sv->reply = 0;
		return;
	}

	ldns_buffer_clear(sv->buffer);
	ldns_pkt_set_id(p, LDNS_ID_WIRE(ldns_buffer_begin(sv->buffer)));
	ldns_pkt_set_qr(p, LDNS_QR_WIRE(ldns_buffer_begin(sv->buffer)));
	ldns_pkt_set_opcode(p, LDNS_OPCODE_WIRE(ldns_buffer_begin(sv->buffer)));
	ldns_pkt_set_aa(p, LDNS_AA_WIRE(ldns_buffer_begin(sv->buffer)));
	ldns_pkt_set_rd(p, LDNS_RD_WIRE(ldns_buffer_begin(sv->buffer)));
	ldns_pkt_set_ra(p, LDNS_RA_WIRE(ldns_buffer_begin(sv->buffer)));
	ldns_pkt_set_rcode(p, LDNS_RCODE_WIRE(ldns_buffer_begin(sv->buffer)));
	
	fill_r_up_pkt(sv, p);
	
	status = ldns_pkt2buffer_wire(sv->buffer, p);
	if(status != LDNS_STATUS_OK) {
		printf("could not wireformat continuation packet\n");
		LDNS_RCODE_SET(ldns_buffer_begin(sv->buffer), 
			LDNS_RCODE_SERVFAIL);
		ldns_buffer_set_limit(sv->buffer, LDNS_HEADER_SIZE);
		if(sv->reply) ldns_rr_list_deep_free(sv->reply);
		sv->reply = 0;
	}
	ldns_buffer_flip(sv->buffer);
}
