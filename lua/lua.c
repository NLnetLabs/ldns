/* 
 * Lua bindings
 *
 * (c) 2006, NLnet Labs
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <stdbool.h>

#include <stdint.h>

/* lua includes */
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

/* ldns include */
#include <ldns/ldns.h>

/* the Lua interpreter */
lua_State* L;

void
usage(FILE *f, char *progname)
{
	fprintf(f, "Synopsis: %s lua-script\n", progname);
	fprintf(f, "   No options are defined (yet)\n");
}

void
version(FILE *f, char *progname)
{
	fprintf(f, "%s version %s\n", progname, LDNS_VERSION);
}

/*
=====================================================
 Lua bindings for ldns
=====================================================
*/


/*
==========
 RDF
==========
 */
static int
l_rdf_new_frm_str(lua_State *L)
{
	uint16_t t = (uint16_t)lua_tonumber(L, 1);
	char *str = strdup((char*)luaL_checkstring(L, 2));
	if (!str) {
		return 0;
	}
	
	ldns_rdf *new_rdf = ldns_rdf_new_frm_str((ldns_rdf_type)t, str);
	if (new_rdf) {
		lua_pushlightuserdata(L, new_rdf);
		return 1;
	} else {
		return 0;
	}
}

static int
l_rdf_print(lua_State *L)
{
	/* we always print to stdout */
	ldns_rdf *toprint = (ldns_rdf*)lua_touserdata(L, 1); /* pop from the stack */
	if (!toprint) {
		return 0;
	}
	ldns_rdf_print(stdout, toprint);
	return 0;
}

static int
l_rdf_free(lua_State *L)
{
	ldns_rdf *tofree = (ldns_rdf*)lua_touserdata(L, 1); /* pop from the stack */
	if (!tofree) {
		return 0;
	}
	ldns_rdf_free(tofree);
	return 0;
}


/*
==========
 RR 
==========
*/
static int
l_rr_new_frm_str(lua_State *L)
{
	/* pop string from stack, make new rr, push rr to
	 * stack and return 1 - to signal the new pointer
	 */
	char *str = strdup((char*)luaL_checkstring(L, 1));
	uint16_t ttl = (uint16_t)lua_tonumber(L, 2);
	ldns_rdf *orig = (ldns_rdf*)lua_touserdata(L, 2);

	if (!str) {
		return 0;
	}
	
	ldns_rr *new_rr = ldns_rr_new_frm_str(str, ttl, orig);

	if (new_rr) {
		lua_pushlightuserdata(L, new_rr);
		return 1;
	} else {
		return 0;
	}
}

static int
l_rr_print(lua_State *L)
{
	/* we always print to stdout */
	ldns_rr *toprint = (ldns_rr*)lua_touserdata(L, 1); /* pop from the stack */
	if (!toprint) {
		return 0;
	}

	ldns_rr_print(stdout, toprint);
	return 0;
}

static int
l_rr_free(lua_State *L)
{
	ldns_rr *tofree = (ldns_rr*)lua_touserdata(L, 1); /* pop from the stack */
	if (!tofree) {
		return 0;
	}
	ldns_rr_free(tofree);
	return 0;
}

/*
=========
 PACKETS
=========
*/
static int
l_pkt_new(lua_State *L)
{
	ldns_pkt *new_pkt = ldns_pkt_new();
	if (new_pkt) {
		lua_pushlightuserdata(L, new_pkt);
		return 1;
	} else {
		return 0;
	}
}


static int
l_pkt_push_rr(lua_State *L)
{
	ldns_pkt *pkt = (ldns_pkt*)lua_touserdata(L, 1); /* get the packet */
	ldns_pkt_section s = (ldns_pkt_section)lua_tonumber(L, 2); /* the section where to put it */
	ldns_rr *rr = (ldns_rr*)lua_touserdata(L, 3); /* the rr to put */

	if (!pkt) {
		return 0;
	}

	if (ldns_pkt_push_rr(pkt, s, rr)) {
		lua_pushlightuserdata(L, pkt);
		return 1;
	} else {
		return 0;
	}
}

static int
l_pkt_insert_rr(lua_State *L)
{
	ldns_pkt *p = (ldns_pkt*)lua_touserdata(L, 1);
	ldns_rr *rr = (ldns_rr*)lua_touserdata(L, 2);
	uint16_t n = (uint16_t)lua_tonumber(L, 3);

	if (!p) {
		return 0;
	}

	if(ldns_pkt_insert_rr(p, rr, n)) {
		lua_pushlightuserdata(L, p);
		return 1;
	} else {
		return 0;
	}
}

static int
l_pkt_get_rr(lua_State *L)
{
	ldns_pkt *p = (ldns_pkt*)lua_touserdata(L, 1); /* pop from the stack */
	uint16_t n = (uint16_t) lua_tonumber(L, 2);
	ldns_rr *r;

	if (!p) {
		return 0;
	}

	r = ldns_pkt_get_rr(p, n);
	if (r) {
		lua_pushlightuserdata(L, r);
		return 1;
	} else {
		return 0;
	}
}

static int
l_pkt_set_rr(lua_State *L)
{
	ldns_pkt *p = (ldns_pkt*)lua_touserdata(L, 1);
	ldns_rr *rr = (ldns_rr*)lua_touserdata(L, 2);
	uint16_t n = (uint16_t)lua_tonumber(L, 3);
	ldns_rr *r;

	if (!p || !rr) {
		return 0;
	}

	r = ldns_pkt_set_rr(p, rr, n);
	if (r) {
		lua_pushlightuserdata(L, r);
		return 1;
	} else {
		return 0;
	}
}

static int
l_pkt_rr_count(lua_State *L)
{
	ldns_pkt *p = (ldns_pkt*)lua_touserdata(L, 1);
	if (!p) {
		return 0;
	}
	
	lua_pushnumber(L, ldns_pkt_section_count(p, LDNS_SECTION_ANY));
	return 1;
}

static int
l_pkt_print(lua_State *L)
{
	/* we always print to stdout */
	ldns_pkt *toprint = (ldns_pkt*)lua_touserdata(L, 1); /* pop from the stack */
	if (!toprint) {
		return 0;
	}
	ldns_pkt_print(stdout, toprint);
	return 0;
}

/*
===========
 NETWORKING
===========
 */

static int
l_server_socket_udp(lua_State *L)
{
	ldns_rdf *ip = (ldns_rdf*)lua_touserdata(L, 1); /* get the ip */
	uint16_t port = (uint16_t)lua_tonumber(L, 2); /* port number */
	struct timeval timeout;
	struct sockaddr_storage *to;
	size_t socklen;
	int sockfd;

	if (!ip || port == 0) {
		return 0;
	}

	/* use default timeout - maybe this gets to be configurable */
	timeout.tv_sec = LDNS_DEFAULT_TIMEOUT_SEC;
	timeout.tv_usec = LDNS_DEFAULT_TIMEOUT_USEC;

	/* socklen isn't really useful here */
	to = ldns_rdf2native_sockaddr_storage(ip, port, &socklen);
	if (!to) {
		return 0;
	}

	/* get the socket */
	sockfd = ldns_udp_server_connect(to, timeout);
	if (sockfd == 0) {
		return 0;
	}
	lua_pushnumber(L, (lua_Number)sockfd);
	return 1;
}

static int
l_client_socket_udp(lua_State *L)
{
	ldns_rdf *ip = (ldns_rdf*)lua_touserdata(L, 1); /* get the ip */
	uint16_t port = (uint16_t)lua_tonumber(L, 2); /* port number */
	struct timeval timeout;
	struct sockaddr_storage *to;
	size_t socklen;
	int sockfd;

	if (!ip || port == 0) {
		return 0;
	}

	/* use default timeout - maybe this gets to be configurable */
	timeout.tv_sec = LDNS_DEFAULT_TIMEOUT_SEC;
	timeout.tv_usec = LDNS_DEFAULT_TIMEOUT_USEC;

	/* socklen isn't really useful here */
	to = ldns_rdf2native_sockaddr_storage(ip, port, &socklen);
	if (!to) {
		return 0;
	}

	/* get the socket */
	sockfd = ldns_udp_connect(to, timeout);
	if (sockfd == 0) {
		return 0;
	}
	lua_pushnumber(L, (lua_Number)sockfd);
	return 1;
}

static int
l_server_socket_close_udp(lua_State *L)
{
	int sockfd = (int)lua_tonumber(L, 1);

	if (sockfd == 0) {
		return 0;
	}

	close(sockfd);
}

static int
l_write_wire_udp(lua_State *L)
{
	int sockfd = (int)lua_tonumber(L, 1);
	ldns_buffer *pktbuf = (ldns_buffer*)lua_touserdata(L, 2);
	ldns_rdf *rdf_to = (ldns_rdf*)lua_touserdata(L, 3);
	uint16_t port = (uint16_t)lua_tonumber(L, 4); /* port number */

	struct sockaddr_storage *to;
	size_t socklen;
	ssize_t bytes;

	if (!pktbuf || !rdf_to || port == 0) {
		return 0;
	}
	
	/* port number is handled in the socket */
	to = ldns_rdf2native_sockaddr_storage(rdf_to, port, &socklen);
	if (!to) {
		return 0;
	}

	bytes = ldns_udp_send_query(pktbuf, sockfd, to, (socklen_t)socklen);
	if (bytes == 0) {
		return 0;
	} else {
		lua_pushnumber(L, (lua_Number)bytes);
		return 1;
	}
}

static int
l_read_wire_udp(lua_State *L)
{
	int sockfd = (int)lua_tonumber(L, 1);
	size_t size;
	uint8_t *pktbuf_raw;
	ldns_buffer *pktbuf;
	struct sockaddr_storage *from;
	socklen_t from_len;

	if (sockfd == 0) {
		return 0;
	}
		
	from = LDNS_MALLOC(struct sockaddr_storage);
	if (!from) {
		return 0;
	}
	(void)memset(from, 0, sizeof(struct sockaddr_storage));
	from_len = sizeof(struct sockaddr_storage); /* set to predefined state */

	pktbuf = ldns_buffer_new(LDNS_MIN_BUFLEN); /* this /should/ happen in buf_new_frm_data */
	if (!pktbuf) {
		return 0;
	}
	
	pktbuf_raw = ldns_udp_read_wire(sockfd, &size, from, &from_len);

	if (!pktbuf_raw) {
		return 0;
	}
	ldns_buffer_new_frm_data(pktbuf, pktbuf_raw, size);
	
	/* push our buffer onto the stack */
	/* stack func lua cal in same order buf, from */
	lua_pushlightuserdata(L, pktbuf);
	lua_pushlightuserdata(L, from);
	return 2;
}

/* header bits */

/* read section counters */
static int
l_pkt_qdcount(lua_State *L)
{
	ldns_pkt *p = (ldns_pkt*)lua_touserdata(L, 1);
	if (!p) {
		return 0;
	}
	lua_pushnumber(L, (lua_Number)ldns_pkt_qdcount(p));
	return 1;
}

static int
l_pkt_ancount(lua_State *L)
{
	ldns_pkt *p = (ldns_pkt*)lua_touserdata(L, 1);
	if (!p) {
		return 0;
	}
	lua_pushnumber(L, (lua_Number)ldns_pkt_ancount(p));
	return 1;
}

static int
l_pkt_nscount(lua_State *L)
{
	ldns_pkt *p = (ldns_pkt*)lua_touserdata(L, 1);
	if (!p) {
		return 0;
	}
	lua_pushnumber(L, (lua_Number)ldns_pkt_nscount(p));
	return 1;
}

static int
l_pkt_arcount(lua_State *L)
{
	ldns_pkt *p = (ldns_pkt*)lua_touserdata(L, 1);
	if (!p) {
		return 0;
	}
	lua_pushnumber(L, (lua_Number)ldns_pkt_arcount(p));
	return 1;
}

static int
l_pkt_set_ancount(lua_State *L)
{
	ldns_pkt *p  = (ldns_pkt*)lua_touserdata(L, 1);
	uint16_t count = (uint16_t)lua_tonumber(L, 2);
	if (!p) {
		return 0;
	}
	(void)ldns_pkt_set_ancount(p, count);
	return 0;
}

static int
l_pkt_id(lua_State *L)
{
	ldns_pkt *p = (ldns_pkt*)lua_touserdata(L, 1);
	if (!p) {
		return 0;
	}
	lua_pushnumber(L, (lua_Number)ldns_pkt_id(p));
	return 1;
}

static int
l_pkt_set_id(lua_State *L) 
{
	ldns_pkt *p = (ldns_pkt*)lua_touserdata(L, 1);
	uint16_t id = (uint16_t)lua_tonumber(L, 2);
	if (!p) {
		return 0;
	}
	ldns_pkt_set_id(p, id);
	return 0;
}

/* BUFFERs */
static int
l_buf_free(lua_State *L)
{
	ldns_buffer *b = (ldns_buffer *)lua_touserdata(L, 1);
	if (!b) {
		return 0;
	}
	ldns_buffer_free(b);
	return 0;
}

static int
l_buf_info(lua_State *L)
{
	ldns_buffer *b = (ldns_buffer *)lua_touserdata(L, 1);
	if (!b) {
		return 0;
	}
	printf("capacity %d; position %d; limit %d\n",
			ldns_buffer_capacity(b),
			ldns_buffer_position(b),
			ldns_buffer_limit(b));
	return 0;
}

/*
============
 CONVERSION
============
*/
static int
l_buf2pkt(lua_State *L)
{
	ldns_buffer *b = (ldns_buffer *)lua_touserdata(L, 1);
	ldns_pkt *p;

	if (!b) {
		return 0;
	}

	if (ldns_buffer2pkt_wire(&p, b) != LDNS_STATUS_OK) {
		return 0;
	}
	
	lua_pushlightuserdata(L, p);
	return 1;
}

static int
l_pkt2buf(lua_State *L)
{
	ldns_pkt *p = (ldns_pkt *)lua_touserdata(L, 1);
	ldns_buffer *b;

	if (!p) {
		return 0;
	}

	b = ldns_buffer_new(LDNS_MIN_BUFLEN);

	if (ldns_pkt2buffer_wire(b, p) != LDNS_STATUS_OK) {
		ldns_buffer_free(b);
		return 0;
	}
	lua_pushlightuserdata(L, b);
	return 1;
}

static int
l_pkt2string(lua_State *L)
{
	ldns_buffer *b;
	luaL_Buffer lua_b;
	ldns_pkt *p = (ldns_pkt *)lua_touserdata(L, 1);

	if (!p) {
		return 0;
	}

	b = ldns_buffer_new(LDNS_MAX_PACKETLEN);
	luaL_buffinit(L,&lua_b);

	if (ldns_pkt2buffer_wire(b, p) != LDNS_STATUS_OK) {
		ldns_buffer_free(b);
		return 0;
	}
	/* this is a memcpy??? */
	luaL_addlstring(&lua_b,
			(char*)ldns_buffer_begin(b),
			ldns_buffer_capacity(b)
		       );
	/* I hope so */
	ldns_buffer_free(b); 

	luaL_pushresult(&lua_b);
	return 1;
}

static int
l_sockaddr_storage2rdf(lua_State *L)
{
	struct sockaddr_storage *sock;
	uint16_t port;
	ldns_rdf *addr;

	sock = lua_touserdata(L, 1);
	if (!sock) {
		return 0;
	}
	
	addr = ldns_sockaddr_storage2rdf(sock, &port);
	if (addr) {
		lua_pushlightuserdata(L, addr);
		lua_pushnumber(L, (lua_Number)port);
		return 2;
	} else {
		return 0;
	}
}

/*
============
 EXAMPLES
============
*/

static int 
l_average(lua_State *L)
{
	int n = lua_gettop(L);
	double sum = 0;
	int i;

	/* loop through each argument */
	for (i = 1; i <= n; i++)
	{
		/* total the arguments */
		sum += lua_tonumber(L, i);
	}
	lua_pushnumber(L, sum / n);
	lua_pushnumber(L, sum);
	return 2;
}

/*
=====================================================
 Lua bindings for ldns
=====================================================
*/

void
register_ldns_functions(void)
{
        /* register our functions */
        lua_register(L, "l_average", l_average);
	/* RDFs */
	static const struct luaL_reg l_rdf_lib [] = {
		{"new_frm_str", l_rdf_new_frm_str},
		{"print", 	l_rdf_print},
		{"free", 	l_rdf_free},
		{"sockaddr_to_rdf", l_sockaddr_storage2rdf},
                {NULL,          NULL}
	};
	luaL_openlib(L, "rdf", l_rdf_lib, 0);

	/* RRs */
	static const struct luaL_reg l_rr_lib [] = {
		{"new_frm_str", l_rr_new_frm_str},
		{"print", 	l_rr_print},
		{"free", 	l_rr_free},
                {NULL,          NULL}
	};
	luaL_openlib(L, "record", l_rr_lib, 0);

	/* PKTs */
	static const struct luaL_reg l_pkt_lib [] = {
                {"new",         l_pkt_new},
                {"push_rr",     l_pkt_push_rr},
                {"get_rr",      l_pkt_get_rr},
                {"set_rr",      l_pkt_set_rr},
                {"insert_rr",   l_pkt_insert_rr},
                {"print",       l_pkt_print},
                {"qdcount",     l_pkt_qdcount},
                {"ancount",     l_pkt_ancount},
                {"nscount",     l_pkt_nscount},
                {"arcount",     l_pkt_arcount},
                {"set_ancount", l_pkt_set_ancount},
#if 0
                {"set_qdcount", l_pkt_set_qdcount},
                {"set_nscount", l_pkt_set_nscount},
                {"set_arcount", l_pkt_set_arcount},
#endif
                {"rrcount",     l_pkt_rr_count},
                {"id",          l_pkt_id},
                {"set_id",      l_pkt_set_id},
                {"to_string",   l_pkt2string},
                {"to_buf",      l_pkt2buf},
                {NULL,          NULL}
	};
	luaL_openlib(L, "packet", l_pkt_lib, 0);

	/* BUFFERs */
	static const struct luaL_reg l_buf_lib [] = {
                {"to_pkt",              l_buf2pkt},
		{"free", 		l_buf_free},
		{"info", 		l_buf_info},
                {NULL,                  NULL}
        };
	luaL_openlib(L, "buffer", l_buf_lib, 0);

	/* NETWORKING */
	static const struct luaL_reg l_udpnet_lib [] = {
		{"write", 	l_write_wire_udp},
		{"read", 	l_read_wire_udp}, 
		{"server_open", 	l_server_socket_udp},
		{"open", 	l_client_socket_udp},
		{"close", 	l_server_socket_close_udp},
                {NULL,          NULL}
	};
	luaL_openlib(L, "udp", l_udpnet_lib, 0);
}

int
main(int argc, char *argv[])
{
	if (argc != 2) {
		usage(stderr, argv[0]);
		exit(EXIT_FAILURE);
	}

	if (access(argv[1], R_OK)) {
		fprintf(stderr, "File %s is unavailable.\n", argv[1]);
		exit(EXIT_FAILURE);
	}
	
        L = lua_open();
        lua_baselibopen(L);
	luaopen_math(L);
	luaopen_io(L);
	luaopen_string(L);

	register_ldns_functions();

        /* run the script */
        lua_dofile(L, argv[1]);

        lua_close(L);
        exit(EXIT_SUCCESS);
}
