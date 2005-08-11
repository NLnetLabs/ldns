/* 
 * Lua stub to link lua to ldns
 *
 * This also exports functions for lua use
 * partely based upon:
 * http://tonyandpaige.com/tutorials/lua3.html
 *
 * (c) R. Gieben, NLnet Labs
 */

/****
 * BIG TODO error handling and checking from the lua 
 * side
 *
 * Can't use doxygen, because everything goes through
 * lua_State's stack
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <stdbool.h>

#include <stdint.h>

/* lua includes */
#include "lua50/lua.h"
#include "lua50/lualib.h"
#include "lua50/lauxlib.h"

/* ldns include */
#include <ldns/dns.h>

/* the Lua interpreter */
lua_State* L;

char *VERSION = "lua-rns 0.1";

void
usage(FILE *f, char *progname)
{
	fprintf(f, "Synopsis: %s lua-script\n", progname);
	fprintf(f, "   No options are defined (yet)\n");
}

void
version(FILE *f, char *progname)
{
	fprintf(f, "%s version %s\n", progname, VERSION);
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
l_rdf_new_frm_str(lua_State *L)
{
	uint16_t t = lua_tonumber(L, 1);
	char *str = strdup((char*)luaL_checkstring(L, 2));

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
	ldns_rdf_print(stdout, toprint);
	return 0;
}

static int
l_rdf_free(lua_State *L)
{
	ldns_rdf *tofree = (ldns_rdf*)lua_touserdata(L, 1); /* pop from the stack */
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
	ldns_rr_print(stdout, toprint);
	return 0;
}

static int
l_rr_free(lua_State *L)
{
	ldns_rr *tofree = (ldns_rr*)lua_touserdata(L, 1); /* pop from the stack */
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
	ldns_pkt_section s = lua_tonumber(L, 2); /* the section where to put it */
	ldns_rr *rr = (ldns_rr*)lua_touserdata(L, 3); /* the rr to put */

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
	unsigned int n = lua_tonumber(L, 3);

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
	uint16_t n = lua_tonumber(L, 2);
	ldns_rr *r;

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
	uint16_t n = lua_tonumber(L, 3);
	ldns_rr *r;

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
	lua_pushnumber(L, ldns_pkt_section_count(p, LDNS_SECTION_ANY));
	return 1;
}

static int
l_pkt_print(lua_State *L)
{
	/* we always print to stdout */
	ldns_pkt *toprint = (ldns_pkt*)lua_touserdata(L, 1); /* pop from the stack */
	ldns_pkt_print(stdout, toprint);
	return 0;
}

/*
===========
 NETWORKIBG
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

	/* use default timeout - maybe this gets to be configureable */
	timeout.tv_sec = LDNS_DEFAULT_TIMEOUT_SEC;
	timeout.tv_usec = LDNS_DEFAULT_TIMEOUT_USEC;

	/* socklen isn't really usefull here */
	to = ldns_rdf2native_sockaddr_storage(ip, port, &socklen);
	if (!to) {
		return 0;
	}

	/* get the socket */
	sockfd = ldns_udp_server_connect(to, timeout);
	if (sockfd == 0) {
		return 0;
	}
	lua_pushnumber(L, sockfd);
	return 1;
}

static int
l_server_socket_close_udp(lua_State *L)
{
	int sockfd = (int)lua_tonumber(L, 1);

	close(sockfd);
}

static int
l_write_wire_udp(lua_State *L)
{
	int sockfd = (int)lua_tonumber(L, 1);
	ldns_buffer *pktbuf = (ldns_buffer*) lua_touserdata(L, 2);
	ldns_rdf *rdf_to = (ldns_rdf*)lua_touserdata(L, 2);
	uint16_t port = (uint16_t)lua_tonumber(L, 3); /* port number */

	struct sockaddr_storage *to;
	size_t socklen;
	ssize_t bytes;
	
	/* port number is handled in the socket */
	to = ldns_rdf2native_sockaddr_storage(rdf_to, port, &socklen);
	if (!to) {
		return 0;
	}

	bytes = ldns_udp_send_query(pktbuf, sockfd, to, (socklen_t)socklen);
	if (bytes == 0) {
		return 0;
	} else {
		lua_pushnumber(L, bytes);
		return 1;
	}
}

static int
l_read_wire_udp(lua_State *L)
{
	int sockfd = (int)lua_tonumber(L, 1);
	size_t size;
	uint8_t *pktbuf_raw;
	ldns_pkt *pkt;
	ldns_buffer *pktbuf;

	pktbuf_raw = ldns_udp_read_wire(sockfd, &size);

	if (!pktbuf_raw) {
		printf("[debug] nothing allright\n");
		return 0;
	}
	ldns_buffer_new_frm_data(pktbuf, pktbuf_raw, size);

	LDNS_FREE(pktbuf_raw);
	
	/* push our buffer onto the stack */
	printf("[debug] I've read %d bytes\n", size);
	printf("[debug] buffer cap %d bytes\n", ldns_buffer_capacity(pktbuf));
	lua_pushlightuserdata(L, pktbuf);
	return 1;
}

/* header bits */

/* read section counters */
static int
l_pkt_qdcount(lua_State *L)
{
	ldns_pkt *p = (ldns_pkt*)lua_touserdata(L, 1);
	lua_pushnumber(L, ldns_pkt_qdcount(p));
	return 1;
}

static int
l_pkt_ancount(lua_State *L)
{
	ldns_pkt *p = (ldns_pkt*)lua_touserdata(L, 1);
	lua_pushnumber(L, ldns_pkt_ancount(p));
	return 1;
}

static int
l_pkt_nscount(lua_State *L)
{
	ldns_pkt *p = (ldns_pkt*)lua_touserdata(L, 1);
	lua_pushnumber(L, ldns_pkt_nscount(p));
	return 1;
}

static int
l_pkt_arcount(lua_State *L)
{
	ldns_pkt *p = (ldns_pkt*)lua_touserdata(L, 1);
	lua_pushnumber(L, ldns_pkt_arcount(p));
	return 1;
}

static int
l_pkt_set_qdcount(lua_State *L)
{
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
		printf("[debug] conversion buf2pkt sour\n");
		return 0;
	}
	printf("[debug] conversion buf2pkt ok\n");
	
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

	/* resize! XXX */
	b = ldns_buffer_new(LDNS_MAX_PACKETLEN);
	if (ldns_pkt2buffer_wire(b, p) != LDNS_STATUS_OK) {
		return 0;
	}
	/* resize to current usage */
	printf("[debug] usage buffer %d\n", ldns_buffer_position(b));
	ldns_buffer_reserve(b, (size_t)
			ldns_buffer_position(b));
	lua_pushlightuserdata(L, b);
	return 1;
}


static int
l_pkt2string(lua_State *L)
{
	ldns_buffer *b;
	luaL_Buffer lua_b;
	ldns_pkt *p = (ldns_pkt *)lua_touserdata(L, 1);

	b = ldns_buffer_new(LDNS_MAX_PACKETLEN);
	luaL_buffinit(L,&lua_b);

	if (ldns_pkt2buffer_wire(b, p) != LDNS_STATUS_OK) {
		ldns_buffer_free(b);
		return 0;
	}
	/* this is a memcpy??? */
	luaL_addlstring(&lua_b,
			ldns_buffer_begin(b),
			ldns_buffer_capacity(b)
		       );
	/* I hope so */
	ldns_buffer_free(b); 

	luaL_pushresult(&lua_b);
	return 1;
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
	lua_register(L, "l_rdf_new_frm_str", l_rdf_new_frm_str);
	lua_register(L, "l_rdf_print", l_rdf_print);
	lua_register(L, "l_rdf_free", l_rdf_free);
	/* RRs */
	lua_register(L, "l_rr_new_frm_str", l_rr_new_frm_str);
	lua_register(L, "l_rr_print", l_rr_print);
	lua_register(L, "l_rr_free", l_rr_free);
	/* PKTs */
	lua_register(L, "l_pkt_new", l_pkt_new);
	lua_register(L, "l_pkt_push_rr", l_pkt_push_rr);
	lua_register(L, "l_pkt_print", l_pkt_print);
	lua_register(L, "l_pkt_get_rr", l_pkt_get_rr);
	lua_register(L, "l_pkt_set_rr", l_pkt_set_rr);
	lua_register(L, "l_pkt_rr_count", l_pkt_rr_count);
	lua_register(L, "l_pkt_insert_rr", l_pkt_insert_rr);

	lua_register(L, "l_pkt_qdcount", l_pkt_qdcount);
	lua_register(L, "l_pkt_ancount", l_pkt_ancount);
	lua_register(L, "l_pkt_nscount", l_pkt_nscount);
	lua_register(L, "l_pkt_nscount", l_pkt_nscount);
	
	/* CONVERSIONs */
	lua_register(L, "l_pkt2string", l_pkt2string);
	lua_register(L, "l_buf2pkt", l_buf2pkt);
	lua_register(L, "l_pkt2buf", l_pkt2buf);

	/* NETWORKING */
	lua_register(L, "l_write_wire_udp", l_write_wire_udp);
	lua_register(L, "l_read_wire_udp", l_read_wire_udp);
	lua_register(L, "l_server_socket_udp", l_server_socket_udp);
	lua_register(L, "l_server_socket_close_udp", l_server_socket_close_udp);
	
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
