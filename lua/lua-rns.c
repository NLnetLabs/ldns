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
 */

/** MISC code found on the Internet */

/*
 luaL_checktype(lua,1,LUA_TLIGHTUSERDATA);
 QCanvasLine *line = static_cast<QCanvasLine*>(lua_touserdata(lua,1));
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
	fprintf(f, "Synopsis: %s lua-file\n", progname);
	fprintf(f, "   Useless bunch of other options\n");
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
	ldns_rr *new_rr = ldns_rr_new_frm_str(str);

	lua_pushlightuserdata(L, new_rr);
	return 1;
}

static int
l_rr_print(lua_State *L)
{
	/* we always print to stdout */
	ldns_rr *toprint = (ldns_rr*)lua_touserdata(L, 1); /* pop from the stack */
	ldns_rr_print(stdout, toprint);
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
	lua_pushlightuserdata(L, new_pkt);
	return 1;
}


static int
l_pkt_push_rr(lua_State *L)
{
	ldns_pkt *pkt = (ldns_pkt*)lua_touserdata(L, 1); /* get the packet */
	ldns_pkt_section s = lua_tonumber(L, 2); /* the section where to put it */
	ldns_rr *rr = (ldns_rr*)lua_touserdata(L, 3); /* the rr to put */

	/* this function return bool, what to do with it??? */
	ldns_pkt_push_rr(pkt, s, rr);

	lua_pushlightuserdata(L, pkt);
	return 1;
}

static int
l_pkt_get_rr(lua_State *L)
{
	ldns_pkt *p = (ldns_pkt*)lua_touserdata(L, 1); /* pop from the stack */
	unsigned int n = lua_tonumber(L, 2);
	ldns_rr *r;

	r = ldns_pkt_get_rr(p, (uint16_t) n);
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
	unsigned int n = lua_tonumber(L, 3);
	ldns_rr *r;

	r = ldns_pkt_set_rr(p, rr, (uint16_t) n);
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
============
 EXAMPLES
============
*/


/* Example test function which doesn't call ldns stuff yet */
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
	/* RRs */
	lua_register(L, "l_rr_new_frm_str", l_rr_new_frm_str);
	lua_register(L, "l_rr_print", l_rr_print);
	/* PKTs */
	lua_register(L, "l_pkt_new", l_pkt_new);
	lua_register(L, "l_pkt_push_rr", l_pkt_push_rr);
	lua_register(L, "l_pkt_print", l_pkt_print);
	lua_register(L, "l_pkt_get_rr", l_pkt_get_rr);
	lua_register(L, "l_pkt_set_rr", l_pkt_set_rr);
	lua_register(L, "l_pkt_rr_count", l_pkt_rr_count);
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

	register_ldns_functions();

        /* run the script */
        lua_dofile(L, argv[1]);

        lua_close(L);
        exit(EXIT_SUCCESS);
}
