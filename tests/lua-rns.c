/* 
 * Lua stub to link lua to ldns
 *
 * This also exports functions for lua use
 * partely based upon:
 * http://tonyandpaige.com/tutorials/lua3.html
 *
 * (c) R. Gieben, NLnet Labs
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
 * http://lua-users.org/wiki/UserDataWithPointerExample
 * is the way to go here, as we do our own mem management
 * in ldns
 *
 * Seems pretty straitforward
 */

/* Test function which doesn't call ldns stuff yet */
static int 
lua_ldns_average(lua_State *L)
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

	/* push the average */
	lua_pushnumber(L, sum / n);

	/* push the sum */
	lua_pushnumber(L, sum);

	/* return the number of results */
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

	/* need to encap. all used functions in a
	 * still lua can understand
	 */
        lua_register(L, "lua_ldns_average", lua_ldns_average);
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

	register_ldns_functions();

        /* run the script */
        lua_dofile(L, argv[1]);

        lua_close(L);
        exit(EXIT_SUCCESS);
}
