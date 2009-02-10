#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.56)
AC_INIT(ldns, 1.5.1, libdns@nlnetlabs.nl,libdns)
AC_CONFIG_SRCDIR([drill.c])

OURCPPFLAGS=''
CPPFLAGS=${CPPFLAGS:-${OURCPPFLAGS}}
OURCFLAGS='-g'
CFLAGS=${CFLAGS:-${OURCFLAGS}}
AC_DEFINE(WINVER, 0x0502, [the version of the windows API enabled])

AC_AIX
# Checks for programs.
AC_PROG_CC
AC_PROG_MAKE_SET
AC_CHECK_PROGS(libtool, [glibtool libtool15 libtool], [../libtool])

dnl routine to help check for compiler flags.
AC_DEFUN([CHECK_COMPILER_FLAG],
[
AC_REQUIRE([AC_PROG_CC])
AC_MSG_CHECKING(whether $CC supports -$1)
cache=`echo $1 | sed 'y% .=/+-%____p_%'`
AC_CACHE_VAL(cv_prog_cc_flag_$cache,
[
echo 'void f(){}' >conftest.c
if test -z "`$CC -$1 -c conftest.c 2>&1`"; then
eval "cv_prog_cc_flag_$cache=yes"
else
eval "cv_prog_cc_flag_$cache=no"
fi
rm -f conftest*
])
if eval "test \"`echo '$cv_prog_cc_flag_'$cache`\" = yes"; then
AC_MSG_RESULT(yes)
:
$2
else
AC_MSG_RESULT(no)
:
$3
fi
])

# add option to disable the evil rpath
dnl Check whether to use rpath or not
AC_ARG_ENABLE(rpath,
        [  --disable-rpath                disable hardcoded rpath (default=enabled)],
	enable_rpath=$enableval, enable_rpath=yes)

if test "x$enable_rpath" = xyes; then
    RPATH_VAL="-Wl,-rpath=\${libdir}"
fi


dnl routine to help check for needed compiler flags.
# if the given code compiles without the flag, execute argument 4
# if the given code only compiles with the flag, execute argument 3
# otherwise fail
AC_DEFUN([CHECK_COMPILER_FLAG_NEEDED],
[
AC_REQUIRE([AC_PROG_CC])
AC_MSG_CHECKING(whether we need -$1 as a flag for $CC)
cache=`echo $1 | sed 'y% .=/+-%____p_%'`
AC_CACHE_VAL(cv_prog_cc_flag_needed_$cache,
[
echo '$2' > conftest.c
echo 'void f(){}' >>conftest.c
if test -z "`$CC $CFLAGS -Werror -Wall -c conftest.c 2>&1`"; then
eval "cv_prog_cc_flag_needed_$cache=no"
else
[
if test -z "`$CC $CFLAGS $1 -Werror -Wall -c conftest.c 2>&1`"; then
eval "cv_prog_cc_flag_needed_$cache=yes"
fi
]
fi
rm -f conftest*
])
if eval "test \"`echo '$cv_prog_cc_flag_needed_'$cache`\" = yes"; then
AC_MSG_RESULT(yes)
:
$3
else
AC_MSG_RESULT(no)
:
$4
fi
])

CHECK_COMPILER_FLAG(std=c99, [C99FLAG="-std=c99"])
CHECK_COMPILER_FLAG(xc99, [C99FLAG="-xc99"])

AC_TYPE_SIZE_T
CHECK_COMPILER_FLAG(O2, [CFLAGS="$CFLAGS -O2"])

CHECK_COMPILER_FLAG_NEEDED($C99FLAG -D__EXTENSIONS__ -D_BSD_SOURCE -D_POSIX_C_SOURCE=200112 -D_XOPEN_SOURCE=600,
[
#include "confdefs.h"
#include <stdlib.h>
#include <ctype.h>
#include <sys/time.h>
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#include <unistd.h>
#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

int test() {
	int a;
	char **opts = NULL;
	struct timeval tv;
	char *t;
	time_t time = 0;
	char *buf = NULL;
	t = ctime_r(&time, buf);
	tv.tv_usec = 10;
	srandom(32);
	a = getopt(2, opts, "a");
	a = isascii(32);
	return a;
}
], [CFLAGS="$CFLAGS $C99FLAG -D__EXTENSIONS__ -D_BSD_SOURCE -D_POSIX_C_SOURCE=200112 -D_XOPEN_SOURCE=600"])


CHECK_COMPILER_FLAG_NEEDED($C99FLAG, [#include <stdbool.h>], [CFLAGS="$CFLAGS $C99FLAG"])

AC_C_INLINE
AC_CHECK_TYPE(int8_t, char)
AC_CHECK_TYPE(int16_t, short)
AC_CHECK_TYPE(int32_t, int)
AC_CHECK_TYPE(int64_t, long long)
AC_CHECK_TYPE(uint8_t, unsigned char)
AC_CHECK_TYPE(uint16_t, unsigned short)
AC_CHECK_TYPE(uint32_t, unsigned int)
AC_CHECK_TYPE(uint64_t, unsigned long long)
AC_CHECK_TYPE(ssize_t, int)

AC_CHECK_HEADERS([sys/types.h getopt.h stdlib.h stdio.h assert.h netinet/in.h ctype.h time.h arpa/inet.h sys/time.h sys/socket.h sys/select.h],,, [AC_INCLUDES_DEFAULT])
AC_CHECK_HEADERS([netinet/in_systm.h net/if.h netinet/ip.h netinet/udp.h netinet/if_ether.h netinet/ip6.h],,, [
AC_INCLUDES_DEFAULT 
#ifdef HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif])
# MinGW32 tests
AC_CHECK_HEADERS([winsock2.h ws2tcpip.h],,, [AC_INCLUDES_DEFAULT])

AC_CHECK_TYPE(socklen_t, , 
	[AC_DEFINE([socklen_t], [int], [Define to 'int' if not defined])], [
AC_INCLUDES_DEFAULT
#if HAVE_SYS_SOCKET_H
#  include <sys/socket.h>
#endif
])

AC_CHECK_HEADERS([sys/param.h sys/mount.h],,,
[AC_INCLUDES_DEFAULT]
[
  [
   #if HAVE_SYS_PARAM_H
   # include <sys/param.h>
   #endif
  ]
])
AC_CHECK_TYPE(in_addr_t, [], [AC_DEFINE([in_addr_t], [uint32_t], [in_addr_t])], [
#if HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#if HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif])
AC_CHECK_TYPE(in_port_t, [], [AC_DEFINE([in_port_t], [uint16_t], [in_port_t])], [
#if HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#if HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif])

# check to see if libraries are needed for these functions.
AC_CHECK_LIB(socket, socket)
AC_CHECK_LIB(nsl, inet_pton)

# Checks for libraries.
# Check for SSL, original taken from
# http://www.gnu.org/software/ac-archive/htmldoc/check_ssl.html and
# modified for NSD and 
# copied again for use in ldns
AC_ARG_WITH(ssl, AC_HELP_STRING([--with-ssl=pathname],
                                    [enable SSL (will check /usr/local/ssl
                            /usr/lib/ssl /usr/ssl /usr/pkg /usr/local /usr/sfw /usr)]),[
        ],[
            withval="yes"
    if test x_$withval != x_no; then
        AC_MSG_CHECKING(for SSL)
        if test x_$withval = x_ -o x_$withval = x_yes; then
            withval="/usr/local/ssl /usr/lib/ssl /usr/ssl /usr/pkg /usr/local /usr/sfw /usr"
        fi
        for dir in $withval; do
            ssldir="$dir"
            if test -f "$dir/include/openssl/ssl.h"; then
                found_ssl="yes";
                AC_DEFINE_UNQUOTED([HAVE_SSL], [], [Define if you have the SSL libraries installed.])
                CPPFLAGS="$CPPFLAGS -I$ssldir/include";
                break;
            fi
        done
        if test x_$found_ssl != x_yes; then
            AC_MSG_ERROR(Cannot find the SSL libraries in $withval)
        else
            AC_MSG_RESULT(found in $ssldir)
            HAVE_SSL=yes
            LDFLAGS="$LDFLAGS -L$ssldir/lib";
            if test "x$enable_rpath" = xyes; then
	        RUNTIME_PATH="$RUNTIME_PATH -R$ssldir/lib"
            fi
            AC_MSG_CHECKING([for HMAC_CTX_init in -lcrypto])
            LIBS="$LIBS -lcrypto"
            AC_TRY_LINK(, [
                int HMAC_CTX_init(void);
                (void)HMAC_CTX_init();
              ], [
                AC_MSG_RESULT(yes)
                AC_DEFINE([HAVE_HMAC_CTX_INIT], 1,
                        [If you have HMAC_CTX_init])
              ], [
                AC_MSG_RESULT(no)
                # check if -lwsock32 or -lgdi32 are needed.     
                LIBS="$LIBS -lgdi32 -lws2_32"
                AC_MSG_CHECKING([if -lcrypto needs -lgdi32])
                AC_TRY_LINK([], [
                    int HMAC_CTX_init(void);
                    (void)HMAC_CTX_init();
                  ],[
                    AC_DEFINE([HAVE_HMAC_CTX_INIT], 1,
                        [If you have HMAC_CTX_init])
                    AC_MSG_RESULT(yes)
                  ],[
                    AC_MSG_RESULT(no)
                    AC_MSG_ERROR([OpenSSL found in $ssldir, but version 0.9.7 or
 higher is required])
                ])
            ])
        fi
        AC_SUBST(HAVE_SSL)
	AC_SUBST(RUNTIME_PATH)
    fi
])

LIBS_STC="$LIBS"
AC_SUBST(LIBS_STC)

# check for ldns
AC_ARG_WITH(ldns, 
	AC_HELP_STRING([--with-ldns=PATH        specify prefix of path of ldns library to use])
	,
	[
		specialldnsdir="$withval"
		CPPFLAGS="$CPPFLAGS -I$withval/include"
		LDFLAGS="-L$withval -L$withval/lib $LDFLAGS"
		LDNSDIR="$withval"
		LIBS="-lldns $LIBS"
		LIBS_STC="$withval/lib/libldns.a $LIBS_STC"
	]
)

#AC_CHECK_HEADER(ldns/ldns.h,,  [
#	AC_MSG_ERROR([Can't find ldns headers (make copy-headers in devel source.)])
#	], [AC_INCLUDES_DEFAULT]
#)

AC_CHECK_FUNCS(isblank)

# check for ldns development source tree
AC_MSG_CHECKING([for ldns devel source])
ldns_dev_dir=..
if test -f $ldns_dev_dir/ldns/util.h && \
	grep LDNS_VERSION $ldns_dev_dir/ldns/util.h >/dev/null; then
	ldns_version=`grep LDNS_VERSION $ldns_dev_dir/ldns/util.h | sed -e 's/^.*"\(.*\)".*$/\1/'`
	AC_MSG_RESULT([using $ldns_dev_dir with $ldns_version])
	CPPFLAGS="$CPPFLAGS -I$ldns_dev_dir/include"
	LDFLAGS="-L$ldns_dev_dir -L$ldns_dev_dir/lib $LDFLAGS"
	LIBS="-lldns $LIBS"
	AC_DEFINE(HAVE_LIBLDNS, 1, [If the ldns library is available.])
	LDNSDIR="$ldns_dev_dir"
	LIBS_STC="$ldns_dev_dir/lib/libldns.a $LIBS_STC"
else
	AC_MSG_RESULT([no])
	AC_CHECK_LIB(ldns, ldns_rr_new, , [
			AC_MSG_ERROR([Can't find ldns library])
		]
	)
fi

AC_SUBST(LDNSDIR)

AH_BOTTOM([

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#if STDC_HEADERS
#include <stdlib.h>
#include <stddef.h>
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_NETINET_UDP_H
#include <netinet/udp.h>
#endif

#ifdef HAVE_TIME_H
#include <time.h>
#endif

#ifdef HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#endif

#ifdef HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif

#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif

#ifdef HAVE_NETINET_IF_ETHER_H
#include <netinet/if_ether.h>
#endif

#ifdef HAVE_WINSOCK2_H
#define USE_WINSOCK 1
#include <winsock2.h>
#endif

#ifdef HAVE_WS2TCPIP_H
#include <ws2tcpip.h>
#endif

extern char *optarg;
extern int optind, opterr;

#ifndef EXIT_FAILURE
#define EXIT_FAILURE  1
#endif
#ifndef EXIT_SUCCESS
#define EXIT_SUCCESS  0
#endif

#ifdef S_SPLINT_S
#define FD_ZERO(a) /* a */
#define FD_SET(a,b) /* a, b */
#endif
])

AC_CONFIG_FILES([Makefile
                 drill.h
                ])
AC_CONFIG_HEADER([config.h])
AC_OUTPUT
