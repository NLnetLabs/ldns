#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.57)
AC_INIT(ldns, 1.7.0, libdns@nlnetlabs.nl,libdns)
AC_CONFIG_SRCDIR([nsd-ldnsd.c])

OURCPPFLAGS='-D_POSIX_C_SOURCE=200112 -D_XOPEN_SOURCE=600 -D__EXTENSIONS__ -D__BSD_VISIBLE'
CPPFLAGS=${CPPFLAGS:-${OURCPPFLAGS}}
OURCFLAGS='-g'
CFLAGS=${CFLAGS:-${OURCFLAGS}}

AC_AIX
# Checks for programs.
AC_PROG_CC
AC_PROG_MAKE_SET

dnl routine to help check for compiler flags.
AC_DEFUN([CHECK_COMPILER_FLAG],
[
AC_REQUIRE([AC_PROG_CC])
AC_MSG_CHECKING(whether $CC supports -$1)
cache=`echo $1 | sed 'y%.=/+-%___p_%'`
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
CHECK_COMPILER_FLAG(O2, [CFLAGS="$CFLAGS -O2"])
CHECK_COMPILER_FLAG(std=c99, [CFLAGS="$CFLAGS -std=c99"], [CFLAGS="$CFLAGS -ansi"])

AC_CHECK_HEADERS([sys/types.h getopt.h stdlib.h stdio.h assert.h netinet/in.h ctype.h time.h pcap.h arpa/inet.h sys/time.h sys/socket.h],,, [AC_INCLUDES_DEFAULT])
AC_CHECK_HEADERS([netinet/in_systm.h net/if.h netinet/ip.h netinet/udp.h netinet/if_ether.h],,, [
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

AC_CHECK_HEADERS([sys/param.h sys/mount.h],,,
[AC_INCLUDES_DEFAULT]
[
  [
   #if HAVE_SYS_PARAM_H
   # include <sys/param.h>
   #endif
  ]
])

AC_CHECK_LIB(socket, socket)
AC_CHECK_LIB(nsl, inet_ntop)

# check for ldns
AC_ARG_WITH(ldns, 
	AC_HELP_STRING([--with-ldns=PATH        specify prefix of path of ldns library to use])
	,
	[
		specialldnsdir="$withval"
		CPPFLAGS="$CPPFLAGS -I$withval/include"
		LDFLAGS="$LDFLAGS -L$withval/lib"
		LDNSDIR="$withval"
	]
)

# check for ldns development source tree
AC_MSG_CHECKING([for ldns devel source])
ldns_dev_dir=../..
if test -f $ldns_dev_dir/ldns/util.h && \
	grep LDNS_VERSION $ldns_dev_dir/ldns/util.h >/dev/null; then
	ldns_version=`grep LDNS_VERSION $ldns_dev_dir/ldns/util.h | sed -e 's/^.*"\(.*\)".*$/\1/'`
	AC_MSG_RESULT([using $ldns_dev_dir with $ldns_version])
	CPPFLAGS="$CPPFLAGS -I$ldns_dev_dir/include"
	LDFLAGS="$LDFLAGS -L$ldns_dev_dir/lib"
	LIBS="$LIBS -lldns"
	AC_DEFINE(HAVE_LIBLDNS, 1, [If the ldns library is available.])
	LDNSDIR="$ldns_dev_dir"
else
	AC_MSG_RESULT([no])
	AC_CHECK_LIB(ldns, ldns_rr_new,, [
			AC_MSG_ERROR([Can't find ldns library])
		]
	)
fi

AC_SUBST(LDNSDIR)

AC_CHECK_HEADER(ldns/ldns.h,,  [
	AC_MSG_ERROR([Can't find ldns headers])
	], [AC_INCLUDES_DEFAULT]
)

AC_CHECK_LIB(pcap, pcap_open_offline,, [
	AC_MSG_WARN([Can't find pcap library (needed for ldns-dpa, will not build dpa now.)])
	]
)

AC_CHECK_FUNCS(isblank)

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

#ifdef HAVE_PCAP_H
#include <pcap.h>
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
])

AC_CONFIG_FILES([Makefile])
AC_CONFIG_HEADER([config.h])
AC_OUTPUT
