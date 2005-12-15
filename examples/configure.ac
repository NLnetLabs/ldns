#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.57)
AC_INIT(libdns, 1.0.1, libdns@nlnetlabs.nl,libdns)
AC_CONFIG_SRCDIR([ldns-read-zone.c])

AC_AIX
# Checks for programs.
AC_PROG_CC
AC_PROG_MAKE_SET

AC_CHECK_HEADERS([sys/types.h getopt.h stdlib.h stdio.h assert.h netinet/in.hctype.h netinet/udp.h time.h pcap.h arpa/inet.h sys/time.h sys/socket.h],,, [AC_INCLUDES_DEFAULT])
AC_CHECK_HEADERS([netinet/in.h netinet/ip.h netinet/if_ether.h])

AC_CHECK_HEADERS([sys/param.h sys/mount.h],,,
[AC_INCLUDES_DEFAULT]
[
  [
   #if HAVE_SYS_PARAM_H
   # include <sys/param.h>
   #endif
  ]
])

# check for ldns
AC_ARG_WITH(ldns, 
	AC_HELP_STRING([--with-ldns=PATH        specify prefix of path of ldns library to use])
	,
	[
		specialldnsdir="$withval"
		CPPFLAGS="$CPPFLAGS -I$withval/include"
		LDFLAGS="$LDFLAGS -L$withval/lib"
	]
)

AC_CHECK_LIB(ldns, ldns_rr_new,, [
	AC_MSG_ERROR([Can't find ldns library])
	]
)

AC_CHECK_HEADER(ldns/dns.h,,  [
	AC_MSG_ERROR([Can't find ldns headers])
	], [AC_INCLUDES_DEFAULT]
)

AC_CHECK_LIB(pcap, pcap_open_offline,, [
	AC_MSG_ERROR([Can't find pcap library (needed for dpa)])
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

#include <netinet/in_systm.h>  

#ifdef HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif

#ifdef HAVE_NETINET_IF_ETHER_H
#include <netinet/if_ether.h>
#endif
])

AC_CONFIG_FILES([Makefile])
AC_CONFIG_HEADER([config.h])
AC_OUTPUT
