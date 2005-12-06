#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.57)
AC_INIT(drill, 1.0.1, libdns@nlnetlabs.nl, drill)
AC_CONFIG_SRCDIR([drill_util.h])

AC_AIX
AC_PROG_CC
AC_PROG_MAKE_SET

AC_CHECK_HEADERS([getopt.h stdlib.h stdio.h assert.h netinet/in.hctype.h time.h],,, [AC_INCLUDES_DEFAULT])
AC_CHECK_HEADERS(sys/param.h sys/mount.h,,, [AC_INCLUDES_DEFAULT]
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

AC_ARG_WITH(ldns, AC_HELP_STRING([--with-ldns=PATHNAME],[]))

AC_CHECK_HEADER(ldns/dns.h,,  [
	AC_MSG_ERROR([Can't find ldns headers])
	], [AC_INCLUDES_DEFAULT]
)

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

#ifdef HAVE_TIME_H
#include <time.h>
#endif
])

AC_CONFIG_FILES([Makefile
		 drill.h
                 ])
AC_CONFIG_HEADER([config.h])
AC_OUTPUT
