#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.57)
AC_INIT(drill, 1.1.0, libdns@nlnetlabs.nl, drill)
AC_CONFIG_SRCDIR([drill_util.h])

OURCFLAGS='-g'
CFLAGS=${CFLAGS:-${OURCFLAGS}}

AC_AIX
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

AC_CHECK_HEADERS([getopt.h stdlib.h stdio.h assert.h netinet/in.h ctype.h time.h],,, [AC_INCLUDES_DEFAULT])
AC_CHECK_HEADERS(sys/param.h sys/mount.h,,, [AC_INCLUDES_DEFAULT]
[ 
  [
   #if HAVE_SYS_PARAM_H
   # include <sys/param.h>
   #endif
  ] 
])

AC_ARG_WITH(ssl, AC_HELP_STRING([--with-ssl=pathname],
                                    [enable SSL (will check /usr/local/ssl
                            /usr/lib/ssl /usr/ssl /usr/pkg /usr/local /usr)]),[
        ],[
            withval="yes"
        ])
    if test x_$withval != x_no; then
        AC_MSG_CHECKING(for SSL)
        if test x_$withval = x_ -o x_$withval = x_yes; then
            withval="/usr/local/ssl /usr/lib/ssl /usr/ssl /usr/pkg /usr/local /usr"
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
            AC_CHECK_LIB(crypto, HMAC_CTX_init,, [
                    AC_MSG_ERROR([OpenSSL found in $ssldir, but version 0.9.7 or higher is required])
                ])
        fi
        AC_SUBST(HAVE_SSL)
    fi

AC_CHECK_LIB(ssl, BN_bn2bin,, [
	AC_MSG_ERROR([Can't find ssl library])
	]
)

AC_ARG_WITH(ldns, AC_HELP_STRING([--with-ldns=PATHNAME],[]))

AC_CHECK_HEADER(openssl/ssl.h,,  [
	AC_MSG_ERROR([Can't find (open)ssl headers])
	], [AC_INCLUDES_DEFAULT]
)

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

# check for ldns development source tree
AC_MSG_CHECKING([for ldns devel source])
ldns_dev_dir=..
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

AC_ARG_WITH(ldns, AC_HELP_STRING([--with-ldns=PATHNAME],[]))

AC_CHECK_HEADER(ldns/ldns.h,,  [
	AC_MSG_ERROR([Can't find ldns headers (make copy-headers in devel source)])
	], [AC_INCLUDES_DEFAULT]
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

#ifdef HAVE_TIME_H
#include <time.h>
#endif
])

AC_CONFIG_FILES([Makefile
		 drill.h
                 ])
AC_CONFIG_HEADER([config.h])
AC_OUTPUT
