#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
AC_PREREQ(2.57)

AC_INIT(libdns, 1.1.0, libdns@nlnetlabs.nl, libdns)
AC_CONFIG_SRCDIR([packet.c])

PACKAGE_VERSION="$PACKAGE_VERSION $VERSION_ADD"

OURCPPFLAGS='-ansi -D_POSIX_C_SOURCE=200112 -D_XOPEN_SOURCE=600 -D__EXTENSIONS__'
CPPFLAGS=${CPPFLAGS:-${OURCPPFLAGS}}
OURCFLAGS='-g -Wall -W -Wwrite-strings'
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

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_LANG_C
AC_TYPE_SIZE_T
CHECK_COMPILER_FLAG(O2, [CFLAGS="$CFLAGS -O2"])
AC_CHECK_TYPE(int8_t, char)
AC_CHECK_TYPE(int16_t, short)
AC_CHECK_TYPE(int32_t, int)
AC_CHECK_TYPE(int64_t, long long)
AC_CHECK_TYPE(uint8_t, unsigned char)
AC_CHECK_TYPE(uint16_t, unsigned short)
AC_CHECK_TYPE(uint32_t, unsigned int)
AC_CHECK_TYPE(uint64_t, unsigned long long)

AC_DEFUN([AC_CHECK_FORMAT_ATTRIBUTE],
[AC_REQUIRE([AC_PROG_CC])
AC_MSG_CHECKING(whether the C compiler (${CC-cc}) accepts the "format" attribute)
AC_CACHE_VAL(ac_cv_c_format_attribute,
[ac_cv_c_format_attribute=no
AC_TRY_COMPILE(
[#include <stdio.h>
void f (char *format, ...) __attribute__ ((format (printf, 1, 2)));
void (*pf) (char *format, ...) __attribute__ ((format (printf, 1, 2)));
], [
   f ("%s", "str");
],
[ac_cv_c_format_attribute="yes"],
[ac_cv_c_format_attribute="no"])
])

AC_MSG_RESULT($ac_cv_c_format_attribute)
if test $ac_cv_c_format_attribute = yes; then
  AC_DEFINE(HAVE_ATTR_FORMAT, 1, [Whether the C compiler accepts the "format" attribute])
fi
])dnl

AC_DEFUN([AC_CHECK_UNUSED_ATTRIBUTE],
[AC_REQUIRE([AC_PROG_CC])
AC_MSG_CHECKING(whether the C compiler (${CC-cc}) accepts the "unused" attribute)
AC_CACHE_VAL(ac_cv_c_unused_attribute,
[ac_cv_c_unused_attribute=no
AC_TRY_COMPILE(
[#include <stdio.h>
void f (char *u __attribute__((unused)));
], [
   f ("x");
],
[ac_cv_c_unused_attribute="yes"],
[ac_cv_c_unused_attribute="no"])
])

AC_MSG_RESULT($ac_cv_c_unused_attribute)
if test $ac_cv_c_unused_attribute = yes; then
  AC_DEFINE(HAVE_ATTR_UNUSED, 1, [Whether the C compiler accepts the "unused" attribute])
fi
])dnl

# my own checks
AC_CHECK_PROG(doxygen, doxygen, doxygen)

# Checks for libraries.
# Check for SSL, original taken from
# http://www.gnu.org/software/ac-archive/htmldoc/check_ssl.html and
# modified for NSD and 
# copied again for use in ldns
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
            LDFLAGS="$LDFLAGS -L$ssldir/lib -lcrypto";
	    RUNTIME_PATH="$RUNTIME_PATH -R$ssldir/lib"
            AC_CHECK_LIB(crypto, HMAC_CTX_init,, [
                    AC_MSG_ERROR([OpenSSL found in $ssldir, but version 0.9.7 or higher is required])
                ])
        fi
        AC_SUBST(HAVE_SSL)
	AC_SUBST(RUNTIME_PATH)
    fi

# Use libtool 
# for macosx, see if glibtool exists and use that
# BSD's need to know the version...
AC_CHECK_PROG(glibtool, glibtool, [glibtool], )
AC_CHECK_PROG(libtool, libtool15, [libtool15], libtool)
AC_PATH_TOOL(AR, ar, [false])
if test $AR = false; then
	AC_MSG_ERROR([Cannot find 'ar', please extend PATH to include it])
fi
AC_PROG_LIBTOOL


# Checks for header files.
AC_HEADER_STDC
#AC_HEADER_SYS_WAIT
#AC_CHECK_HEADERS([getopt.h fcntl.h stdlib.h string.h strings.h unistd.h])
# do the very minimum - we can always extend this
AC_CHECK_HEADERS([getopt.h stdbool.h openssl/ssl.h netinet/in.h time.h],,, [AC_INCLUDES_DEFAULT])
AC_CHECK_HEADERS(sys/param.h sys/mount.h sys/socket.h,,,
[AC_INCLUDES_DEFAULT
  [
   #if HAVE_SYS_PARAM_H
   # include <sys/param.h>
   #endif
  ]
])
AC_CHECK_TYPE(socklen_t, , 
	[AC_DEFINE([socklen_t], [int], [Define to 'int' if not defined])], [
AC_INCLUDES_DEFAULT
#if HAVE_SYS_SOCKET_H
#  include <sys/socket.h>
#endif
])
AC_CHECK_TYPE(ssize_t, int)

AC_FUNC_MALLOC

AC_REPLACE_FUNCS(b64_pton)
AC_REPLACE_FUNCS(b64_ntop)
AC_REPLACE_FUNCS(b32_pton)
AC_REPLACE_FUNCS(b32_ntop)
AC_REPLACE_FUNCS(timegm)
AC_REPLACE_FUNCS(isblank)

#AC_SEARCH_LIBS(RSA_new, [crypto])

AC_CHECK_FORMAT_ATTRIBUTE
AC_CHECK_UNUSED_ATTRIBUTE

# check OSX deployment target which is needed
if echo $build_os | grep darwin > /dev/null; then
	if test x$MACOSX_DEPLOYMENT_TARGET != x10.4; then
		AC_MSG_ERROR([Please export MACOSX_DEPLOYMENT_TARGET=10.4 in your environment to compile on Mac OS/X])
	fi
fi

AC_DEFINE([SYSCONFDIR], [sysconfdir], [System configuration dir])

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
])

AH_BOTTOM([
#ifndef B64_PTON
int b64_ntop(uint8_t const *src, size_t srclength,
	     char *target, size_t targsize);
/**
 * calculates the size needed to store the result of b64_ntop
 */
/*@unused@*/
static inline size_t b64_ntop_calculate_size(size_t srcsize)
{
	return ((((srcsize + 2) / 3) * 4) + 1);
}
#endif /* !B64_PTON */
#ifndef B64_NTOP
int b64_pton(char const *src, uint8_t *target, size_t targsize);
/**
 * calculates the size needed to store the result of b64_pton
 */
/*@unused@*/
static inline size_t b64_pton_calculate_size(size_t srcsize)
{
	return ((((srcsize / 4) * 3) - 2) + 2);
}
#endif /* !B64_NTOP */

#ifndef B32_NTOP
int b32_ntop(uint8_t const *src, size_t srclength,
	     char *target, size_t targsize);
int b32_ntop_extended_hex(uint8_t const *src, size_t srclength,
	     char *target, size_t targsize);
/**
 * calculates the size needed to store the result of b32_ntop
 */
/*@unused@*/
static inline size_t b32_ntop_calculate_size(size_t srcsize)
{
	size_t result = ((((srcsize / 5) * 8) - 2) + 2);
	return result;
}
#endif /* !B32_PTON */
#ifndef B32_PTON
int b32_pton(char const *src, size_t hashed_owner_str_len, uint8_t *target, size_t targsize);
int b32_pton_extended_hex(char const *src, size_t hashed_owner_str_len, uint8_t *target, size_t targsize);
/**
 * calculates the size needed to store the result of b32_pton
 */
/*@unused@*/
static inline size_t b32_pton_calculate_size(size_t srcsize)
{
	size_t result = ((((srcsize) / 8) * 5));
	return result;
}
#endif /* !B32_NTOP */


#ifndef TIMEGM
#include <time.h>
time_t timegm (struct tm *tm);
#endif /* !TIMEGM */
#ifndef HAVE_ISBLANK
int isblank(int c);
#endif /* !HAVE_ISBLANK */
])

AC_CONFIG_FILES([Makefile ldns/util.h])
AC_CONFIG_HEADER([ldns/config.h])
AC_OUTPUT

AC_CONFIG_SUBDIRS([drill])
