#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
AC_PREREQ(2.56)

AC_INIT(ldns, 1.4.0, libdns@nlnetlabs.nl, libdns)
AC_CONFIG_SRCDIR([packet.c])
# needed to build correct soname
AC_SUBST(LIBTOOL_VERSION_INFO, "1:4:0")

PACKAGE_VERSION="$PACKAGE_VERSION"

OURCPPFLAGS=''
CPPFLAGS=${CPPFLAGS:-${OURCPPFLAGS}}
CFLAGS=

AC_AIX
# Checks for programs.
AC_PROG_CC
AC_PROG_MAKE_SET

AC_DEFINE(WINVER, 0x0502, [the version of the windows API enabled])

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

dnl routine to help check for needed compiler flags.
# if the given code compiles without the flag, execute argument 4
# if the given code only compiles with the flag, execute argument 3
# otherwise fail, execute argument 5.
AC_DEFUN([CHECK_COMPILER_FLAG_NEEDED],
[
AC_REQUIRE([AC_PROG_CC])
AC_MSG_CHECKING(whether we need $1 as a flag for $CC)
cache=`echo $1 | sed 'y%.=/+- %___p__%'`
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
else
eval "cv_prog_cc_flag_needed_$cache=fail"
#echo 'Test with flag fails too!'
#cat conftest.c
#echo "$CC $CFLAGS $1 -Werror -Wall -c conftest.c 2>&1"
#echo `$CC $CFLAGS $1 -Werror -Wall -c conftest.c`
#exit 1
fi
]
fi
rm -f conftest
])
if eval "test \"`echo '$cv_prog_cc_flag_needed_'$cache`\" = yes"; then
AC_MSG_RESULT(yes)
:
$3
else
if eval "test \"`echo '$cv_prog_cc_flag_needed_'$cache`\" = no"; then
AC_MSG_RESULT(no)
:
$4
else
AC_MSG_RESULT(failed)
:
#cat conftest.c
#echo "$CC $CFLAGS -Werror -Wall -c conftest.c"
#echo `$CC $CFLAGS -Werror -Wall -c conftest.c`
#echo "$CC $CFLAGS $1 -Werror -Wall -c conftest.c"
#echo `$CC $CFLAGS $1 -Werror -Wall -c conftest.c`
$5

fi
fi
])


# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_LANG_C
CHECK_COMPILER_FLAG(g, [CFLAGS="$CFLAGS -g"])
CHECK_COMPILER_FLAG(O2, [CFLAGS="$CFLAGS -O2"])
CHECK_COMPILER_FLAG(Wall, [CFLAGS="$CFLAGS -Wall"])
CHECK_COMPILER_FLAG(W, [CFLAGS="$CFLAGS -W"])
CHECK_COMPILER_FLAG(Wwrite-strings, [CFLAGS="$CFLAGS -Wwrite-strings"])

AC_CHECK_HEADERS([getopt.h time.h],,, [AC_INCLUDES_DEFAULT])

# MinGW32 tests
AC_CHECK_HEADERS([winsock2.h ws2tcpip.h],,, [AC_INCLUDES_DEFAULT])
# end mingw32 tests

CHECK_COMPILER_FLAG_NEEDED(-std=c99 -D__EXTENSIONS__ -D_BSD_SOURCE -D_POSIX_C_SOURCE=200112 -D_XOPEN_SOURCE=600,
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
], [CFLAGS="$CFLAGS -std=c99 -D__EXTENSIONS__ -D_BSD_SOURCE -D_POSIX_C_SOURCE=200112 -D_XOPEN_SOURCE=600"])

CHECK_COMPILER_FLAG_NEEDED(-std=c99,
[
#include <stdbool.h>
#include <ctype.h>
int test() {
	int a = 0;
	a = isblank(12);
	return a;
}
], [CFLAGS="$CFLAGS -std=c99"])

CHECK_COMPILER_FLAG_NEEDED(-D_BSD_SOURCE, 
[
#include <ctype.h>

int test() {
	int a;
	a = isascii(32);
	return a;
}
], [CFLAGS="$CFLAGS -D_BSD_SOURCE"])

CHECK_COMPILER_FLAG_NEEDED(-D_POSIX_C_SOURCE=200112, 
[
#include <time.h>

int test() {
	int a = 0;
	char *t;
	time_t time = 0;
	char *buf = NULL;
	t = ctime_r(&time, buf);
        return a;
}
], [CFLAGS="$CFLAGS -D_POSIX_C_SOURCE=200112"])

CHECK_COMPILER_FLAG_NEEDED(-D__EXTENSIONS__, 
[
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
        tv.tv_usec = 10;
        srandom(32);
#ifdef HAVE_GETOPT_H
        a = getopt(2, opts, "a");
#else
	opts = opts;
#endif
        a = isascii(32);
        return a;
}
], [CFLAGS="$CFLAGS -D__EXTENSIONS__"])

AC_C_INLINE
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

# add option to disable the evil rpath
dnl Check whether to use rpath or not
AC_ARG_ENABLE(rpath,
        [  --disable-rpath                disable hardcoded rpath (default=enabled)],
	enable_rpath=$enableval, enable_rpath=yes)

if test "x$enable_rpath" = xyes; then
    RPATH_VAL="-Wl,-rpath=\${libdir}"
fi

# Checks for libraries.
# Check for SSL, original taken from
# http://www.gnu.org/software/ac-archive/htmldoc/check_ssl.html and
# modified for NSD and 
# copied again for use in ldns
AC_ARG_WITH(ssl, AC_HELP_STRING([--with-ssl=pathname],
                                    [enable SSL (will check /usr/local/ssl
                            /usr/lib/ssl /usr/ssl /usr/pkg /usr/local /opt/local /usr/sfw /usr)]),[
        ],[
            withval="yes"
        ])
    if test x_$withval != x_no; then
        AC_MSG_CHECKING(for SSL)
        if test x_$withval = x_ -o x_$withval = x_yes; then
            withval="/usr/local/ssl /usr/lib/ssl /usr/ssl /usr/pkg /usr/local /opt/local /usr/sfw /usr"
        fi
        for dir in $withval; do
            ssldir="$dir"
            if test -f "$dir/include/openssl/ssl.h"; then
                found_ssl="yes"
                AC_DEFINE_UNQUOTED([HAVE_SSL], [], [Define if you have the SSL libraries installed.])
                CPPFLAGS="$CPPFLAGS -I$ssldir/include"
                break;
            fi
        done
        if test x_$found_ssl != x_yes; then
            AC_MSG_ERROR(Cannot find the SSL libraries in $withval)
        else
            AC_MSG_RESULT(found in $ssldir)
            HAVE_SSL=yes
            LDFLAGS="$LDFLAGS -L$ssldir/lib -lcrypto"
	    if test "x$enable_rpath" = xyes; then
	        RUNTIME_PATH="$RUNTIME_PATH -R$ssldir/lib"
	    fi
	
	    AC_MSG_CHECKING([for HMAC_CTX_init in -lcrypto])
	    ORIGLIBS="$LIBS"
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
		LIBS="$LIBS -lgdi32"
		AC_MSG_CHECKING([if -lcrypto needs -lgdi32])
		AC_TRY_LINK([], [
		    int HMAC_CTX_init(void);
		    (void)HMAC_CTX_init();
		  ],[
		    AC_DEFINE([HAVE_HMAC_CTX_INIT], 1, 
			[If you have HMAC_CTX_init])
		    AC_MSG_RESULT(yes)
		    LDFLAGS="$LDFLAGS -lgdi32" 
		  ],[
		    AC_MSG_RESULT(no)
                    AC_MSG_ERROR([OpenSSL found in $ssldir, but version 0.9.7 or higher is required])
		])
            ])
        fi
        AC_SUBST(HAVE_SSL)
	AC_SUBST(RUNTIME_PATH)
    fi
AC_CHECK_HEADERS([openssl/ssl.h],,, [AC_INCLUDES_DEFAULT])
AC_CHECK_HEADERS([openssl/err.h],,, [AC_INCLUDES_DEFAULT])
AC_CHECK_HEADERS([openssl/rand.h],,, [AC_INCLUDES_DEFAULT])

AC_ARG_ENABLE(sha2, AC_HELP_STRING([--enable-sha2], [Enable SHA256 and SHA512 RRSIG support]))
case "$enable_sha2" in
        yes)
		AC_MSG_CHECKING(for SHA256 and SHA512)
	        AC_CHECK_LIB(crypto, SHA256_Init,, [
        	        AC_MSG_ERROR([SHA2 enabled, but no SHA2 functions found in OpenSSL])
		])
                AC_DEFINE_UNQUOTED([USE_SHA2], [], [Define this to enable SHA256 and SHA512 support.])
                ;;
        no|*)
                ;;
esac

# Use libtool 
# skip these tests, we do not need them.
AC_DEFUN([AC_PROG_F77], [:])
AC_DEFUN([AC_PROG_FC], [:])
AC_DEFUN([AC_PROG_CXX], [:])
AC_DEFUN([AC_PROG_CXXCPP], [:])
AC_DEFUN([AC_PROG_OBJC], [:])
AC_DEFUN([AC_PROG_OBJCCPP], [:])
AC_DEFUN([AC_LIBTOOL_CXX], [:])
AC_DEFUN([AC_LIBTOOL_F77], [:])
# for macosx, see if glibtool exists and use that
# BSD's need to know the version...
AC_CHECK_PROG(glibtool, glibtool, [glibtool], )
AC_CHECK_PROGS(libtool, [libtool15 libtool], [./libtool])
AC_PATH_TOOL(AR, ar, [false])
if test $AR = false; then
	AC_MSG_ERROR([Cannot find 'ar', please extend PATH to include it])
fi
# avoid libtool max commandline length test on systems that fork slowly.
AC_CANONICAL_HOST
if echo "$host_os" | grep "sunos4" >/dev/null; then
	lt_cv_sys_max_cmd_len=32750;
fi
AC_PROG_LIBTOOL


# Checks for header files.
AC_HEADER_STDC
#AC_HEADER_SYS_WAIT
#AC_CHECK_HEADERS([getopt.h fcntl.h stdlib.h string.h strings.h unistd.h])
# do the very minimum - we can always extend this
AC_CHECK_HEADERS([getopt.h stdarg.h stdbool.h openssl/ssl.h netinet/in.h time.h arpa/inet.h netdb.h],,, [AC_INCLUDES_DEFAULT])
AC_CHECK_HEADERS(sys/param.h sys/mount.h,,,
[AC_INCLUDES_DEFAULT
  [
   #if HAVE_SYS_PARAM_H
   # include <sys/param.h>
   #endif
  ]
])
AC_CHECK_HEADER(sys/socket.h,
[
include_sys_socket_h='#include <sys/socket.h>'
AC_DEFINE(HAVE_SYS_SOCKET_H, 1, [define if you have sys/socket.h])
],[
include_sys_socket_h=''
],[AC_INCLUDES_DEFAULT
  [
   #if HAVE_SYS_PARAM_H
   # include <sys/param.h>
   #endif
  ]
])
AC_SUBST(include_sys_socket_h)

AC_CHECK_TYPE(socklen_t, , 
	[AC_DEFINE([socklen_t], [int], [Define to 'int' if not defined])], [
AC_INCLUDES_DEFAULT
#if HAVE_SYS_SOCKET_H
#  include <sys/socket.h>
#endif
])
AC_CHECK_TYPE(ssize_t, int)
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

AC_FUNC_MALLOC
AC_FUNC_REALLOC

AC_REPLACE_FUNCS(b64_pton)
AC_REPLACE_FUNCS(b64_ntop)
AC_REPLACE_FUNCS(b32_pton)
AC_REPLACE_FUNCS(b32_ntop)
AC_REPLACE_FUNCS(timegm)
AC_REPLACE_FUNCS(gmtime_r)
AC_REPLACE_FUNCS(ctime_r)
AC_REPLACE_FUNCS(isblank)
AC_REPLACE_FUNCS(inet_aton)
AC_REPLACE_FUNCS(inet_pton)
AC_REPLACE_FUNCS(inet_ntop)
AC_REPLACE_FUNCS(snprintf)
AC_REPLACE_FUNCS(strlcpy)
AC_REPLACE_FUNCS(memmove)
AC_CHECK_FUNCS([endprotoent endservent sleep random])

AC_DEFUN([AC_CHECK_GETADDRINFO_WITH_INCLUDES],
[AC_REQUIRE([AC_PROG_CC])
AC_MSG_CHECKING(for getaddrinfo)
AC_CACHE_VAL(ac_cv_func_getaddrinfo,
[ac_cv_func_getaddrinfo=no
AC_LINK_IFELSE( 
[
#ifdef __cplusplus
extern "C"
{
#endif
char* getaddrinfo();
char* (*f) () = getaddrinfo;
#ifdef __cplusplus
}
#endif
int main() {
	;
	return 0;
}
],
dnl this case on linux, solaris, bsd
[ac_cv_func_getaddrinfo="yes"],
dnl no quick getaddrinfo, try mingw32 and winsock2 library.
ORIGLIBS="$LIBS"
LIBS="$LIBS -lws2_32"
AC_LINK_IFELSE(
AC_LANG_PROGRAM(
[
#ifdef HAVE_WS2TCPIP_H
#include <ws2tcpip.h>
#endif
],
[
	(void)getaddrinfo(NULL, NULL, NULL, NULL);
]
), 
[ac_cv_func_getaddrinfo="yes"
LDFLAGS="$LDFLAGS -lws2_32"
],
[ac_cv_func_getaddrinfo="no" 
LIBS="$ORIGLIBS"
])
)
])

AC_MSG_RESULT($ac_cv_func_getaddrinfo)
if test $ac_cv_func_getaddrinfo = yes; then
  AC_DEFINE(HAVE_GETADDRINFO, 1, [Whether getaddrinfo is available])
fi
])dnl

AC_CHECK_GETADDRINFO_WITH_INCLUDES

if test $ac_cv_func_getaddrinfo = no; then
AC_LIBOBJ([fake-rfc2553])
fi

#AC_SEARCH_LIBS(RSA_new, [crypto])

AC_CHECK_FORMAT_ATTRIBUTE
AC_CHECK_UNUSED_ATTRIBUTE

# check OSX deployment target which is needed
if echo $build_os | grep darwin > /dev/null; then
 	export MACOSX_DEPLOYMENT_TARGET="10.4"
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

#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#endif

#ifdef HAVE_WS2TCPIP_H
#include <ws2tcpip.h>
#endif
])

AH_BOTTOM([
#ifndef B64_PTON
int ldns_b64_ntop(uint8_t const *src, size_t srclength,
	 	  char *target, size_t targsize);
/**
 * calculates the size needed to store the result of b64_ntop
 */
/*@unused@*/
static inline size_t ldns_b64_ntop_calculate_size(size_t srcsize)
{
	return ((((srcsize + 2) / 3) * 4) + 1);
}
#endif /* !B64_PTON */
#ifndef B64_NTOP
int ldns_b64_pton(char const *src, uint8_t *target, size_t targsize);
/**
 * calculates the size needed to store the result of ldns_b64_pton
 */
/*@unused@*/
static inline size_t ldns_b64_pton_calculate_size(size_t srcsize)
{
	return ((((srcsize / 4) * 3) - 2) + 2);
}
#endif /* !B64_NTOP */

#ifndef B32_NTOP
int ldns_b32_ntop(uint8_t const *src, size_t srclength,
	     char *target, size_t targsize);
int ldns_b32_ntop_extended_hex(uint8_t const *src, size_t srclength,
	     char *target, size_t targsize);
/**
 * calculates the size needed to store the result of b32_ntop
 */
/*@unused@*/
static inline size_t ldns_b32_ntop_calculate_size(size_t srcsize)
{
	size_t result = ((((srcsize / 5) * 8) - 2) + 2);
	return result;
}
#endif /* !B32_NTOP */
#ifndef B32_PTON
int ldns_b32_pton(char const *src, size_t hashed_owner_str_len, uint8_t *target, size_t targsize);
int ldns_b32_pton_extended_hex(char const *src, size_t hashed_owner_str_len, uint8_t *target, size_t targsize);
/**
 * calculates the size needed to store the result of b32_pton
 */
/*@unused@*/
static inline size_t ldns_b32_pton_calculate_size(size_t srcsize)
{
	size_t result = ((((srcsize) / 8) * 5));
	return result;
}
#endif /* !B32_PTON */

#ifndef HAVE_SLEEP
/* use windows sleep, in millisecs, instead */
#define sleep(x) Sleep((x)*1000)
#endif

#ifndef HAVE_RANDOM
#define srandom(x) srand(x)
#define random(x) rand(x)
#endif

#ifndef HAVE_TIMEGM
#include <time.h>
time_t timegm (struct tm *tm);
#endif /* !TIMEGM */
#ifndef HAVE_GMTIME_R
struct tm *gmtime_r(const time_t *timep, struct tm *result);
#endif
#ifndef HAVE_ISBLANK
int isblank(int c);
#endif /* !HAVE_ISBLANK */
#ifndef HAVE_SNPRINTF
#include <stdarg.h>
int snprintf (char *str, size_t count, const char *fmt, ...);
int vsnprintf (char *str, size_t count, const char *fmt, va_list arg);
#endif /* HAVE_SNPRINTF */
#ifndef HAVE_INET_PTON
int inet_pton(int af, const char* src, void* dst);
#endif /* HAVE_INET_PTON */
#ifndef HAVE_INET_NTOP
const char *inet_ntop(int af, const void *src, char *dst, size_t size);
#endif
#ifndef HAVE_INET_ATON
int inet_aton(const char *cp, struct in_addr *addr);
#endif
#ifndef HAVE_MEMMOVE
void *memmove(void *dest, const void *src, size_t n);
#endif
#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t siz);
#endif
#ifndef HAVE_GETADDRINFO
#include "compat/fake-rfc2553.h"
#endif
])

AC_CONFIG_FILES([Makefile ldns/net.h ldns/util.h])
AC_CONFIG_HEADER([ldns/config.h])
AC_OUTPUT

AC_CONFIG_SUBDIRS([drill])
