#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
AC_PREREQ(2.56)
sinclude(acx_nlnetlabs.m4)

AC_INIT(ldns, 1.6.0, libdns@nlnetlabs.nl, libdns)
AC_CONFIG_SRCDIR([packet.c])
# needed to build correct soname
AC_SUBST(LIBTOOL_VERSION_INFO, "1:6:0")

PACKAGE_VERSION="$PACKAGE_VERSION"

OURCPPFLAGS=''
CPPFLAGS=${CPPFLAGS:-${OURCPPFLAGS}}
CFLAGS="$CFLAGS"

LT_INIT
AC_CONFIG_MACRO_DIR([m4])

AC_AIX
# Checks for programs.
AC_PROG_CC
AC_PROG_MAKE_SET

AC_DEFINE(WINVER, 0x0502, [the version of the windows API enabled])

ACX_CHECK_COMPILER_FLAG(std=c99, [C99FLAG="-std=c99"])
ACX_CHECK_COMPILER_FLAG(xc99, [C99FLAG="-xc99"])

# routine to copy files
# argument 1 is a list of files (relative to the source dir)
# argument 2 is a destination directory (relative to the current
# working directory
AC_DEFUN([COPY_FILES],
[
for file in $1; do
	sh $srcdir/install-sh -m 644 $file $2
done
])

# copy all .h files in the dir at argument 1
# (relative to source) to the dir at argument 2
# (relative to current dir)
AC_DEFUN([COPY_HEADER_FILES],
[
echo "copying header files"
COPY_FILES($srcdir/$1/*.h, $2)
])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_LANG_C
ACX_CHECK_COMPILER_FLAG(g, [CFLAGS="-g $CFLAGS"])
ACX_CHECK_COMPILER_FLAG(O2, [CFLAGS="-O2 $CFLAGS"])
ACX_CHECK_COMPILER_FLAG(Wall, [CFLAGS="-Wall $CFLAGS"])
ACX_CHECK_COMPILER_FLAG(W, [CFLAGS="-W $CFLAGS"])
ACX_CHECK_COMPILER_FLAG(Wwrite-strings, [CFLAGS="-Wwrite-strings $CFLAGS"])

AC_CHECK_HEADERS([getopt.h time.h],,, [AC_INCLUDES_DEFAULT])

# MinGW32 tests
AC_CHECK_HEADERS([winsock2.h ws2tcpip.h],,, [AC_INCLUDES_DEFAULT])
# end mingw32 tests

ACX_DETERMINE_EXT_FLAGS_UNBOUND

AC_C_INLINE
AC_CHECK_TYPE(int8_t, char)
AC_CHECK_TYPE(int16_t, short)
AC_CHECK_TYPE(int32_t, int)
AC_CHECK_TYPE(int64_t, long long)
AC_CHECK_TYPE(uint8_t, unsigned char)
AC_CHECK_TYPE(uint16_t, unsigned short)
AC_CHECK_TYPE(uint32_t, unsigned int)
AC_CHECK_TYPE(uint64_t, unsigned long long)


# my own checks
AC_CHECK_PROG(doxygen, doxygen, doxygen)

AC_ARG_ENABLE(sha2, AC_HELP_STRING([--enable-sha2], [Enable SHA256 and SHA512 RRSIG support]))
case "$enable_sha2" in
    yes)
        AC_MSG_CHECKING(for SHA256 and SHA512)
        AC_CHECK_LIB(crypto, SHA256_Init,, [
            AC_MSG_ERROR([SHA2 enabled, but no SHA2 functions found in OpenSSL])
        ])
        AC_DEFINE_UNQUOTED([USE_SHA2], [1], [Define this to enable SHA256 and SHA512 support.])
        ;;
    no|*)
        ;;
esac

# add option to disable installation of ldns-config script
AC_ARG_ENABLE(ldns-config, [ --disable-ldns-config          disable installation of ldns-config (default=enabled)],
	enable_ldns_config=$enableval, enable_ldns_config=yes)
if test "x$enable_ldns_config" = xyes; then
	INSTALL_LDNS_CONFIG="yes"
else
	INSTALL_LDNS_CONFIG="no"
fi
AC_SUBST(INSTALL_LDNS_CONFIG)

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
                AC_SUBST(HAVE_SSL)
                CPPFLAGS="$CPPFLAGS -I$ssldir/include"
                break;
            fi
        done
        if test x_$found_ssl != x_yes; then
            AC_MSG_ERROR(Cannot find the SSL libraries in $withval)
        else
            AC_MSG_RESULT(found in $ssldir)
            HAVE_SSL=yes
            AC_SUBST(HAVE_SSL)
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
	AC_SUBST(RUNTIME_PATH)
    fi
AC_CHECK_HEADERS([openssl/ssl.h],,, [AC_INCLUDES_DEFAULT])
AC_CHECK_HEADERS([openssl/err.h],,, [AC_INCLUDES_DEFAULT])
AC_CHECK_HEADERS([openssl/rand.h],,, [AC_INCLUDES_DEFAULT])

# Use libtool 
ACX_LIBTOOL_C_ONLY

# for macosx, see if glibtool exists and use that
# BSD's need to know the version...
#AC_CHECK_PROG(glibtool, glibtool, [glibtool], )
#AC_CHECK_PROGS(libtool, [libtool15 libtool], [./libtool])

#AC_TRY_RUN(
#[
#int main()
#{
#short one = 1;
#char *cp = (char*)&one;
#if ( *cp == 0 )
#return(0);
#else
#return(1);
#}
#], [],[
#AC_DEFINE(CONFCHECK_LITTLE_ENDIAN, 1, [system appears to be little-endian])
#],[])

# should define WORDS_BIGENDIAN if the system is big-endian
AC_C_BIGENDIAN


AC_OUTPUT()

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
AC_CHECK_HEADER(inttypes.h,
[
include_inttypes_h='#include <inttypes.h>'
AC_DEFINE(HAVE_INTTYPES_H, 1, [define if you have inttypes.h])
],[
include_inttypes_h=''
],[AC_INCLUDES_DEFAULT
])
AC_SUBST(include_inttypes_h)

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

ACX_CHECK_FORMAT_ATTRIBUTE
ACX_CHECK_UNUSED_ATTRIBUTE

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

#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN 1234
#endif

#ifndef BIG_ENDIAN
#define BIG_ENDIAN 4321
#endif

#ifndef BYTE_ORDER
#ifdef WORDS_BIGENDIAN
#define BYTE_ORDER BIG_ENDIAN
#else
#define BYTE_ORDER LITTLE_ENDIAN
#endif /* WORDS_BIGENDIAN */
#endif /* BYTE_ORDER */

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

AC_CONFIG_FILES([Makefile ldns/net.h ldns/util.h packaging/libldns.pc packaging/ldns-config])

AC_CONFIG_HEADER([ldns/config.h])
AC_OUTPUT
COPY_HEADER_FILES(ldns/, ldns/)

AC_CONFIG_SUBDIRS([drill])
