#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.57)
AC_INIT(libdns, 0.01, libdns@nlnetlabs.nl, libdns0.01)
AC_CONFIG_SRCDIR([packet.c])

OURCPPFLAGS='-ansi -pedantic -D_POSIX_C_SOURCE=200112 -D_XOPEN_SOURCE=600'
CPPFLAGS=${CPPFLAGS:-${OURCPPFLAGS}}
OURCFLAGS='-g -O2 -Wall -W -Wwrite-strings'
CFLAGS=${CFLAGS:-${OURCFLAGS}}

AC_AIX
# Checks for programs.
AC_PROG_CC
AC_PROG_MAKE_SET

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE

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


# my own checks
AC_PATH_PROG(doxygen, doxygen, "/usr/bin/doxygen")

# Checks for libraries.

# Checks for header files.
AC_HEADER_STDC
#AC_HEADER_SYS_WAIT
#AC_CHECK_HEADERS([getopt.h fcntl.h stdlib.h string.h strings.h unistd.h])
# do the very minimum - we can always extend this
AC_CHECK_HEADERS([getopt.h stdbool.h openssl/ssl.h netinet/in.h])
AC_CHECK_HEADERS(sys/param.h sys/mount.h,,,
[
  [
   #if HAVE_SYS_PARAM_H
   # include <sys/param.h>
   #endif
  ]
])

# I don't use these
# Checks for typedefs, structures, and compiler characteristics.
#AC_TYPE_UID_T
#AC_TYPE_MODE_T
#AC_TYPE_OFF_T
#AC_TYPE_SIZE_T
#AC_STRUCT_TM

# Checks for library functions.
#AC_FUNC_CHOWN
#AC_FUNC_FORK
#AC_FUNC_MALLOC
#AC_FUNC_MKTIME
#AC_FUNC_STAT
#AC_CHECK_FUNCS([mkdir rmdir strchr strrchr strstr])

#AC_SEARCH_LIBS(RSA_new, [crypto])

dnl LIBGTOP_CHECK_TYPE
dnl Stolen from Gnome's anjuta
dnl Improved version of AC_CHECK_TYPE which takes into account
dnl that we need to #include some other header files on some
dnl systems to get some types.

dnl AC_LIBGTOP_CHECK_TYPE(TYPE, DEFAULT)
AC_DEFUN([AC_LIBGTOP_CHECK_TYPE],
[AC_REQUIRE([AC_HEADER_STDC])dnl
AC_MSG_CHECKING(for $1)
AC_CACHE_VAL(ac_cv_type_$1,
[AC_EGREP_CPP(dnl
changequote(<<,>>)dnl
<<(^|[^a-zA-Z_0-9])$1[^a-zA-Z_0-9]>>dnl
changequote([,]), [
#include <sys/types.h>
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

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif

/* For Tru64 */
#ifdef HAVE_SYS_BITYPES_H
#include <sys/bitypes.h>
#endif
], ac_cv_type_$1=yes, ac_cv_type_$1=no)])dnl
AC_MSG_RESULT($ac_cv_type_$1)
if test $ac_cv_type_$1 = no; then
  AC_DEFINE($1, $2, Define "$1" to "$2" if "$1" is missing)
fi
])

AC_LIBGTOP_CHECK_TYPE(int8_t, char) 
AC_LIBGTOP_CHECK_TYPE(int16_t, short)
AC_LIBGTOP_CHECK_TYPE(int32_t, int)
AC_LIBGTOP_CHECK_TYPE(int64_t, long long)
AC_LIBGTOP_CHECK_TYPE(uint8_t, unsigned char)
AC_LIBGTOP_CHECK_TYPE(uint16_t, unsigned short)
AC_LIBGTOP_CHECK_TYPE(uint32_t, unsigned int)
AC_LIBGTOP_CHECK_TYPE(uint64_t, unsigned long long)
AC_LIBGTOP_CHECK_TYPE(u_char, uint8_t)
AC_LIBGTOP_CHECK_TYPE(u_short, uint16_t)
AC_LIBGTOP_CHECK_TYPE(u_long, uint32_t)
AC_LIBGTOP_CHECK_TYPE(socklen_t, int)
AC_LIBGTOP_CHECK_TYPE(sig_atomic_t, int)

AC_DEFINE([SYSCONFDIR], [$sysconfdir], [System configuration dir])

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

#ifdef HAVE_ATTR_FORMAT
#define ATTR_FORMAT(archetype, string_index, first_to_check) \
    __attribute__ ((format (archetype, string_index, first_to_check)))
#else /* !HAVE_ATTR_FORMAT */
#define ATTR_FORMAT(archetype, string_index, first_to_check) /* empty */
#endif /* !HAVE_ATTR_FORMAT */

])


AC_CONFIG_FILES([Makefile 
                 ])
AC_CONFIG_HEADER([config.h])
AC_OUTPUT
