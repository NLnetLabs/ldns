#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.57)
AC_INIT(libdns, 0.01, libdns@nlnetlabs.nl, libdns0.01)
AC_CONFIG_SRCDIR([prototype.h])

AC_AIX
# Checks for programs.
AC_PROG_CC
AC_PROG_MAKE_SET

# check for compiler capabilities
#AC_MSG_CHECKING(for flexible array members)
#AC_TRY_COMPILE([struct test { int i; int data[]; }; ], [],
#		AC_MSG_RESULT(yes),
#		[AC_MSG_RESULT(no)
#			AC_MSG_ERROR(Please use gcc >= 3 or another compiler with flexible array members)
#		]
#)

# my own checks
AC_PATH_PROG(doxygen, doxygen, "/usr/bin/doxygen")

# Checks for libraries.

# Checks for header files.
#AC_HEADER_STDC
#AC_HEADER_SYS_WAIT
#AC_CHECK_HEADERS([getopt.h fcntl.h stdlib.h string.h strings.h unistd.h])
# do the very minimum - we can always extend this
AC_CHECK_HEADERS([getopt.h stdlib.h stdio.h openssl/ssl.h assert.h netinet/in.hctype.h])
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

AC_SEARCH_LIBS(RSA_new, [crypto])

AC_DEFINE_UNQUOTED(SYSCONFDIR, "$sysconfdir")

AC_CONFIG_FILES([Makefile
		 prototype.h
                 ])
AC_CONFIG_HEADER([common.h])
AC_OUTPUT
