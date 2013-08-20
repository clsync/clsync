#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.59])
AC_INIT([clsync],[0.0],[Dmitry Yu Okunev <xai@mephi.ru>],,[https://github.com/xaionaro/clsync])
AC_CONFIG_SRCDIR([sync.c])
AM_INIT_AUTOMAKE([1.11 -Wall foreign])
AC_CONFIG_HEADERS([autoconfig.h])

AC_ARG_ENABLE(debug,
AS_HELP_STRING([--enable-debug],
               [enable debugging, default: no]),
[case "${enableval}" in
             yes) debug=true ;;
             no)  debug=false ;;
             *)   AC_MSG_ERROR([bad value ${enableval} for --enable-debug]) ;;
esac],
[debug=false])

AM_CONDITIONAL(DEBUG, test x"$debug" = x"true")

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET
PKG_PROG_PKG_CONFIG([0.20])

# Checks for libraries.
AC_CHECK_LIB([pthread], [pthread_create])
PKG_CHECK_MODULES(GLIB, [glib-2.0])
LIBS="${GLIB_LIBS} ${LIBS}"
AM_CPPFLAGS="${GLIB_CFLAGS}"
AC_SUBST(AM_CPPFLAGS)


# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h netinet/in.h stdint.h stdlib.h string.h strings.h sys/socket.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_MODE_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_ALLOCA
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([alarm memset mkdir realpath regcomp socket strdup strerror uname])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
