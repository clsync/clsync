#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.59])
AC_INIT([clsync],[0.0],[Dmitry Yu Okunev <xai@mephi.ru>],,[https://github.com/xaionaro/clsync])
AC_CONFIG_SRCDIR([sync.c])
AM_INIT_AUTOMAKE([1.11 -Wall foreign])
AC_CONFIG_HEADERS([autoconfig.h])


dnl --enable-debug

AC_ARG_ENABLE(debug,
AS_HELP_STRING(--enable-debug,
[enable debugging, default: no]))

AS_IF([test "x$enable_debug" = "xyes"],
[CFLAGS+="-pipe -Wall -Werror -ggdb3 -Wno-error=unused-variable"])

dnl --paranoid-level

AC_ARG_ENABLE(paranoid,
AS_HELP_STRING([--enable-paranoid],
               [set paranoid level of code security, default: 1, values: 0, 1, 2]),
[case "${enableval}" in
	0)	paranoid=0 ;;
	1)	paranoid=1 ;;
	2)	paranoid=2 ;;
	*)	AC_MSG_ERROR([bad value ${enableval} for --paranoid-level]) ;;
esac],
[paranoid=1])

AM_CONDITIONAL(PARANOID,     test x"$paranoid" = x"1")
AM_CONDITIONAL(VERYPARANOID, test x"$paranoid" = x"2")


# Checks for programs.
AC_PROG_CC_C99
AC_PROG_INSTALL
PKG_PROG_PKG_CONFIG([0.20])

# Checks for libraries.
AC_CHECK_LIB([pthread], [pthread_create])
PKG_CHECK_MODULES(GLIB, [glib-2.0])
LIBS="${GLIB_LIBS} ${LIBS}"
AM_CPPFLAGS="${GLIB_CFLAGS}"
AC_SUBST(AM_CPPFLAGS)

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
