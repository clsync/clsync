#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([clsync],[0.0],[Dmitry Yu Okunev <xai@mephi.ru>])
AC_CONFIG_SRCDIR([sync.c])
AM_INIT_AUTOMAKE([1.11 -Wall foreign])
AC_CONFIG_HEADERS([autoconfig.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET
PKG_PROG_PKG_CONFIG([0.20])

# Checks for libraries.
AC_CHECK_LIB([pthread], [pthread_create])
PKG_CHECK_MODULES(GLIB, [glib-2.0])
LIBS="${GLIB_LIBS} ${LIBS}"
AM_CPPFLAGS="${GLIB_CFLAGS} -DPARANOID"
AC_SUBST(AM_CPPFLAGS)

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
