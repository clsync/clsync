#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.59])
AC_INIT([clsync],[0.3],[Dmitry Yu Okunev <dyokunev@ut.mephi.ru>],,[https://github.com/xaionaro/clsync])
AC_CONFIG_SRCDIR([sync.c])
AM_INIT_AUTOMAKE([1.11 foreign -Wall -Wno-portability])
AC_CONFIG_HEADERS([config.h])
AM_PROG_CC_C_O
AC_PROG_CC_STDC
AC_CONFIG_MACRO_DIR([m4])

LT_INIT

AC_CANONICAL_HOST
case $host_os in
	*bsd*)
		AC_SEARCH_LIBS([inotify_init], [inotify], [],
			[AC_MSG_ERROR("Unable to find libinotify")])
		AC_SEARCH_LIBS([backtrace], [execinfo], [],
			[AC_MSG_ERROR("Unable to find libexecinfo")])

		dnl pthread
		AC_CHECK_LIB(pthread, pthread_create)
		PTHREAD_LIBS=-pthread
		AC_SUBST(PTHREAD_LIBS)
		;;

	linux*)
		dnl pthread
		AC_CHECK_LIB([pthread], [pthread_create],
			[CPPFLAGS+=" -pthread" LDFLAGS+=" -pthread"],
			[AC_MSG_ERROR("Pthread support is mandatory")])
		;;
esac

dnl --enable-clsync
AC_ARG_ENABLE(clsync,
AS_HELP_STRING(--disable-clsync,
[do not build clsync binary, default: build clsync]))
AM_CONDITIONAL([CLSYNC], [test "x$enable_clsync" != "xno"])

dnl check for glibc only if clsync is being build
AS_IF([test "x$enable_clsync" != "xno"], [
    PKG_CHECK_MODULES(GLIB,  [glib-2.0])
])

dnl --enable-cluster
AC_ARG_ENABLE(cluster,
AS_HELP_STRING(--enable-cluster,
[enable clustering support (not yet implemented), default: no]))

AS_IF([test "x$enable_cluster" = "xyes"], [CPPFLAGS="${CPPFLAGS} -DCLUSTER_SUPPORT"

	dnl mhash check
	AC_ARG_WITH(mhash,
	AS_HELP_STRING(--with-mhash,
	[use mhash instead of internal version of hash algo, default: enabled]))

	AS_IF([test "x$with_mhash" = "xno"], [], [
	AC_CHECK_HEADER([mhash.h], [], [AC_MSG_ERROR("Unable to find mhash.h")])
	AC_SEARCH_LIBS([mhash_init], [mhash], [CPPFLAGS="${CPPFLAGS} -DHAVE_MHASH"],
		[AC_MSG_ERROR("Unable to find libmhash")])
	])
])

dnl --enable-socket
AC_ARG_ENABLE(socket,
AS_HELP_STRING(--enable-socket,
[enable control socket support, default: no]))

AS_IF([test "x$enable_socket" = "xyes"],
[CPPFLAGS="${CPPFLAGS} -DENABLE_SOCKET"])

AM_CONDITIONAL([SOCKET], [test "x$enable_socket" = "xyes"])

dnl --enable-libclsync
AC_ARG_ENABLE(socket-library,
AS_HELP_STRING(--enable-socket-library,
[build libclsync socket library, default: no]))
AM_CONDITIONAL([LIBCLSYNC], [test "x$enable_socket_library" = "xyes"])

dnl --enable-debug
AC_ARG_ENABLE(debug,
AS_HELP_STRING(--enable-debug,
[enable debugging, default: no]))

AS_IF([test "x$enable_debug" = "xyes"],
[CFLAGS="${CFLAGS} -pipe -Wall -ggdb3" CPPFLAGS="${CPPFLAGS} -D_DEBUG"])

dnl --paranoid
AC_ARG_ENABLE(paranoid,
AS_HELP_STRING([--enable-paranoid],
[set paranoid level of code security, default: 1, values: 0, 1, 2]),
[case "${enableval}" in
	(0|"no")    paranoid=0 ;;
	(1|"yes")   paranoid=1 ;;
	(2)         paranoid=2 ;;
	(*)         AC_MSG_ERROR([bad value ${enableval} for --paranoid]) ;;
esac],
[paranoid=1])

AS_IF([test $paranoid -ge 1],[
CPPFLAGS="${CPPFLAGS} -D_FORTIFY_SOURCE=2 -DPARANOID"
CFLAGS="${CFLAGS} -fstack-protector-all -Wall --param ssp-buffer-size=4 -fstack-check"
LDFLAGS="${LDFLAGS} -Xlinker -zrelro"
])
AS_IF([test $paranoid -eq 2], [CPPFLAGS="${CPPFLAGS} -DVERYPARANOID"])

# Checks for programs.
AC_PROG_CC_C99
AC_PROG_INSTALL
PKG_PROG_PKG_CONFIG([0.20])

# Checks for libraries.
dnl libdl
AC_CHECK_HEADER([dlfcn.h], [], [AC_MSG_ERROR("Unable to find dlfcn.h")])
AC_SEARCH_LIBS([dlopen], [dl], [LDFLAGS="${LDFLAGS} -rdynamic"],
[AC_MSG_ERROR("Unable to find libdl")])

dnl -lrt is needed on < glibc-2.17
#AC_SEARCH_LIBS([clock_getres], [rt], [],
#    [AC_MSG_ERROR("Unable to find librt; clock_getres() is needed")])

dnl capabilities check
AC_ARG_WITH(capabilities,
AS_HELP_STRING(--with-capabilities,
[enable linux capabilities support, default: disabled]))

AS_IF(
    [test "x$with_capabilities" = "xyes"], [
        AC_CHECK_HEADER(
            [sys/capability.h],
            [CPPFLAGS="${CPPFLAGS} -DHAVE_CAPABILITIES"],
            [AC_MSG_ERROR("Unable to find sys/capability.h")])
])



LIBS="${GLIB_LIBS} ${LIBS}"
AM_CPPFLAGS="${GLIB_CFLAGS}"
AC_SUBST(AM_CPPFLAGS)


AC_CONFIG_FILES([Makefile pkgconfig/libclsync.pc])
AC_OUTPUT
