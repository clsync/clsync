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
		AC_SEARCH_LIBS([backtrace], [execinfo], [],
			[AC_MSG_ERROR("Unable to find libexecinfo")])

		AC_CHECK_LIB(pthread, pthread_create)
		PTHREAD_LIBS=-pthread
		AC_SUBST(PTHREAD_LIBS)
		;;

	linux*)
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
	[test "x$with_capabilities" = "xyes"],
		[AC_CHECK_HEADER(
			[sys/capability.h],
			[CPPFLAGS="${CPPFLAGS} -DHAVE_CAPABILITIES"],
			[AC_MSG_ERROR("Unable to find sys/capability.h")]
		)]
)

AC_ARG_WITH(kqueue,
	AS_HELP_STRING(--with-kqueue,
		[Enable kqueue support; values: no, native, lib, check; default: check]),
	[],
	[with_kqueue=check]
)

AC_ARG_WITH(inotify,
	AS_HELP_STRING(--with-inotify,
		[Enable inotify support; values: no, native, lib, check; default: check]),
	[],
	[with_inotify=check]
)

AC_ARG_WITH(bsm,
	AS_HELP_STRING(--with-bsm,
		[Enable BSM (Sun/*BSD audit) support as FS monitor subsystem; values: no, native, check; default: check]),
	[],
	[with_inotify=check]
)

case "$with_kqueue" in
	check)
		AC_CHECK_FUNC([kqueue],
			[
				HAVE_KQUEUE=1
			],
			AC_CHECK_LIB([kqueue], [kqueue],
				[
					LDFLAGS="${LDFLAGS} -lkqueue"
					HAVE_KQUEUE=1
				],
			)
		)
		;;
	native)
		AC_CHECK_FUNC([kqueue],
			[
				HAVE_KQUEUE=1
			],
			[
				AC_MSG_FAILURE(
					[There is no kqueue native support on this system])
			]
		)
		;;
	lib)
		AC_CHECK_LIB([kqueue], [kqueue],
			[
				LDFLAGS="${LDFLAGS} -lkqueue"
				HAVE_KQUEUE=1
			],
			[
				AC_MSG_FAILURE(
					[Cannot find libkqueue])
			]
		)
		;;
esac

INOTIFY_LIBS=-linotify
case "$with_inotify" in
	check)
		AC_CHECK_FUNC([inotify_init],
			[
				HAVE_INOTIFY=1
			],
			AC_CHECK_LIB([inotify], [inotify_init],
				[
					LDFLAGS="${LDFLAGS} -linotify"
					HAVE_INOTIFY=1
				],
			)
		)
		;;
	native)
		AC_CHECK_FUNC([inotify_init],
			[
				HAVE_INOTIFY=1
			],
			[
				AC_MSG_FAILURE(
					[There is no inotify native support on this system])
			]
		)
		;;
	lib)
		AC_CHECK_LIB([inotify], [inotify_init],
			[
				LDFLAGS="${LDFLAGS} -linotify"
				HAVE_INOTIFY=1
			],
			[
				AC_MSG_FAILURE(
					[Cannot find libinotify])
			]
		)
		;;
esac

INOTIFY_LIBS=-lbsm
case "$with_bsm" in
	check)
		AC_CHECK_FUNC([au_fetch_tok],
			[
				HAVE_BSM=1
			],
			AC_CHECK_LIB([bsm], [au_fetch_tok],
				[
					LDFLAGS="${LDFLAGS} -lbsm"
					HAVE_BSM=1
				],
			)
		)
		;;
	lib)
		AC_CHECK_LIB([bsm], [au_fetch_tok],
			[
				LDFLAGS="${LDFLAGS} -lbsm"
				HAVE_BSM=1
			],
			[
				AC_MSG_FAILURE(
					[Cannot find libbsm])
			]
		)
		;;
esac

AS_IF([test "$HAVE_INOTIFY" != ""], [AC_CHECK_FUNC([inotify_init1], [], [INOTIFY_OLD=1])])

AM_CONDITIONAL([HAVE_KQUEUE],   [test "$HAVE_KQUEUE"   != ""])
AM_CONDITIONAL([HAVE_INOTIFY],  [test "$HAVE_INOTIFY"  != ""])
AM_CONDITIONAL([INOTIFY_OLD],   [test "$INOTIFY_OLD"   != ""])
AM_CONDITIONAL([HAVE_FANOTIFY], [test "$HAVE_FANOTIFY" != ""])
AM_CONDITIONAL([HAVE_BSM],      [test "$HAVE_BSM"      != ""])

AS_IF([test "$HAVE_KQUEUE" = '' -a "$HAVE_INOTIFY" = '' -a "$HAVE_FANOTIFY" = '' -a "$HAVE_BSM" = '' ], [AC_MSG_FAILURE([kqueue, inotify and bsm are not supported on this system])])

LIBS="${GLIB_LIBS} ${LIBS}"
AM_CPPFLAGS="${GLIB_CFLAGS}"
AC_SUBST(AM_CPPFLAGS)


AC_CONFIG_FILES([Makefile pkgconfig/libclsync.pc])
AC_OUTPUT
