#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.59])
AC_INIT([clsync],[0.4.4],[Dmitry Yu Okunev <xaionaro@gmail.com>],,[https://github.com/clsync/clsync])
AC_CONFIG_SRCDIR([sync.c])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([1.11 foreign -Wall -Wno-portability])
AC_CONFIG_HEADERS([config.h])
AC_PROG_CC([gcc cc])
AM_PROG_CC_C_O
AC_PROG_CC_STDC
AC_CONFIG_MACRO_DIR([m4])
AC_PROG_LIBTOOL
AM_PROG_LIBTOOL

LT_INIT

PKG_INSTALLDIR

AC_CANONICAL_HOST

m4_include(m4/ax_pthread.m4)
AX_PTHREAD(
	[
		CC="$PTHREAD_CC"
		LIBS="$LIBS $PTHREAD_LIBS"
		CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
		LDFLAGS="$LDFLAGS $PTHREAD_LDFLAGS"
	], [
		AC_MSG_ERROR([Pthread library not found. Please set PTHREAD_CFLAGS and PTHREAD_LIBS correctly for your setup])
	]
)


case $host_os in
	*bsd*)
		AC_SEARCH_LIBS([backtrace], [execinfo], [HAVE_BACKTRACE=1])
		;;
	*)
		AC_CHECK_HEADER([execinfo.h], [HAVE_BACKTRACE=1])
		;;
esac

case $host_os in
	*musl*)
		# musl uses stand-alone fts implementation
		LDFLAGS="${LDFLAGS} -lfts"
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
	HAVE_CLUSTER=1
	dnl mhash check
	AC_ARG_WITH(mhash,
	AS_HELP_STRING(--with-mhash,
	[use mhash instead of internal version of hash algo, default: enabled]))

	AS_IF([test "x$with_mhash" = "xno"], [], [
	AC_CHECK_HEADER([mhash.h], [], [AC_MSG_ERROR("Unable to find mhash.h")])
	AC_SEARCH_LIBS([mhash_init], [mhash], [CPPFLAGS="${CPPFLAGS} -DHAVE_MHASH"; LDFLAGS="${LDFLAGS} -lmhash"],
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

dnl --enable-unshare
AC_ARG_ENABLE(unshare,
AS_HELP_STRING(--disable-unshare,
[disable support of unshare(), default: enabled]))

AS_IF([ test "x$enable_unshare" != "xno" ],
[
    AC_CHECK_FUNC([unshare], [HAVE_UNSHARE=1])
])

dnl --enable-highload-locks
AC_ARG_ENABLE(highload-locks,
AS_HELP_STRING(--disable-highload-locks,
[disable locks for high loaded instances with --splitting={thread,process} [which are not enough tested and can cause deadlocks with 100% CPU utilization]]))
AM_CONDITIONAL([HLLOCKS], [test "x$enable_highload_locks" != "xno"])

dnl --enable-debug
AC_ARG_ENABLE(debug,
AS_HELP_STRING(--enable-debug,
[enable debugging support, default: yes; value: no, yes, force]),
[case "${enableval}" in
	(0|"no")    debug=0 ;;
	(1|"yes")   debug=1 ;;
	(2|"force") debug=2 ;;
	(*)         AC_MSG_ERROR([bad value ${enableval} for --enable-debug]) ;;
esac],
[debug=1])

AS_IF([ test "$debug" -ge 1 ],
[CFLAGS="${CFLAGS} -pipe -Wall" CPPFLAGS="${CPPFLAGS} -D_DEBUG_SUPPORT"])

AS_IF([ test "$debug" -ge 2 ],
[CFLAGS="${CFLAGS} -Wextra -pedantic -O0 -ggdb3" CPPFLAGS="${CPPFLAGS} -D_DEBUG_FORCE"])

dnl --paranoid
AC_ARG_ENABLE(paranoid,
AS_HELP_STRING([--enable-paranoid],
[set paranoid level of code security, default: 1, values: 0, 1, 2]),
[case "${enableval}" in
	(0|"no")    paranoid=0 ;;
	(1|"yes")   paranoid=1 ;;
	(2)         paranoid=2 ;;
	(*)         AC_MSG_ERROR([bad value ${enableval} for --enable-paranoid]) ;;
esac],
[paranoid=1])

AS_IF(
	[test $paranoid -ge 1],
	[
		CPPFLAGS="${CPPFLAGS} -D_FORTIFY_SOURCE=2 -DPARANOID"
		CFLAGS="${CFLAGS} -fstack-protector-all -Wall --param ssp-buffer-size=4"
		LDFLAGS="${LDFLAGS} -Xlinker -zrelro"
		AX_CHECK_COMPILE_FLAG([-fstack-check], [CFLAGS="${CFLAGS} -fstack-check"])
	]
)
AS_IF([test $paranoid -eq 2], [CPPFLAGS="${CPPFLAGS} -DVERYPARANOID"])

dnl capabilities check
AC_ARG_ENABLE(capabilities,
	AS_HELP_STRING(--enable-capabilities,
		[Enable linux capabilities support; values: no, check, yes; default: check]),
	,
	[enable_capabilities=check]
)

case "$enable_capabilities" in
	yes)
		AC_CHECK_FUNC([capset],
			[
				AC_CHECK_HEADER(sys/capability.h, [HAVE_CAPABILITIES=2], [AC_MSG_FAILURE([Cannot find sys/capability.h])])
			],
			[
				AC_MSG_FAILURE([There is no capabilities support on this system])
			]
		)
		;;
	check)
		AC_CHECK_FUNC([capset],
			[
				AC_CHECK_HEADER(sys/capability.h, [HAVE_CAPABILITIES=2])
			]
		)
		;;
esac

dnl searching for seccomp
AC_ARG_ENABLE(seccomp,
	AS_HELP_STRING(--enable-seccomp,
		[Enable seccomp support be able to forbid extra syscalls (requires capabilities); values: no, check, yes; default: check]),
	,
	[enable_seccomp=check]
)

case "$enable_seccomp" in
	yes)
		AS_IF([test "$HAVE_CAPABILITIES" = ''], [AC_MSG_ERROR([Seccomp needs capabilities to be enabled])])
		AC_CHECK_TYPES([struct seccomp_data], [HAVE_SECCOMP=1], [AC_MSG_FAILURE([Cannot find valid linux/seccomp.h])], [[#include <linux/seccomp.h>]])
		;;
	check)
		AS_IF([test "$HAVE_CAPABILITIES" != ''], [
		AC_CHECK_TYPES([struct seccomp_data], [HAVE_SECCOMP=1], ,                                                      [[#include <linux/seccomp.h>]])
		])
		;;
esac

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
AC_SEARCH_LIBS([clock_getres], [rt], [],
    [AC_MSG_ERROR("Unable to find librt; clock_getres() is needed")])

dnl searching for getmntent
AC_CHECK_FUNC([getmntent], [HAVE_GETMNTENT=1])

dnl searching for pivot_root
AC_CHECK_FUNC([pivot_root], [HAVE_PIVOTROOT=1])

dnl searching for pthread_timedjoin_np
AC_CHECK_FUNC([pthread_timedjoin_np], [HAVE_PTHREAD_TIMEDJOIN_NP=1])

dnl libcgroup check
AC_ARG_WITH(libcgroup,
	AS_HELP_STRING(--with-libcgroup,
		[Enable cgroup support via libcgroup; values: no, check, yes; default: check]),
	,
	[with_libcgroup=check]
)

case "$with_libcgroup" in
	yes)

		AC_CHECK_LIB([cgroup], [cgroup_init],
			[
				AC_CHECK_HEADER(libcgroup.h, [], [AC_MSG_FAILURE([Cannot find libcgroup.h])])
				LDFLAGS="${LDFLAGS} -lcgroup"
				HAVE_LIBCGROUP=1
			],
			[
				AC_MSG_FAILURE(
					[Cannot find libcgroup])
			]
		)
		;;
	check)
		AC_CHECK_LIB([cgroup], [cgroup_init],
			[
				AC_CHECK_HEADER(libcgroup.h, [], [AC_MSG_FAILURE([Cannot find libcgroup.h])])
				LDFLAGS="${LDFLAGS} -lcgroup"
				HAVE_LIBCGROUP=1
			]
		)
		;;
esac

dnl tre check

#AC_ARG_WITH(tre,
#	AS_HELP_STRING(--with-tre,
#		[Enable tre support be able to predict which directories should be scanned for excludes; values: no, check, yes; default: check]),
#	[],
#	[with_tre=check]
#)
#
#case "$with_tre" in
#	yes)
#		AC_CHECK_LIB([tre], [tre_regaexec],
#			[
#				AC_CHECK_HEADER(tre/tre.h, [], [AC_MSG_FAILURE([Cannot find tre/tre.h])])
#				LDFLAGS="${LDFLAGS} -ltre"
#				HAVE_TRE=1
#			],
#			[
#				AC_MSG_FAILURE(
#					[Cannot find libtre])
#			]
#		)
#		;;
#	check)
#		AC_CHECK_LIB([tre], [tre_regaexec],
#			[
#				AC_CHECK_HEADER(tre/tre.h, [], [AC_MSG_FAILURE([Cannot find tre/tre.h])])
#				LDFLAGS="${LDFLAGS} -ltre"
#				HAVE_TRE=1
#			],
#			[]
#		)
#		;;
#esac

dnl kqueue/inotify/gio/bsm

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

AC_ARG_WITH(gio,
	AS_HELP_STRING(--with-gio,
		[Enable GIO support as FS monitor subsystem; values: no, lib, check; default: check]),
	[],
	[with_gio=check]
)

AC_ARG_WITH(bsm,
	AS_HELP_STRING(--with-bsm,
		[Enable BSM (Sun/*BSD audit) support as FS monitor subsystem; values: no, lib, check; default: check]),
	[],
	[with_bsm=check]
)

case "$with_kqueue" in
	check)
		AC_CHECK_FUNC([kqueue],
			[
				HAVE_KQUEUE=2
			],
			[
				AC_CHECK_LIB([kqueue], [kqueue],
					[
						AC_CHECK_HEADER(sys/event.h, [
							LDFLAGS="${LDFLAGS} -lkqueue"
							HAVE_KQUEUE=1
						])
					]
				)
			]
		)
		;;
	native)
		AC_CHECK_FUNC([kqueue],
			[
				AC_CHECK_HEADER(sys/event.h, , [AC_MSG_FAILURE([Cannot find sys/event.h])])
				HAVE_KQUEUE=2
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
				AC_CHECK_HEADER(sys/event.h, , [AC_MSG_FAILURE([Cannot find sys/event.h])])
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

case "$with_inotify" in
	check)
		AC_CHECK_FUNC([inotify_init],
			[
				HAVE_INOTIFY=2
			],
			[
				AC_CHECK_LIB([inotify], [inotify_init],
					[
						AC_CHECK_HEADER(sys/inotify.h, [
							LDFLAGS="${LDFLAGS} -linotify"
							HAVE_INOTIFY=1
						])
					]
				)
			]
		)
		;;
	native)
		AC_CHECK_FUNC([inotify_init],
			[
				AC_CHECK_HEADER(sys/inotify.h, [], [AC_MSG_FAILURE([Cannot find sys/inotify.h])])
				HAVE_INOTIFY=2
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
				AC_CHECK_HEADER(sys/inotify.h, [], [AC_MSG_FAILURE([Cannot find sys/inotify.h])])
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

case "$with_gio" in
	check)
		PKG_CHECK_MODULES(GIO,  [gio-2.0], [
			HAVE_GIO=1
			AC_SUBST([GIO_CFLAGS])
			AC_SUBST([GIO_LIBS])
		])
		;;
	lib)
		PKG_CHECK_MODULES(GIO,  [gio-2.0], [
			HAVE_GIO=1
			AC_SUBST([GIO_CFLAGS])
			AC_SUBST([GIO_LIBS])
		], [
			AC_MSG_FAILURE([Cannot find libgio-2.0])
		])
		;;
esac

case "$with_bsm" in
	check)
		AC_CHECK_FUNC([au_fetch_tok],
			[
				HAVE_BSM=2
			],
			[
				AC_CHECK_LIB([bsm], [au_fetch_tok],
					[
						AC_CHECK_HEADER(bsm/libbsm.h, [
							LDFLAGS="${LDFLAGS} -lbsm"
							HAVE_BSM=1
						])
					]
				)
			]
		)
		;;
	lib)
		AC_CHECK_LIB([bsm], [au_fetch_tok],
			[
				AC_CHECK_HEADER(bsm/libbsm.h, [], [AC_MSG_FAILURE([Cannot find bsm/libbsm.h])])
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
#AC_CHECK_PROG([HAVE_DTRACEPIPE], [dtrace], [found])

AS_IF([test "$HAVE_INOTIFY" != ""], [AC_CHECK_FUNC([inotify_init1], [], [INOTIFY_OLD=1])])

dnl calc is used only in kqueue and cluster code
AS_IF([test "$HAVE_KQUEUE" != "" -o "$HAVE_CLUSTER" != ""], [HAVE_CALC=1])

AM_CONDITIONAL([HAVE_KQUEUE],       [test "x$HAVE_KQUEUE"       != "x"])
AM_CONDITIONAL([HAVE_INOTIFY],      [test "x$HAVE_INOTIFY"      != "x"])
AM_CONDITIONAL([INOTIFY_OLD],       [test "x$INOTIFY_OLD"       != "x"])
AM_CONDITIONAL([HAVE_FANOTIFY],     [test "x$HAVE_FANOTIFY"     != "x"])
AM_CONDITIONAL([HAVE_BSM],          [test "x$HAVE_BSM"          != "x"])
AM_CONDITIONAL([HAVE_GIO],          [test "x$HAVE_GIO"          != "x"])
AM_CONDITIONAL([HAVE_DTRACEPIPE],   [test "x$HAVE_DTRACEPIPE"   != "x"])
AM_CONDITIONAL([HAVE_BACKTRACE],    [test "x$HAVE_BACKTRACE"    != "x"])
AM_CONDITIONAL([HAVE_CAPABILITIES], [test "x$HAVE_CAPABILITIES" != "x"])
AM_CONDITIONAL([HAVE_GETMNTENT],    [test "x$HAVE_GETMNTENT"    != "x"])
AM_CONDITIONAL([HAVE_PIVOTROOT],    [test "x$HAVE_PIVOTROOT"    != "x"])
AM_CONDITIONAL([HAVE_CLUSTER],      [test "x$HAVE_CLUSTER"      != "x"])
AM_CONDITIONAL([HAVE_UNSHARE],      [test "x$HAVE_UNSHARE"      != "x"])
AM_CONDITIONAL([HAVE_SECCOMP],      [test "x$HAVE_SECCOMP"      != "x"])
AM_CONDITIONAL([HAVE_TRE],          [test "x$HAVE_TRE"          != "x"])
AM_CONDITIONAL([HAVE_LIBCGROUP],    [test "x$HAVE_LIBCGROUP"    != "x"])
AM_CONDITIONAL([HAVE_PTHREAD_TIMEDJOIN_NP], [test "x$HAVE_PTHREAD_TIMEDJOIN_NP" != "x"])
AM_CONDITIONAL([HAVE_CALC],         [test "x$HAVE_CALC"         != "x"])

AS_IF([test "$HAVE_KQUEUE" = '' -a "$HAVE_INOTIFY" = '' -a "$HAVE_FANOTIFY" = '' -a "$HAVE_BSM" = '' -a  "$HAVE_GIO" = ''],
[AC_MSG_FAILURE([At least one monitoring engine must be enabled!
Available (depending on system): inotify, kqueue, gio, bsm])])

LIBS="${GLIB_LIBS} ${LIBS}"
AM_CPPFLAGS="${GLIB_CFLAGS}"
AC_SUBST(AM_CPPFLAGS)

dnl Generating program.h
VER_MAJ=$(echo $VERSION | cut -d'.' -f1)
VER_MID=$(echo $VERSION | cut -d'.' -f2)
VER_MIN=$(echo $VERSION | cut -d'.' -f3)
AC_SUBST(VER_MAJ)
AC_SUBST(VER_MID)
AC_SUBST(VER_MIN)
AC_SUBST(PACKAGE_BUGREPORT)
AC_SUBST(PACKAGE_URL)

AC_CONFIG_FILES([Makefile examples/Makefile pkgconfig/libclsync.pc program.h])
AC_OUTPUT
