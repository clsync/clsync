ACLOCAL_AMFLAGS = -I m4
SUBDIRS = examples

if CLSYNC
bin_PROGRAMS = clsync gencompilerflags

gencompilerflags_SOURCES = gencompilerflags.c

clsync_SOURCES = calc.c cluster.c error.c fileutils.c glibex.c		\
	indexes.c main.c malloc.c rules.c stringex.c sync.c		\
	posix-hacks.c privileged.c pthreadex.c calc.h cluster.h		\
	fileutils.h glibex.h main.h port-hacks.h posix-hacks.h		\
	pthreadex.h stringex.h sync.h common.h control.h privileged.h	\
	rules.h syscalls.h

clsync_CFLAGS  = $(AM_CFLAGS)
clsync_LDFLAGS = $(AM_LDFLAGS)

if HAVE_KQUEUE
clsync_CFLAGS  += -DKQUEUE_SUPPORT
clsync_SOURCES += mon_kqueue.c mon_kqueue.h
endif
if HAVE_INOTIFY
clsync_CFLAGS  += -DINOTIFY_SUPPORT
clsync_SOURCES += mon_inotify.c mon_inotify.h
if INOTIFY_OLD
clsync_CFLAGS  += -DINOTIFY_OLD
endif
endif
if HAVE_FANOTIFY
clsync_CFLAGS  += -DFANOTIFY_SUPPORT
clsync_SOURCES += mon_fanotify.c mon_fanotify.h
endif
if HAVE_BSM
clsync_CFLAGS  += -DBSM_SUPPORT
clsync_SOURCES += mon_bsm.c mon_bsm.h
endif
if HAVE_GIO
clsync_CFLAGS  += -DGIO_SUPPORT $(GIO_CFLAGS)
clsync_LDFLAGS += $(GIO_LIBS)
clsync_SOURCES += mon_gio.c mon_gio.h
endif
if HAVE_DTRACEPIPE
clsync_CFLAGS  += -DDTRACEPIPE_SUPPORT
clsync_SOURCES += mon_dtracepipe.c mon_dtracepipe.h
endif
if HAVE_BACKTRACE
clsync_CFLAGS  += -DBACKTRACE_SUPPORT
endif
if HAVE_CAPABILITIES
clsync_CFLAGS  += -DCAPABILITIES_SUPPORT
if HAVE_SECCOMP
clsync_CFLAGS  += -DSECCOMP_SUPPORT
endif
endif
if HAVE_GETMNTENT
clsync_CFLAGS  += -DGETMNTENT_SUPPORT
endif
if HAVE_UNSHARE
clsync_CFLAGS  += -DUNSHARE_SUPPORT
if HAVE_PIVOTROOT
clsync_CFLAGS  += -DPIVOTROOT_OPT_SUPPORT
endif
endif
#if HAVE_TRE
#clsync_CFLAGS  += -DTRE_SUPPORT
#endif
if HAVE_LIBCGROUP
clsync_CFLAGS  += -DCGROUP_SUPPORT
clsync_SOURCES += cgroup.c cgroup.h
endif

if HLLOCKS
clsync_CFLAGS  += -DHL_LOCKS
endif

if SOCKET
clsync_SOURCES += socket.c control.c program.h
endif

gencompilerflags_CFLAGS = $(clsync_CFLAGS)

main.o: compilerflags.h

compilerflags.h: gencompilerflags
	./gencompilerflags > compilerflags.h

dist_man_MANS = man/man1/clsync.1
endif

dist_doc_DATA = CONTRIB DEVELOPING LICENSE PROTOCOL README.md TODO

EXTRA_DIST = .doxygen .travis.sh .travis.yml NOTES SHORTHANDS freebsd debian gentoo

if LIBCLSYNC
lib_LTLIBRARIES = libclsync.la
libclsync_la_SOURCES = malloc.c libclsync.c socket.c error.c
libclsync_la_LDFLAGS = -version-info 0:0:0
endif

REVISION=$(shell [ -d .git ] &&\
	(echo -n \
		'\".'$$(($$(git log 2>/dev/null \
			| grep -c ^commit \
			| tr -d "\n" \
			)-1083 \
		))'\"' \
	) || echo -n '\"-release\"' )

AM_CFLAGS := -DREVISION=$(REVISION)

clsync_includedir = $(includedir)/clsync
libclsync_includedir = $(includedir)/libclsync

if CLSYNC
clsync_include_HEADERS = \
	clsync.h \
	port-hacks.h \
	configuration.h \
	ctx.h \
	error.h \
	indexes.h \
	malloc.h \
	compilerflags.h

if SOCKET
clsync_include_HEADERS += \
	socket.h
endif
endif
if LIBCLSYNC
libclsync_include_HEADERS = \
	clsync.h \
	ctx.h \
	libclsync.h \
	malloc.h \
	socket.h
endif

doc:
	doxygen .doxygen

if LIBCLSYNC
pkgconfig_DATA = pkgconfig/libclsync.pc
endif

CLEANFILES = compilerflags.h gencompilerflags
if CLSYNC
CLEANFILES += examples/rules
clean-local:
	-rm -rf examples/testdir examples/*.o examples/*.so examples/*.xz doc/doxygen
endif
