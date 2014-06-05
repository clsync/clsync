ACLOCAL_AMFLAGS = -I m4
SUBDIRS = examples

bin_PROGRAMS = clsync

clsync_SOURCES = cluster.c error.c fileutils.c glibex.c main.c		\
	malloc.c sync.c cluster.h fileutils.h glibex.h main.h sync.h	\
	common.h control.h

clsync_CFLAGS = $(AM_CFLAGS)

if SOCKET
lib_LTLIBRARIES = libclsync.la
libclsync_la_SOURCES = malloc.c libclsync.c socket.c
libclsync_la_LDFLAGS = -version-info 0:0:0
clsync_SOURCES += socket.c control.c
endif

main.o: revision.h

dist_man_MANS = man/man1/clsync.1

dist_doc_DATA = CONTRIB DEVELOPING LICENSE PROTOCOL README.md TODO

EXTRA_DIST = .doxygen .travis.sh .travis.yml NOTES SHORTHANDS debian gentoo

REVISION=$(shell [ -d .git ] &&\
	(echo -n \
		'\".'$$(($$(git log 2>/dev/null \
			| grep -c ^commit \
			| tr -d "\n" \
			)-612 \
		))'\"' \
	) || echo -n '\"-release\"' )

AM_CFLAGS := -DREVISION=$(REVISION)

clsync_includedir = $(includedir)/clsync

clsync_include_HEADERS = \
	configuration.h \
	clsync.h \
	malloc.h \
	indexes.h \
	ctx.h \
	error.h \
	socket.h \
	libclsync.h

doc:
	doxygen .doxygen

if SOCKET
pkgconfig_DATA = pkgconfig/clsync.pc
endif

CLEANFILES = revision.h
CLEANFILES += examples/rules
clean-local:
	-rm -rf examples/testdir examples/*.o examples/*.so examples/*.xz doc

