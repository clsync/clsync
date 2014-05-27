ACLOCAL_AMFLAGS = -I m4

if CLSYNC
bin_PROGRAMS = clsync
clsync_SOURCES = sync.c cluster.c main.c error.c fileutils.c malloc.c glibex.c indexes.c calc.c
clsync_CFLAGS = $(AM_CFLAGS)

if HAVE_KQUEUE
clsync_CFLAGS += -DKQUEUE_SUPPORT
clsync_SOURCES += mon_kqueue.c
endif
if HAVE_INOTIFY
clsync_CFLAGS += -DINOTIFY_SUPPORT
clsync_SOURCES += mon_inotify.c
if INOTIFY_OLD
clsync_CFLAGS += -DINOTIFY_OLD
endif
endif
if HAVE_FANOTIFY
clsync_CFLAGS += -DFANOTIFY_SUPPORT
clsync_SOURCES += mon_fanotify.c
endif
if HAVE_BSM
clsync_CFLAGS += -DBSM_SUPPORT
clsync_SOURCES += mon_bsm.c
endif

if SOCKET
clsync_SOURCES += socket.c control.c
endif

main.o: revision.h

man_MANS = man/man1/clsync.1

exampledir=$(docdir)/examples

example_DATA = \
 $(wildcard $(srcdir)/examples/*.c) \
 $(wildcard $(srcdir)/examples/*.sh)
endif

doc_DATA = CONTRIB DEVELOPING LICENSE PROTOCOL README.md TODO

if LIBCLSYNC
lib_LTLIBRARIES = libclsync.la
libclsync_la_SOURCES = malloc.c libclsync.c socket.c
libclsync_la_LDFLAGS = -version-info 0:0:0
endif

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
libclsync_includedir = $(includedir)/libclsync

if CLSYNC
clsync_include_HEADERS = \
	error.h \
	malloc.h
clsync_include_HEADERS += \
	clsync.h \
	configuration.h \
	indexes.h
if SOCKET
clsync_include_HEADERS += \
	socket.h \
	ctx.h
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

install-data-local:
if LIBCLSYNC
	mkdir -p $(DESTDIR)/$(libdir)/pkgconfig
	cp pkgconfig/*.pc $(DESTDIR)/$(libdir)/pkgconfig/
endif
if CLSYNC
	mkdir -p $(DESTDIR)/$(exampledir)
	cp -R examples/production $(DESTDIR)/$(exampledir)/
endif

uninstall-local:
	rm -rf $(DESTDIR)/$(exampledir)/production

CLEANFILES = revision.h
if CLSYNC
CLEANFILES += examples/rules
clean-local:
	-rm -rf examples/testdir examples/*.o examples/*.so examples/*.xz doc
endif
