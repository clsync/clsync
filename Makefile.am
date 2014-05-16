ACLOCAL_AMFLAGS = -I m4

if CLSYNC
bin_PROGRAMS = clsync
clsync_SOURCES = sync.c cluster.c main.c error.c fileutils.c malloc.c glibex.c
clsync_CFLAGS = $(AM_CFLAGS)

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

clsync_include_HEADERS = \
	error.h \
	malloc.h
if CLSYNC
clsync_include_HEADERS += \
	clsync.h \
	configuration.h \
	ctx.h \
	indexes.h
if SOCKET
clsync_include_HEADERS += \
	socket.h
endif
endif
if LIBCLSYNC
clsync_include_HEADERS += \
	libclsync.h \
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
