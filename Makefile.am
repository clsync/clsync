bin_PROGRAMS = clsync
clsync_SOURCES = sync.c cluster.c main.c error.c fileutils.c malloc.c glibex.c
clsync_CFLAGS = $(AM_CFLAGS)

if SOCKET
lib_LTLIBRARIES = libclsync.la
libclsync_la_SOURCES = malloc.c libclsync.c socket.c
libclsync_la_LDFLAGS = -version-info 0:0:0
clsync_SOURCES += socket.c control.c
endif

main.o: revision.h

man_MANS = man/man1/clsync.1

doc_DATA = CONTRIB DEVELOPING LICENSE PROTOCOL README.md TODO

exampledir=$(docdir)/examples

example_DATA = \
 $(wildcard $(srcdir)/examples/*.c) \
 $(wildcard $(srcdir)/examples/*.sh)

REVISION=$(shell [ -d .git ] &&\
	(echo -n \
		'\".'$$(($$(git log 2>/dev/null \
			| grep -c ^commit \
			| tr -d "\n" \
			)-606 \
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

install-data-local:
if SOCKET
	mkdir -p $(DESTDIR)/$(libdir)/pkgconfig
	cp pkgconfig/*.pc $(DESTDIR)/$(libdir)/pkgconfig/
endif
	mkdir -p $(DESTDIR)/$(exampledir)
	cp -R examples/production $(DESTDIR)/$(exampledir)/

uninstall-local:
	rm -rf $(DESTDIR)/$(exampledir)/production

CLEANFILES = revision.h
CLEANFILES += examples/rules
clean-local:
	-rm -rf examples/testdir examples/*.o examples/*.so examples/*.xz doc

