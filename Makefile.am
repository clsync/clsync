bin_PROGRAMS = clsync

clsync_SOURCES = sync.c cluster.c main.c socket.c output.c fileutils.c malloc.c glibex.c

main.o: revision.h

man_MANS = man/man1/clsync.1

doc_DATA = CONTRIB DEVELOPING LICENSE PROTOCOL README.md TODO

exampledir=$(docdir)/examples

example_DATA = \
 $(wildcard $(srcdir)/examples/*.c) \
 $(wildcard $(srcdir)/examples/*.sh)


clsync_includedir = $(includedir)/clsync
clsync_include_HEADERS = configuration.h clsync.h malloc.h indexes.h options.h output.h socket.h

revision.h:
	(echo -n '#define REVISION "'; [ -d .git ] && \
	(echo -n '.'$$(( $$(git log 2>/dev/null | grep -c ^commit | tr -d "\n") - 523 )) ) \
	|| echo -n '-release'; echo '"') > $@

doc:
	doxygen .doxygen

install-data-local:
	mkdir -p $(DESTDIR)/$(exampledir)
	cp -R examples/production $(DESTDIR)/$(exampledir)/

uninstall-local:
	rm -rf $(DESTDIR)/$(exampledir)/production

CLEANFILES = revision.h
CLEANFILES += examples/rules
clean-local:
	-rm -rf examples/testdir examples/*.o examples/*.so examples/*.xz doc
