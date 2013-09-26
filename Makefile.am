bin_PROGRAMS = clsync

clsync_SOURCES = sync.c cluster.c main.c output.c fileutils.c malloc.c glibex.c

main.o: revision.h

man_MANS = man/man1/clsync.1

doc_DATA = CONTRIB DEVELOPING LICENSE PROTOCOL README.md TODO

exampledir=$(docdir)/examples

example_DATA = \
 $(wildcard $(srcdir)/examples/*.c) \
 $(wildcard $(srcdir)/examples/*.sh)


clsync_includedir = $(includedir)/clsync
clsync_include_HEADERS = clsync.h options.h indexes.h output.h configuration.h

revision.h:
	(echo -n '#define REVISION "'; [ -d .git ] && \
	(echo -n '.'$$(( $$(git log 2>/dev/null | grep -c ^commit | tr -d "\n") - 308 )) ) \
	|| echo -n '-release'; echo '"') > $@

doc:
	doxygen .doxygen

install-data-local:
	cp -R examples/production $(exampledir)/
	chown -R root:root $(exampledir)/production

uninstall-local:
	rm -rf $(exampledir)/production

CLEANFILES = revision.h
CLEANFILES += examples/rules
clean-local:
	-rm -rf examples/testdir examples/*.o examples/*.so examples/*.xz doc
