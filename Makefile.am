bin_PROGRAMS = clsync

clsync_SOURCES = sync.c cluster.c main.c output.c fileutils.c malloc.c glibex.c

main.o: revision.h

man_MANS = man/man1/clsync.1

doc_DATA = CONTRIB DEVELOPING LICENSE PROTOCOL README.md TODO

exampledir=$(docdir)/examples

example_DATA = \
 examples/clsync-synchandler-so.c \
 examples/clsync-synchandler-rsyncshell.sh \
 examples/clsync-synchandler-production.sh \
 examples/clsync-start-so.sh \
 examples/clsync-start-rsyncshell.sh \
 examples/clsync-start-rsyncdirect.sh \
 examples/clsync-start-cluster.sh \
 examples/clsync-start-production.sh

clsync_includedir = $(includedir)/clsync
clsync_include_HEADERS = clsync.h options.h indexes.h output.h configuration.h

revision.h:
	(echo -n '#define REVISION "'; [ -d .git ] && \
	(echo -n '.'$$(( $$(git log 2>/dev/null | grep -c ^commit | tr -d "\n") - 308 )) ) \
	|| echo -n '-release'; echo '"') > $@

doc:
	doxygen .doxygen

CLEANFILES = revision.h
CLEANFILES += examples/rules
clean-local:
	-rm -rf examples/testdir examples/*.o examples/*.so doc
