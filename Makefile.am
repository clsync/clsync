bin_PROGRAMS = clsync

clsync_SOURCES = sync.c cluster.c main.c output.c fileutils.c malloc.c

main.o: revision.h

man_MANS = man/man1/clsync.1

doc_DATA = CONTRIB DEVELOPING LICENSE PROTOCOL README.md TODO

exampledir=$(docdir)/examples

example_DATA = \
 examples/clsync-synchandler-so.c \
 examples/clsync-synchandler-rsync.sh \
 examples/clsync-synchandler-production.sh \
 examples/clsync-start-so.sh \
 examples/clsync-start-rsync.sh \
 examples/clsync-start-simple.sh \
 examples/clsync-start-cluster.sh \
 examples/clsync-start-production.sh

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
