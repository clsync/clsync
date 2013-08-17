
DESTDIR ?= 
PREFIX  ?= /usr

CSECFLAGS ?= -fstack-protector-all -Wall --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -fstack-check -DPARANOID
CFLAGS := -pipe -O2 $(CSECFLAGS) $(CFLAGS) 
DEBUGCFLAGS ?= -pipe -Wall -Werror -ggdb3 -Wno-error=unused-variable $(CSECFLAGS) -D_DEBUG

CARCHFLAGS ?= -march=native

NORMSYSTEMCFLAGS ?= -std=gnu11 $(CARCHFLAGS)
OLDSYSTEMCFLAGS  ?= -std=gnu99 -DOLDSYSTEM

LDFLAGS := $(shell pkg-config --libs glib-2.0) -lpthread -Xlinker -zrelro $(LDFLAGS)
INC := $(shell pkg-config --cflags glib-2.0) $(INC)

INSTDIR = $(DESTDIR)$(PREFIX)

objs=\
sync.o\
cluster.o\
main.o\
output.o\
fileutils.o\
malloc.o

binary=clsync

binarydebug=$(binary)-debug

binarytest=$(binary)-test

.PHONY: doc

all: updaterevision $(objs)
	$(CC) $(NORMSYSTEMCFLAGS) $(CFLAGS) $(LDFLAGS) $(objs) -o $(binary)

%.o: %.c
	$(CC) $(NORMSYSTEMCFLAGS) $(CFLAGS) $(INC) $< -c -o $@

debug: updaterevision
	$(CC) $(NORMSYSTEMCFLAGS) -DFANOTIFY_SUPPORT $(DEBUGCFLAGS) $(INC) $(LDFLAGS) $(shell ls *.c | grep -v "test.c") -o $(binarydebug)

test: updaterevision
	$(CC) $(NORMSYSTEMCFLAGS) -DFANOTIFY_SUPPORT $(DEBUGCFLAGS) $(INC) $(LDFLAGS) $(shell ls *.c | grep -v "main.c") -o $(binarytest)

onoldsystem: updaterevision
	$(CC) $(OLDSYSTEMCFLAGS) $(CFLAGS) $(INC) $(LDFLAGS) *.c -o $(binary)

updaterevision:
	(echo -n '#define REVISION "'; [ -d .git ] && (echo -n '.'$$(( $$(git log 2>/dev/null | grep -c ^commit | tr -d "\n") - 137 )) ) || echo -n '-release'; echo '"') > revision.h
	touch main.c

clean:
	rm -f $(binary) $(binarydebug) $(binarytest) $(objs) revision.h
	rm -rf example/testdir example/rules doc

distclean: clean

doc:
	mkdir -p doc
	doxygen .doxygen

install:
	mkdir -p "$(INSTDIR)/bin" "$(INSTDIR)/share/man/man1" "$(INSTDIR)/share/doc/clsync"
	cp -Rp example "$(INSTDIR)/share/doc/clsync"
	chown -R 0:0 "$(INSTDIR)/share/doc/clsync"
	install -m 755 -o root -s clsync "$(INSTDIR)"/bin/
	install -m 644 -o root man/man1/clsync.1 "$(INSTDIR)"/share/man/man1/
	rm -f "$(INSTDIR)"/share/man/man1/clsync.1.gz
	gzip "$(INSTDIR)"/share/man/man1/clsync.1

deinstall:
	rm -f "$(INSTDIR)"/bin/clsync "$(INSTDIR)"/share/man/man1/clsync.1.gz

dpkg: clean
	tar --exclude "debian" --exclude-vcs -C .. -cJvf ../clsync_0.0.orig.tar.xz clsync
	dpkg-buildpackage -rfakeroot

