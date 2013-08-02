
DESTDIR ?= 
PREFIX ?= /usr

CSECFLAGS = -fstack-protector-all --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -fstack-check
CFLAGS := -pipe -Wall -O2 $(CSECFLAGS) $(CFLAGS)
DEBUGCFLAGS = -pipe -Wall -Werror -ggdb3 -Wno-error=unused-variable $(CSECFLAGS)

NORMSYSTEMCFLAGS = -std=gnu11 -march=native
OLDSYSTEMCFLAGS = -std=gnu99 -DOLDSYSTEM

LDFLAGS := $(shell pkg-config --libs glib-2.0) -lpthread -Xlinker -zrelro $(LDFLAGS)
INC := $(shell pkg-config --cflags glib-2.0) $(INC)

INSTDIR = $(DESTDIR)$(PREFIX)

objs=\
main.o\
output.o\
fileutils.o\
sync.o\
malloc.o

binary=clsync

binarydebug=$(binary)-debug

all: updaterevision $(objs)
	$(CC) $(NORMSYSTEMCFLAGS) $(CFLAGS) $(LDFLAGS) $(objs) -o $(binary)

%.o: %.c
	$(CC) $(NORMSYSTEMCFLAGS) $(CFLAGS) $(INC) $< -c -o $@

debug: updaterevision
	$(CC) $(NORMSYSTEMCFLAGS) -DFANOTIFY_SUPPORT $(DEBUGCFLAGS) $(INC) $(LDFLAGS) *.c -o $(binarydebug)

onoldsystem: updaterevision
	$(CC) $(OLDSYSTEMCFLAGS) $(CFLAGS) $(INC) $(LDFLAGS) *.c -o $(binary)

updaterevision:
	(echo -n '#define REVISION "'; [ -d .git ] && (echo -n '.'; git log 2>/dev/null | grep -c ^commit | tr -d "\n") || echo -n '-release'; echo '"') > revision.h
	touch main.c

clean:
	rm -f $(binary) $(binarydebug) $(objs) revision.h
	rm -rf example/testdir example/rules

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

