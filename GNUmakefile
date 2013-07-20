
DESTDIR ?= 
PREFIX ?= /usr

CFLAGS += -pipe -Wall -O2 -ggdb3 -fstack-protector-all
DEBUGCFLAGS = -pipe -Wall -Werror -ggdb3 -Wno-error=unused-variable -fstack-protector-all

NORMSYSTEMCFLAGS = -std=gnu11
OLDSYSTEMCFLAGS = -std=gnu99 -DOLDSYSTEM

LDFLAGS += $(shell pkg-config --libs glib-2.0) -lpthread
INC += $(shell pkg-config --cflags glib-2.0)

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
	(echo -n '#define REVISION '; git log | grep -c ^commit) > revision.h
	touch main.c

clean:
	rm -f $(binary) $(binarydebug) $(objs) revision.h
	rm -rf example/testdir example/rules

install:
	mkdir -p "$(INSTDIR)/bin" "$(INSTDIR)/share/man/man1"
	install -m 755 -o root -s clsync "$(INSTDIR)"/bin/
	install -m 755 -o root man/man1/clsync.1 "$(INSTDIR)"/share/man/man1/
	rm -f "$(INSTDIR)"/share/man/man1/clsync.1.gz
	gzip "$(INSTDIR)"/share/man/man1/clsync.1

deinstall:
	rm -f "$(INSTDIR)"/bin/clsync "$(INSTDIR)"/share/man/man1/clsync.1.gz

dpkg: clean
	tar --exclude "debian" --exclude-vcs -C .. -cJvf ../clsync_0.0.orig.tar.xz clsync
	dpkg-buildpackage -rfakeroot


