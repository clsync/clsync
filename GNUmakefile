
PREFIX ?= /usr
ifneq ($(DESTDIR),)
PREFIX = $(DESTDIR)/$(PREFIX)
endif

CFLAGS += -pipe -Wall -O2 -ggdb3 -fstack-protector-all
DEBUGCFLAGS = -pipe -Wall -Werror -ggdb3 -Wno-error=unused-variable -fstack-protector-all

NORMSYSTEMCFLAGS = -std=gnu11
OLDSYSTEMCFLAGS = -std=gnu99 -DOLDSYSTEM

LDFLAGS += $(shell pkg-config --libs glib-2.0) -lpthread
INC += $(shell pkg-config --cflags glib-2.0)

objs=\
main.o\
output.o\
fileutils.o\
sync.o\
malloc.o

binary=clsync

binarydebug=$(binary)-debug

all: $(objs)
	$(CC) $(NORMSYSTEMCFLAGS) $(CFLAGS) $(LDFLAGS) $(objs) -o $(binary)

%.o: %.c
	$(CC) $(NORMSYSTEMCFLAGS) $(CFLAGS) $(INC) $< -c -o $@

debug:
	$(CC) $(NORMSYSTEMCFLAGS) -DFANOTIFY_SUPPORT $(DEBUGCFLAGS) $(INC) $(LDFLAGS) *.c -o $(binarydebug)

onoldsystem:
	$(CC) $(OLDSYSTEMCFLAGS) $(CFLAGS) $(INC) $(LDFLAGS) *.c -o $(binary)

clean:
	rm -f $(binary) $(binarydebug) $(objs)
	rm -rf example/testdir example/rules

install:
	install -m 755 -o root -s clsync "$(PREFIX)"/bin/
	install -m 755 -o root man/man1/clsync.1 "$(PREFIX)"/share/man/man1/
	gzip "$(PREFIX)"/share/man/man1/clsync.1

deinstall:
	rm -f "$(PREFIX)"/bin/clsync "$(PREFIX)"/share/man/man1/clsync.1.gz


