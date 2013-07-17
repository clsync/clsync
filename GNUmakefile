
PREFIX ?= /usr/local/bin

CFLAGS += -pipe -Wall -O2 -ggdb3 -fstack-protector-all
DEBUGCFLAGS = -pipe -Wall -Werror -ggdb3 -Wno-error=unused-variable -fstack-protector-all

NORMSYSTEMCFLAGS = -std=gnu11
OLDSYSTEMCFLAGS = -std=gnu99

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

install:
	install -m 755 -o root -s clsync "$(PREFIX)"/

deinstall:
	rm -f "$(PREFIX)"/clsync


