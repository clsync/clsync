

CFLAGS += -std=gnu11 -pipe -Wall -O2 -fstack-protector-all
DEBUGCFLAGS = -pipe -Wall -Werror -ggdb3 -Wno-error=unused-variable -fstack-protector-all

LDFLAGS += $(shell pkg-config --libs glib-2.0)
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
	$(CC) $(CFLAGS) $(LDFLAGS) $(objs) -o $(binary)

%.o: %.c
	$(CC) -pedantic $(CFLAGS) $(INC) $< -c -o $@

debug:
	$(CC) $(DEBUGCFLAGS) $(INC) $(LDFLAGS) *.c -o $(binarydebug)

clean:
	rm -f $(binary) $(binarydebug) $(objs)


