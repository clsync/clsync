
CFLAGS += -std=gnu11 -pipe -Wall -O2 -fstack-protector-all
DEBUGCFLAGS = -pipe -Wall -Werror -ggdb3 -Wno-error=unused-variable -fstack-protector-all

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
	$(CC) -pedantic $(CFLAGS) $< -c -o $@

debug:
	$(CC) $(DEBUGCFLAGS) *.c -o $(binarydebug)

clean:
	rm -f $(binary) $(binarydebug) $(objs)


