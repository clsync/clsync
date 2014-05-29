CC = gcc
CFLAGS = -march=native -O2 -funswitch-loops -fpredictive-commoning -fgcse-after-reload -ftree-vectorize -ftree-loop-linear -ftree-loop-im -fweb -frename-registers -fomit-frame-pointer -fexcess-precision=fast -pipe
CFLAGS += --std=gnu11 -Wall -fPIC -shared
LDFLAGS = -Wl,-O1,--as-needed

HANDLERS = handler-pdcp.so handler-backup.so

all: $(HANDLERS)

%.so: %.c
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@
	strip --strip-unneeded -R .comment -R .GCC.command.line -R .note.gnu.gold-version $@

clean:
	rm $(HANDLERS)

