#!/bin/bash

RUN_TIMES=27

tmpdir=$(mktemp --tmpdir -d clsync-hl-bench.XXXXXXXXXX)

configuration() {
	git checkout -- configuration.h
	for regex in "$@"; do
		sed -i configuration.h -e "$regex"
	done
}

configure() {
	./configure -C "$@" >/dev/null 2>/dev/null || ./configure "$@" || exit 1
}

run() {
	time ./clsync -Mso -S'doc/devel/thread-splitting/benchmark-synchandler.so' --have-recursive-sync --max-iterations 1 -W ~/clsync-test "$@" || exit 1
}

benchmark() {
	make clean all
	HL_INITIAL=$(awk '{if ($2 == "HL_LOCK_TRIES_INITIAL") print $3}' < configuration.h)
	HL_AUTO=$(gcc -x c - -o "$tmpdir/hl_auto.bin" << 'EOF'
#include <stdio.h>
#include "configuration.h"
int main() {
#ifdef HL_LOCK_TRIES_AUTO
	printf("auto\n");
#else
	printf("noauto\n");
#endif
	return 0;
}
EOF
"$tmpdir/hl_auto.bin"
rm -f "$tmpdir/hl_auto.bin"
)
	CONFIGURE=$(awk '{if ($2 == "./configure") {$1=""; $2="";print $0; exit}}' < config.log)
	hash="$*|$CONFIGURE"
	if [[ "$HL_AUTO" == "auto" ]]; then
		hash="$hash|$HL_AUTO"
	else
		hash="$hash|$HL_INITIAL"
	fi
	i=0
	while [[ "$i" -lt "$RUN_TIMES" ]]; do
		run -d1 "$@" >> "$tmpdir/benchmark.log-$hash" 2>> "$tmpdir/benchmark.errlog-$hash"
		i=$(( i + 1 ))
	done
}

gcc -I. -shared -o doc/devel/thread-splitting/benchmark-synchandler.so -fPIC -D_DEBUG_SUPPORT doc/devel/thread-splitting/benchmark-synchandler.c

configuration 's|SLEEP_SECONDS.*$|SLEEP_SECONDS 0|g'

for args in "" "--thread-splitting"; do
#for args in "--thread-splitting"; do
	configure --enable-debug=yes
	benchmark $args
	configure --enable-highload-locks --enable-debug=no
	benchmark $args
	configure --enable-highload-locks --enable-debug=yes
	benchmark $args
	configure --enable-highload-locks --enable-debug=force
	benchmark $args
done

configure --enable-highload-locks --enable-debug=yes

benchmark

interval=1;
while [[ "$interval" -le "2147483648" ]]; do
	configuration 's|SLEEP_SECONDS.*$|SLEEP_SECONDS 0|g' 's|#define HL_LOCK_TRIES_AUTO|//#define HL_LOCK_TRIES_AUTO|g' "s|HL_LOCK_TRIES_INITIAL.*$|HL_LOCK_TRIES_INITIAL $interval|g"
	benchmark --thread-splitting
	interval=$(( interval * 2 ))
done

rm -f doc/devel/thread-splitting/benchmark-synchandler.so
