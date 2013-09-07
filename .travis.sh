#!/bin/bash

# test aggressive optimizations
export CFLAGS="-O3 -march=native"
autoreconf -if

# Test all possible package-specific configure options, including
# empty option (e.g. when option is not specified). In an ideal
# world empty values should be the same as --enable/--with default
# values, but they may not due to bugs.

for a0 in "" "--enable-cluster" "--disable-cluster"; do
    arg[0]="$a0"
for a1 in "" "--enable-debug" "--disable-debug"; do
    arg[1]="$a1"
for a2 in "" "--enable-paranoid=0" "--enable-paranoid=1" "--enable-paranoid=2" ; do
    arg[2]="$a2"
for a3 in "" "--with-capabilities" "--without-capabilities"; do
    arg[3]="$a3"
for a4 in "" "--with-mhash" "--without-mhash"; do
    arg[4]="$a4"

    make clean
    echo ">>> Testing with \"${arg[@]}\""
    # make sure we test paralled build as they tend to fail when single works
    ./configure ${arg[@]} && make -j5 || {
        echo "!!! test with \"${arg[@]}\" configure options failed"
        exit 1
    }

done
done
done
done
done
