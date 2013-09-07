#!/bin/bash

# test aggressive optimizations
export CFLAGS="-O3 -march=native"
autoreconf -if

# Build unit test
build_test() {
    make clean
    echo ">>> Testing with \"$@\""
    # make sure we test paralled build as they tend to fail when single works
    ./configure $@ && make -j5 || {
        echo "!!! test with \"@\" configure options failed"
        exit 1
    }
}

# Test all possible package-specific configure options.
# Do not test empty cases save as no options at all.
build_test ${arg[@]}

for a0 in "--enable-cluster" "--disable-cluster"; do
    arg[0]="$a0"
for a1 in "--enable-debug" "--disable-debug"; do
    arg[1]="$a1"
for a2 in "--enable-paranoid=0" "--enable-paranoid=1" "--enable-paranoid=2" ; do
    arg[2]="$a2"
for a3 in "--with-capabilities" "--without-capabilities"; do
    arg[3]="$a3"
for a4 in "--with-mhash" "--without-mhash"; do
    arg[4]="$a4"

    build_test ${arg[@]}

done
done
done
done
done
