#!/bin/bash -x

# configuration

TIMEOUT_SYNC=15

# test aggressive optimizations
export CFLAGS="-O3 -march=native"
autoreconf -if

# Build unit test
build_test() {
	make clean
	echo ">>> Testing with \"$@\""
	# make sure we test paralled build as they tend to fail when single works
	./configure $@ && make -j5 || {
		echo "!!! test with \"$@\" configure options failed"
		exit 1
	}
}

# Cleanup functions for run_example()
run_example_cleanup_success() {
	rm -rf "examples/testdir"/{to,from}/*
	pkill -F "$CLSYNC_PIDFILE"
}
run_example_cleanup_failure() {
	pkill -F "$CLSYNC_PIDFILE"
	echo "$@" >&2
	exit 1
}

# Run example script
run_example() {
	MODE="$1"

	export CLSYNC_PIDFILE="/tmp/clsync-example-$MODE.pid"

	rm -rf "examples/testdir"/{to,from}/*
	mkdir -p "examples/testdir/"{to,from}

	trap run_example_cleanup_failure INT TERM
	cd examples
	bash -x clsync-start-"$MODE".sh --background --pid-file "$CLSYNC_PIDFILE" --config-file '/NULL/' -w1 -t1 -d1
	cd -

	sleep 1
	mkdir -p examples/testdir/from/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t/u/v/w/x/y/z/DIR
	touch examples/testdir/from/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t/u/v/w/x/y/z/{a,b,c,d,e,f,g,h}
	touch examples/testdir/from/a/b/c/d/e/f/g/h/7
	touch examples/testdir/from/test
	mkdir examples/testdir/from/dontSync
	i=0
	while [ "$i" -le "$TIMEOUT_SYNC" ]; do
		if [ -f "examples/testdir/to/test" -a -f "examples/testdir/to/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t/u/v/w/x/y/z/a" -a -d "examples/testdir/to/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t/u/v/w/x/y/z/DIR" ]; then
			sleep 1
			break
		fi
		sleep 1
		(( i++ ))
	done
	if [ "$i" -gt "$TIMEOUT_SYNC" ]; then
		run_example_cleanup_failure "$MODE" "timed out on initial syncing"
	fi
	if ! [ -f "$CLSYNC_PIDFILE" ]; then
		run_example_cleanup_failure "$MODE" "no pidfile"
	fi
	touch "examples/testdir/from/file" "examples/testdir/from/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t/u/v/w/x/y/z/DIR/file"
	rm -rf "examples/testdir/from/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t/u/v/w/x/y/z/DIR"
	i=0
	while [ "$i" -le "$TIMEOUT_SYNC" ]; do
		if ! [ -f "$CLSYNC_PIDFILE" ]; then
			run_example_cleanup_failure "$MODE" "premature exit"
		fi
		if [ -f "examples/testdir/to/file" -a ! -d "examples/testdir/to/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t/u/v/w/x/y/z/DIR" ]; then
			sleep 1
			run_example_cleanup_success
			return
		fi
		sleep 1
		(( i++ ))
	done
	run_example_cleanup_failure "$MODE" "no successful sync"
}

if true; then

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

fi

if true; then

	# Test coverage

	export CFLAGS="$CFLAGS --coverage -O0"
	export PATH="$(pwd):$PATH"
	build_test --enable-cluster --enable-debug --enable-paranoid=2 --with-capabilities --without-mhash
	run_example rsyncdirect
	run_example rsyncshell
	run_example rsyncso
	#run_example so
	#run_example cluster

fi

exit 0
