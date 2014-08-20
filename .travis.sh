#!/bin/sh -x

# configuration

TIMEOUT_SYNC=15

case $(uname -s) in
	Linux)
		MAKE='make'
		;;
	*)
		MAKE='gmake'
		;;
esac

# test aggressive optimizations
export CFLAGS="$CFLAGS -O3 -march=native"
autoreconf -if

# Build unit test
build_test() {
	$MAKE clean
	echo ">>> Testing with \"$@\""
	# make sure we test paralled build as they tend to fail when single works
	./configure -C $@ >/dev/null || rm -f config.cache && ./configure -C $@ >/dev/null && $MAKE -j5 >/dev/null || {
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
	pkill -F "$CLSYNC_PIDFILE" 2>/dev/null
	echo "$@" >&2
	exit 1
}

# Run example script
run_example() {
	MODE="$1"; shift;

	export CLSYNC_PIDFILE="/tmp/clsync-example-$MODE.pid"

	rm -rf "examples/testdir"/*/*
	mkdir -p "examples/testdir/to" "examples/testdir/from"

	trap run_example_cleanup_failure INT TERM
	cd examples
	bash -x clsync-start-"$MODE".sh --background --pid-file "$CLSYNC_PIDFILE" --config-file '/NULL/' -w1 -t1 -d9 $@
	cd -

	sleep 1
	mkdir -p examples/testdir/from/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t/u/v/w/x/y/z/DIR
	touch examples/testdir/from/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t/u/v/w/x/y/z/a
	touch examples/testdir/from/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t/u/v/w/x/y/z/b
	touch examples/testdir/from/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t/u/v/w/x/y/z/c
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
		i=$(( $i + 1 ))
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
		i=$(( $i + 1 ))
	done
	run_example_cleanup_failure "$MODE" "no successful sync"
}

if true; then

	# Test all possible package-specific configure options.
	# Do not test empty cases save as no options at all.

	build_test

	# clsync enabled
	a0="--enable-clsync"
	for a1 in "--enable-cluster --with-mhash" "--enable-cluster --without-mhash" "--disable-cluster"; do
	for a2 in "--enable-debug" "--disable-debug"; do
	for a3 in "--enable-paranoid=0" "--enable-paranoid=1" "--enable-paranoid=2" ; do
	for a4 in "--with-capabilities" "--without-capabilities"; do
	for a5 in "--enable-socket" "--disable-socket"; do
	for a6 in "--enable-socket-library" "--disable-socket-library"; do
	for a7 in "--enable-highload-locks" ""; do
	for a8 in "--with-libcgroup" "--without-libcgroup"; do
	for a9 in "--with-libseccomp" "--without-libseccomp"; do
		arg="$a0 $a1 $a2 $a3 $a4 $a5 $a6 $a7 $a8 $a9"
		build_test "$arg"
	done
	done
	done
	done
	done
	done
	done
	done

	# clsync disabled, libclsync enabled
	a0="--disable-clsync --enable-socket-library"
	for a2 in "--enable-debug" "--disable-debug"; do
	for a3 in "--enable-paranoid=0" "--enable-paranoid=1" "--enable-paranoid=2" ; do
		arg="$a0 $a1 $a2"
		build_test "$arg"
	done
	done

	# clsync disabled, libclsync disabled
	build_test "--disable-clsync --disable-socket-library"

fi

if true; then

	# Test coverage

	export CFLAGS="$CFLAGS --coverage -O0"
	export PATH="$(pwd):$PATH"
	build_test --enable-cluster --enable-debug --enable-paranoid=2 --with-capabilities --without-mhash
	run_example rsyncdirect --thread-splitting
	run_example rsyncdirect
	run_example rsyncshell
#	run_example rsyncso
	#run_example so
	#run_example cluster

fi

exit 0
