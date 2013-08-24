#!/bin/bash

(
	cd ..
	if [ "$1" = "cluster" ]; then
		if ! grep "CLUSTER_SUPPORT" config.log >/dev/null; then
			make distclean
		fi
	fi
	if ! [ -f "Makefile" ]; then
		autoreconf -i
		if [ "$1" = "cluster" ]; then
			export CFLAGS=-DCLUSTER_SUPPORT
		fi
		./configure
		make all
	fi
	cd - > /dev/null
)

