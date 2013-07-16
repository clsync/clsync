#!/bin/bash

make -C .. all

mkdir -p testdir/{from,to,listdir}
../clsync -d ./testdir/listdir -w 2 -p -t 5 ./testdir/from ./clsync-actionscript.sh rules

