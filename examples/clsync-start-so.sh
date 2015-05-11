#!/bin/sh

mkdir -m 700 -p testdir/from testdir/to testdir/listdir

cat > rules <<EOF
-d^[Dd]ont[Ss]ync\$
+*.*
EOF

cc -ggdb3 -fPIC -shared -o clsync-synchandler-so.so clsync-synchandler-so.c &&

sudo $(which clsync) -K example-so -M so -w2 -t5 -W ./testdir/from -S ./clsync-synchandler-so.so -R rules -D ./testdir/to $@

