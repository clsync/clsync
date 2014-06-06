#!/bin/sh

mkdir -m 700 -p testdir/from testdir/to testdir/listdir

cat > rules <<EOF
-d^[Dd]ont[Ss]ync\$
+*.*
EOF

cc -ggdb3 -fPIC -shared -o clsync-synchandler-rsyncso.so clsync-synchandler-rsyncso.c &&

clsync -K example-rsyncso -M rsyncso -L /dev/shm/clsync -w2 -t5 -W ./testdir/from -S ./clsync-synchandler-rsyncso.so -R rules -D ./testdir/to $@

