#!/bin/sh

mkdir -m 700 -p testdir/from testdir/to testdir/listdir

cat > rules <<EOF
-d^[Dd]ont[Ss]ync\$
+*.*
EOF

clsync -K example-simple -M rsyncdirect -w2 -p safe -t5 -W ./testdir/from -S `which rsync` -R rules -D ./testdir/to $@

