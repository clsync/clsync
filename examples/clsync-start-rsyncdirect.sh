#!/bin/bash

mkdir -m 700 -p testdir/{from,to,listdir}

cat > rules <<EOF
-d^[Dd]ont[Ss]ync\$
+*.*
EOF

clsync -K example-simple -M rsyncdirect -L ./testdir/listdir -w2 -p -d4 -t5 -W ./testdir/from -S `which rsync` -R rules -D ./testdir/to $@

