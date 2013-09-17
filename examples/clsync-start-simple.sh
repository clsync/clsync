#!/bin/bash

mkdir -m 700 -p testdir/{from,to,listdir}

cat > rules <<EOF
-d^[Dd]ont[Ss]ync\$
+*.*
EOF

clsync -K example-simple -R2 -d ./testdir/listdir -w2 -p -t5 ./testdir/from `which rsync` rules ./testdir/to

