#!/bin/bash

make -C .. all

mkdir -p testdir/{from,to,listdir}

cat > rules <<EOF
-d/[Dd]ont[Ss]ync\$
+*.*
EOF

../clsync -RR -d ./testdir/listdir -w 2 -p -t 5 ./testdir/from `which rsync` rules ./testdir/to

