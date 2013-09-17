#!/bin/bash

mkdir -m 700 -p testdir/{from,to,listdir}

cat > rules <<EOF
-d^[Dd]ont[Ss]ync\$
+*.*
EOF

gcc -ggdb3 -fPIC -shared -o clsync-synchandler-so.so clsync-synchandler-so.c &&

clsync -K example-so -M -d ./testdir/listdir -w2 -p -t5 ./testdir/from ./clsync-synchandler-so.so rules ./testdir/to

