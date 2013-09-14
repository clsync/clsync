#!/bin/bash

mkdir -m 700 -p testdir/{from,to,listdir}

cat > rules <<EOF
-d^[Dd]ont[Ss]ync\$
+*.*
EOF

gcc -ggdb $(pkg-config --cflags glib-2.0) -I../.. -fPIC -shared -o clsync-synchandler-so.so clsync-synchandler-so.c

clsync -M -d ./testdir/listdir -w2 -p -t5 ./testdir/from ./clsync-synchandler-so.so rules

