#!/bin/bash

make -C .. all

mkdir -p testdir/{from,to,listdir}

cat > rules <<EOF
-d/\\.git\$
+*.*
EOF

../clsync -d ./testdir/listdir -w 2 -p -t 5 ./testdir/from ./clsync-actionscript.sh rules

