#!/bin/bash

. ./build.sh

mkdir -m 700 -p testdir/{from,to,listdir}

cat > rules <<EOF
-d/[Dd]ont[Ss]ync\$
+*.*
EOF

../clsync -l test -R -d ./testdir/listdir -w2 -p -t5 ./testdir/from ./clsync-synchandler-rsync.sh rules

