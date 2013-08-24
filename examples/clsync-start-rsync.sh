#!/bin/bash

. ./build.sh

mkdir -m 700 -p testdir/{from,to,listdir}

cat > rules <<EOF
-d/[Dd]ont[Ss]ync\$
+*.*
EOF

../clsync -l test -R -d ./testdir/listdir -w 2 -p -t 5 ./testdir/from ./clsync-actionscript-rsync.sh rules

