#!/bin/bash

mkdir -m 700 -p testdir/{from,to,listdir}

cat > rules <<EOF
-d^[Dd]ont[Ss]ync\$
+*.*
EOF

clsync -K example-rsync -l test -R -d ./testdir/listdir -w2 -p -t5 ./testdir/from ./clsync-synchandler-rsync.sh rules

