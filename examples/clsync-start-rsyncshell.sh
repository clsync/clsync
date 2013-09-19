#!/bin/bash

mkdir -m 700 -p testdir/{from,to,listdir}

cat > rules <<EOF
-d^[Dd]ont[Ss]ync\$
+*.*
EOF

clsync -K example-rsync -l test -M rsyncshell -L ./testdir/listdir -w2 -p -t5 -W ./testdir/from -S ./clsync-synchandler-rsyncshell.sh -R rules

