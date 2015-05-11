#!/bin/sh

mkdir -m 700 -p testdir/from

cat > rules <<EOF
-d^[Dd]ont[Ss]ync\$
+*.*
EOF

sudo $(which clsync) -K example-simple -M simple -w2 -t5 -W ./testdir/from -S $(which echo) -R rules $@

