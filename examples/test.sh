#!/bin/sh

#mkdir -m 700 -p testdir/from testdir/to testdir/listdir

cat > rules <<EOF
-d^[Dd]ont[Ss]ync\$
+*.*
EOF

rm -rf /mnt/data/from/*
rm -rf /mnt/data/to/*

cp -r /usr /mnt/data/from/usr &
sleep 2; ../clsync -L /shm/clsync --monitor=bsm --exit-on-no-events -x 23 -x 24 -M rsyncdirect -S $(which rsync) -W /mnt/data/from -D /mnt/data/to -d99

rm -rf /mnt/data/from/*
rm -rf /mnt/data/to/*

