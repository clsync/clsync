#!/bin/sh

IFACE="$1"

if [ "$IFACE" = "" ]; then
	echo "syntax:  $0 <inet interface name>" >&2
	echo "example: $0 eth0" >&2
	exit 1
fi

IPADDR=$(ip a s "$IFACE" | awk '{if($1=="inet") {gsub("/.*", "", $2); print $2}}')

if [ "$IPADDR" = "" ]; then
	echo "Interface \"$IFACE\" doesn't exists or there's no IP-addresses assigned to it." >&2
	exit 2
fi

mkdir -m 700 -p testdir/from testdir/to testdir/listdir

cat > rules <<EOF
-d^[Dd]ont[Ss]ync\$
+*.*
EOF

clsync -K example-cluster -c "$IPADDR" -M rsyncshell -L ./testdir/listdir -w 2 -p safe -t 5 -W ./testdir/from -S ./clsync-synchandler-rsync.sh -R rules $@

