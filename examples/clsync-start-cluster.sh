#!/bin/bash

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

. ./build.sh cluster

mkdir -m 700 -p testdir/{from,to,listdir}

cat > rules <<EOF
-d^[Dd]ont[Ss]ync\$
+*.*
EOF



../clsync -c "$IPADDR" -R -d ./testdir/listdir -w 2 -p -t 5 ./testdir/from ./clsync-synchandler-rsync.sh rules

