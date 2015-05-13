#!/bin/sh

mkdir -m 700 -p testdir/from testdir/to testdir/listdir

cat > rules <<EOF
-d^[Dd]ont[Ss]ync\$
+*.*
EOF

case "$(uname -s)" in
	GNU/kFreeBSD)
		OPTS=''
		;;
	*)
		OPTS='-p safe'
		;;
esac

sudo $(which clsync) -K example-rsync -l test -M rsyncshell -w2 -t5 -W ./testdir/from -S ./clsync-synchandler-rsyncshell.sh -R rules $OPTS $@

