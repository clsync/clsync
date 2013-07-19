#!/bin/bash -x

FROM="./testdir/from"
TO="./testdir/to"

ACTION="$1"
LABEL="$2"
ARG0="$3"
ARG1="$4"

function rsynclist() {
	LISTFILE="$1"

	rsync -avH --delete-before --include-from="$LISTFILE" --exclude='*' "$FROM"/ "$TO"/
}

case "$ACTION" in
	rsynclist)
		rsynclist "$ARG0"
		;;
esac

exit $?

