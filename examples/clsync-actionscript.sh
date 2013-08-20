#!/bin/bash -x

FROM="./testdir/from"
TO="./testdir/to"

ACTION="$1"
LABEL="$2"
ARG0="$3"
ARG1="$4"

function rsynclist() {
	LISTFILE="$1"
	EXCLISTFILE="$2"

	excludefrom=''
	if [ "$EXCLISTFILE" != "" ]; then
		excludefrom="--exclude-from=${EXCLISTFILE}"
	fi

	rsync -avH --delete-before "$excludefrom" --include-from="${LISTFILE}" --exclude='*' "$FROM"/ "$TO"/

	return 0
}

case "$ACTION" in
	rsynclist)
		rsynclist "$ARG0" "$ARG1"
		;;
esac

exit $?

