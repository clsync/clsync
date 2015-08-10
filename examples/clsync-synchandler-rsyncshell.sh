#!/bin/sh -x

FROM="`pwd`"
TO="`pwd`/../to"

ACTION="$1"
LABEL="$2"
ARG0="$3"
ARG1="$3"
ARG2="$4"

rsynclist() {
	WALKLISTFILE="$1"
	LISTFILE="$2"
	EXCLISTFILE="$3"

	excludefrom=''
	if [ "$EXCLISTFILE" != "" ]; then
		excludefrom="--exclude-from=${EXCLISTFILE}"
	fi

	exec rsync -avH --delete-before --include-from="${WALKLISTFILE}"  "$excludefrom" --include-from="${LISTFILE}" --exclude='*' "$FROM"/ "$TO"/

	return 0
}

case "$ACTION" in
	rsynclist)
		rsynclist "$ARG0" "$ARG1" "$ARG2"
		;;
esac

exit $?

