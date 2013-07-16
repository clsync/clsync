#!/bin/bash -x

FROM="./testdir/from"
TO="./testdir/to"

ACTION="$1"
LABEL="$2"
ARG0="$3"
ARG1="$4"

function initialsync() {
	DIR="$1"

	rsync -avp --delete "$DIR"/ "$TO"/

	return $?
}

function synclist() {
	LISTFILE="$1"

	awk -F '/' '{OFS="/"; $1=""; startdir="'"$FROM"'"; print substr($0, length(startdir)+1)}' < "$LISTFILE" | tee testdir/log0 | rsync -vlptgodD --delete-before --include-from=- --exclude='*' "$FROM"/ "$TO"/
	
	return $?
}

function sync() {
	EVENTMASK="$1"
	FPATH="$2"

	echo '"sync" command is not checked, yet'
	exit -1

	rsync -vlptgodD --delete "$FPATH" "$TO"/

	return $?
}

case "$ACTION" in
	initialsync)
		initialsync "$ARG0" "$ARG1"
		;;
	synclist)
		synclist "$ARG0" "$ARG1"
		;;
	sync)
		sync "$ARG0" "$ARG1"
		;;
esac

exit $?

