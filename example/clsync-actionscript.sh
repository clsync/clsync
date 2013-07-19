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
		sort < "$EXCLISTFILE" | uniq > "$EXCLISTFILE"-uniq
		excludefrom="--exclude-from=${EXCLISTFILE}-uniq"
	fi

	sort < "$LISTFILE" | uniq > "$LISTFILE"-uniq
	rsync -avH --delete-before "$excludefrom" --include-from="${LISTFILE}-uniq" --exclude='*' "$FROM"/ "$TO"/
	rm -f -- "${LISTFILE}-uniq" "${EXCLISTFILE}-uniq"
}

case "$ACTION" in
	rsynclist)
		rsynclist "$ARG0" "$ARG1"
		;;
esac

exit $?

