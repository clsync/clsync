#!/bin/bash -x

FROM="./testdir/from"
TO="./testdir/to"

ACTION="$1"
LABEL="$2"
ARG0="$3"
ARG1="$4"

function rsynclist() {
	LISTFILE="$1"

	sort < "$LISTFILE" | uniq > "$LISTFILE"-uniq

	rsync -avH --delete-before --include-from="${LISTFILE}-uniq" --exclude='*' "$FROM"/ "$TO"/

	rm -f -- "${LISTFILE}-uniq"
}

case "$ACTION" in
	rsynclist)
		rsynclist "$ARG0"
		;;
esac

exit $?

