#!/bin/bash

ACTION="$1"
LABEL="$2"
ARG0="$3"
ARG1="$4"

FROM="/srv/lxc/${LABEL}"
TO="/mnt/mirror/${LABEL}"

BROTHERMNT="/mnt/mirror"
BROTHERNAME=$(brothername)


function rsynclist() {
	LISTFILE="$1"
	EXCLISTFILE="$2"

	excludefrom=''
	if [ "$EXCLISTFILE" != "" ]; then
		excludefrom="--exclude-from=${EXCLISTFILE}"
	fi

	if mount | grep "$BROTHERMNT" > /dev/null; then
		if ping -w 1 -qc 5 -i 0.1 $BROTHERNAME > /dev/null; then
			if [ ! -d "$TO" ]; then
				mkdir -p "$TO"
			fi
			exec rsync -aH --timeout=3600 --inplace --delete-before --exclude-from="/etc/clsync/synchandler/lxc/rsync.exclude" "$excludefrom" --include-from="${LISTFILE}" --exclude='*' "$FROM"/ "$TO"/ 2>/tmp/clsync-rsync-"$LABEL"-brother.err
		else
			sleep $[ 3600 + $RANDOM % 1800 ]
			exit 128
		fi
	else
		sleep $[ 3600 + $RANDOM % 1800 ]
		exit 128
	fi
}

case "$ACTION" in
	rsynclist)
		rsynclist "$ARG0" "$ARG1"
		;;
esac

exit 0

