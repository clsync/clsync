#!/bin/bash

ACTION="$1"
LABEL="$2"
ARG0="$3"
ARG1="$4"

FROM="/srv/lxc/${LABEL}"
BACKUPMNT="/mnt/backup"
BACKUPDECR="/mnt/backup/decrement/${LABEL}"
BACKUPMIRROR="/mnt/backup/mirror/${LABEL}"
BACKUPHOST=$(backuphost)

function rsynclist() {
	LISTFILE="$1"
	EXCLISTFILE="$2"

	excludefrom=''
	if [ "$EXCLISTFILE" != "" ]; then
		excludefrom="--exclude-from=${EXCLISTFILE}"
	fi

	if mount | grep "$BACKUPMNT" > /dev/null; then
		if ping -w 1 -qc 5 -i 0.1 $BACKUPHOST > /dev/null; then
			if [ ! -d "$BACKUPDECR" ]; then
				mkdir -p "$BACKUPDECR"
			fi
			exec rsync -aH --timeout=3600 --inplace --delete-before --exclude-from="/etc/clsync/synchandler/lxc/rsync.exclude" "$excludefrom" --include-from="${LISTFILE}" --exclude='*' --backup --backup-dir="$BACKUPDECR"/ "$FROM"/ "$BACKUPMIRROR"/ 2>/tmp/clsync-rsync-"$LABEL"-backup.err
		else
			sleep $[ 3600 + $RANDOM % 1800 ]
			return 128
		fi
	else
		sleep $[ 3600 + $RANDOM % 1800 ]
		return 128
	fi
}

case "$ACTION" in
	rsynclist)
		rsynclist "$ARG0" "$ARG1"
		;;
esac

exit 0

