#!/bin/bash

ACTION="$1"
LABEL="$2"
ARG0="$3"
ARG1="$4"

FROM="/srv/lxc/${LABEL}"
TO="/mnt/mirror/${LABEL}"
BROTHERMNT="/mnt/mirror"
BACKUPMNT="/mnt/backup"
BACKUPDECR="/mnt/backup/decrement/${LABEL}"
BACKUPMIRROR="/mnt/backup/mirror/${LABEL}"
BROTHERNAME=$(brothername)
BACKUPHOST=$(backuphost)




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
			rsync -aH --timeout=3600 --inplace --delete-before --exclude-from="/etc/clsync/synchandler/lxc/rsync.exclude" "$excludefrom" --include-from="${LISTFILE}" --exclude='*' "$FROM"/ "$TO"/
			rc0="$?"
		else
			sleep $[ 3600 + $RANDOM % 1800 ]
			rc0="128"
		fi
	else
		sleep $[ 3600 + $RANDOM % 1800 ]
		rc0="128"
	fi

	if mount | grep "$BACKUPMNT" > /dev/null; then
		if ping -w 1 -qc 5 -i 0.1 $BACKUPHOST > /dev/null; then
			if [ ! -d "$BACKUPDECR" ]; then
				mkdir -p "$BACKUPDECR"
			fi
			rsync -aH --timeout=3600 --inplace --delete-before --exclude-from="/etc/clsync/synchandler/lxc/rsync.exclude" "$excludefrom" --include-from="${LISTFILE}" --exclude='*' --backup --backup-dir="$BACKUPDECR"/ "$FROM"/ "$BACKUPMIRROR"/ 
			rc1="$?"
		else
			sleep $[ 3600 + $RANDOM % 1800 ]
			rc1="128"
		fi
	else
		sleep $[ 3600 + $RANDOM % 1800 ]
		rc1='128'
	fi

	case $rc0 in
		0)
			;;
		23)
			;;
		24)
			;;
		*)
			exit $rc0
			;;
	esac

	case $rc1 in
		0)
			;;
		23)
			;;
		24)
			;;
		*)
			exit $rc1
			;;
	esac
}

case "$ACTION" in
	rsynclist)
		rsynclist "$ARG0" "$ARG1"
		;;
esac

exit 0

