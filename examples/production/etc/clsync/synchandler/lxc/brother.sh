#!/bin/bash -x

ACTION="$1"
LABEL="$2"
ARG0="$3"
ARG1="$4"

BROTHERMNT="/mnt/mirror"
BROTHERNAME=$(brothername)

CLUSTERNAME=$(clustername)

FROM="/srv/lxc/${LABEL}"
#TO="/mnt/mirror/${LABEL}"
TO="rsync://${CLUSTERNAME}@${BROTHERNAME}/lxc/${LABEL}"

if [ "$CLSYNC_STATUS" = "initsync" ]; then
	STATICEXCLUDE=''
else
	STATICEXCLUDE='--exclude-from=/etc/clsync/synchandler/lxc/rsync.exclude'
fi

tmpfile=$(mktemp -p "" clsync-rsync-"$LABEL"-brother.err.XXXXXXXXXX)
cleanup() {
	[[ -s "${tmpfile}" ]] || rm "${tmpfile}"
}
trap cleanup EXIT

function rsynclist() {
	LISTFILE="$1"
	EXCLISTFILE="$2"

	excludefrom=''
	if [ "$EXCLISTFILE" != "" ]; then
		excludefrom="--exclude-from=${EXCLISTFILE}"
	fi

#	if mount | grep "$BROTHERMNT" > /dev/null; then
		if ping -w 1 -qc 5 -i 0.1 "$BROTHERNAME" > /dev/null; then
			#if [ ! -d "$TO" ]; then
			#	mkdir -p "$TO"
			#fi
			exec rsync --password-file="/etc/rsyncd.pass" -aH --timeout=3600 --inplace --delete-before $STATICEXCLUDE "$excludefrom" --include-from="${LISTFILE}" --exclude='*' "$FROM"/ "$TO"/ 2>"${tmpfile}"
		else
			sleep $(( 3600 + RANDOM % 1800 ))
			exit 128
		fi
#	else
#		sleep $(( 3600 + RANDOM % 1800 ))
#		exit 128
#	fi
}

case "$ACTION" in
	rsynclist)
		rsynclist "$ARG0" "$ARG1"
		;;
esac

exit 0

