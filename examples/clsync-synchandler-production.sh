#!/bin/bash

FROM="$(readlink -f /srv/lxc)"
TO="/mnt/mirror/containers"
DECR="/mnt/decrement"

if [ ! -d $TO ]; then
	mkdir -p $TO
fi

if [ ! -d $DECR ]; then
	mkdir -p $DECR
fi

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

        rsync -avH --inplace --append-verify --delete-before --exclude-from="/opt/backup_engine/rsync.exclude" "$excludefrom" --include-from="${LISTFILE}" --exclude='*' --backup --backup-dir="$DECR"/ "$FROM"/ "$TO"/
}

case "$ACTION" in
        rsynclist)
                rsynclist "$ARG0" "$ARG1"
                ;;
esac

rc="$?"
case $rc in
        0)
                exit 0
                ;;

        23)
		# Notify monitoring system and do something to resync
                exit 0
                ;;

        24)
                exit 0
                ;;
esac

sleep 60 && /opt/backup_engine/clsync-start-production.sh &

# Notify monitoring system about problems with clsync
exit $rc

