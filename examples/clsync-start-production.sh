
ulimit -n 65536

clsync -K example-production -Y -z /opt/backup_engine/clsync.pid -F -M rsyncshell -w15 -t5 -L /opt/backup_engine/list -W "$(readlink -f /srv/lxc)" -S /opt/backup_engine/clsync-synchandler-production.sh -R /opt/backup_engine/clsync.rules &

