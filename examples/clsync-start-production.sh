
ulimit -n 65536

clsync -Y -z /opt/backup_engine/clsync.pid -F -R -w15 -t5 -d /opt/backup_engine/list "$(readlink -f /srv/lxc)" /opt/backup_engine/clsync-synchandler-production.sh /opt/backup_engine/clsync.rules &

