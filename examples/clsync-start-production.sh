
ulimit -n 65536

clsync -z /opt/backup_engine/clsync.pid -F -R -w15 -t 5 -d /opt/backup_engine/list "$(readlink -f /srv/lxc)" /opt/backup_engine/clsync-synchandler-production.sh /opt/backup_engine/clsync.rules > /opt/backup_engine/clsync.log 2>&1 &

