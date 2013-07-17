#
# Regular cron jobs for the clsync package
#
0 4	* * *	root	[ -x /usr/bin/clsync_maintenance ] && /usr/bin/clsync_maintenance
