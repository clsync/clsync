exampledir=$(docdir)/examples

# example_DATA = \
#  $(wildcard $(srcdir)/*.c) \
#  $(wildcard $(srcdir)/*.sh)

dist_example_DATA = clsync-synchandler-rsyncso.c clsync-synchandler-so.c \
	clsync@.service

dist_example_SCRIPTS = clsync-start-cluster.sh			\
	clsync-start-rsyncdirect.sh clsync-start-rsyncshell.sh	\
	clsync-start-rsyncso.sh clsync-start-so.sh		\
	clsync-synchandler-rsyncshell.sh \
	clsync-systemd.sh \
	test.sh

# find production -type f -name '*.sh'
nobase_dist_example_SCRIPTS =					\
	 production/etc/clsync/hooks/lxc/exit-backup.sh		\
	 production/etc/clsync/hooks/lxc/exit-brother.sh	\
	 production/etc/clsync/synchandler/lxc/backup.sh	\
	 production/etc/clsync/synchandler/lxc/brother.sh

# find production -type f -not -name '*.sh'
nobase_dist_example_DATA = production/etc/clsync/rules/hpc	\
	 production/etc/clsync/rules/hpc-backup			\
	 production/etc/clsync/rules/lxc			\
	 production/etc/clsync/synchandler/hpc/handler-backup.c	\
	 production/etc/clsync/synchandler/hpc/handler-pdcp.c	\
	 production/etc/clsync/synchandler/hpc/Makefile		\
	 production/etc/clsync/synchandler/lxc/rsync.exclude	\
	 production/etc/clsync/clsync.conf
