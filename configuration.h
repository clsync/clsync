

#ifndef BUFSIZ
#define BUFSIZ				(1<<16)
#endif

// don't do to much rules, it will degrade performance
#define MAXRULES			(1<<8)

// there's no need in more than 256 arguments while running action-script, IMHO :)
#define MAXARGUMENTS			(1<<8)

// clsync should be used, if there's more than 5-10 nodes. So the limit in 255 is quite enough. :)
#define MAXNODES			((1<<8)-1)

// max user/group lengths
#define USER_LEN			(1<<8)
#define GROUP_LEN			USER_LEN

// control socket listen backlog (man 2 listen)
#define SOCKET_BACKLOG			2

// control socket clients limit
#define SOCKET_CLIENTS_MAX		8

// children count limit
#define MAXCHILDREN			(1<<8)

#define DEFAULT_RULES_PERM		RA_ALL
#define DEFAULT_NOTIFYENGINE		NE_INOTIFY
#define DEFAULT_COLLECTDELAY		30
#define DEFAULT_SYNCDELAY		(DEFAULT_COLLECTDELAY)
#define DEFAULT_BFILETHRESHOLD		(128 * 1024 * 1024)
#define DEFAULT_BFILECOLLECTDELAY	1800
#define DEFAULT_LABEL			"nolabel"
#define DEFAULT_RSYNCINCLUDELINESLIMIT	20000
#define DEFAULT_SYNCTIMEOUT		(3600 * 24)
#define DEFAULT_CLUSTERTIMEOUT		1000
#define DEFAULT_CLUSTERIPADDR		"227.108.115.121"
#define DEFAULT_CLUSTERIPPORT		40079
#define DEFAULT_CLUSTERHDLMIN		1
#define DEFAULT_CLUSTERHDLMAX		16
#define DEFAULT_CLUSTERSDLMAX		32
#define DEFAULT_CONFIG_BLOCK		"default"
#define DEFAULT_RETRIES			1

#define FANOTIFY_FLAGS			(FAN_CLOEXEC|FAN_UNLIMITED_QUEUE|FAN_UNLIMITED_MARKS)
#define FANOTIFY_EVFLAGS		(O_LARGEFILE|O_RDONLY|O_CLOEXEC)

#define FANOTIFY_MARKMASK		(FAN_OPEN|FAN_MODIFY|FAN_CLOSE|FAN_ONDIR|FAN_EVENT_ON_CHILD)

#define INOTIFY_FLAGS			0
					//(FD_CLOEXEC)

#define INOTIFY_MARKMASK		(IN_ATTRIB|IN_CLOSE_WRITE|IN_CREATE|IN_DELETE|IN_DELETE_SELF|IN_MOVE_SELF|IN_MOVED_FROM|IN_MOVED_TO|IN_MODIFY|IN_DONT_FOLLOW)

#define COUNTER_LIMIT			(1<<10)

#define SLEEP_SECONDS			1

#define KILL_TIMEOUT			60

#define ALLOC_PORTION			(1<<10) /* 1  KiX */
#define CLUSTER_WINDOW_BUFSIZE_PORTION	(1<<20) /* 1  MiB */
#define CLUSTER_PACKET_MAXSIZE		(1<<24) /* 16 MiB */

#define CONFIG_PATHS 			{ ".clsync.conf", "/etc/clsync/clsync.conf", NULL } /* "~/.clsync.conf" and "/etc/clsync/clsync.conf" */

#define API_PREFIX			"clsyncapi_"
