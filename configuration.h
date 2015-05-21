#ifndef __CONFIGURATION_H
#define __CONFIGURATION_H


#ifndef BUFSIZ
#define BUFSIZ				(1<<16)
#endif

// don't do to much rules, it will degrade performance
#define MAXRULES			(1<<8)

// there's no need in more than 256 arguments while running action-script, IMHO :)
#define MAXARGUMENTS			(1<<8)

// clsync should be used, if there's more than 5-10 nodes. So the limit in 255 is quite enough. :)
#define MAXNODES			((1<<8)-1)

#define MAXSIGNALNUM			(1<<9)

// max user/group lengths
#define USER_LEN			(1<<8)
#define GROUP_LEN			USER_LEN

// control socket listen backlog (man 2 listen)
#define SOCKET_BACKLOG			2

// control socket connections limit in clsync
#define SOCKET_MAX_CLSYNC		8

// control socket connections limit in libclsync
#define SOCKET_MAX_LIBCLSYNC		(1<<16)

// children count limit
#define MAXCHILDREN			(1<<8)

#define MAXMOUNTPOINTS			(1<<8)
#define MAXPERMITTEDHOOKFILES		(1<<8)

#ifndef PIC
#	ifdef __CLSYNC_COMMON_H
#		ifndef DEFAULT_NOTIFYENGINE
#			ifdef __linux__
#				ifdef INOTIFY_SUPPORT
#					define DEFAULT_NOTIFYENGINE	NE_INOTIFY
#				endif
#			endif
#		endif
#		ifndef DEFAULT_NOTIFYENGINE
#			if __FreeBSD__ | __FreeBSD_kernel__
#				ifdef KQUEUE_SUPPORT
#					define DEFAULT_NOTIFYENGINE	NE_KQUEUE
#				endif
#			endif
#		endif
#		ifndef DEFAULT_NOTIFYENGINE
#			ifdef INOTIFY_SUPPORT
#				define DEFAULT_NOTIFYENGINE	NE_INOTIFY
#			endif
#		endif
#		ifndef DEFAULT_NOTIFYENGINE
#			ifdef GIO_SUPPORT
#				define DEFAULT_NOTIFYENGINE	NE_GIO
#			endif
#		endif
#		ifndef DEFAULT_NOTIFYENGINE
#			ifdef KQUEUE_SUPPORT
#				define DEFAULT_NOTIFYENGINE	NE_KQUEUE
#			endif
#		endif
#		ifndef DEFAULT_NOTIFYENGINE
#			ifdef BSM_SUPPORT
#				define DEFAULT_NOTIFYENGINE	NE_BSM
#			endif
#		endif
#		ifndef DEFAULT_NOTIFYENGINE
#			error No monitor subsystem supported
#			define  DEFAULT_NOTIFYENGINE		NE_UNDEFINED
#		endif
#	endif
#endif

#define DEFAULT_RULES_PERM		RA_ALL
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
#define DEFAULT_VERBOSE			3
#define DEFAULT_DUMPDIR			"/tmp/clsync-dump-%label%"
#define DEFAULT_DETACH_IPC		1

#define FANOTIFY_FLAGS			(FAN_CLOEXEC|FAN_UNLIMITED_QUEUE|FAN_UNLIMITED_MARKS)
#define FANOTIFY_EVFLAGS		(O_LARGEFILE|O_RDONLY|O_CLOEXEC)

#define FANOTIFY_MARKMASK		(FAN_OPEN|FAN_MODIFY|FAN_CLOSE|FAN_ONDIR|FAN_EVENT_ON_CHILD)

#define INOTIFY_FLAGS			(IN_CLOEXEC)

#define INOTIFY_MARKMASK		(IN_ATTRIB|IN_CLOSE_WRITE|IN_CREATE|IN_DELETE|IN_DELETE_SELF|IN_MOVE_SELF|IN_MOVED_FROM|IN_MOVED_TO|IN_MODIFY|IN_DONT_FOLLOW)

#define COUNTER_LIMIT			(1<<10)

#define SLEEP_SECONDS			1

#define KILL_TIMEOUT			60

#define ALLOC_PORTION			(1<<10) /* 1  KiX */
#define CLUSTER_WINDOW_BUFSIZE_PORTION	(1<<20) /* 1  MiB */
#define CLUSTER_PACKET_MAXSIZE		(1<<20) /* 1  MiB */
#define CLUSTER_WINDOW_PCKTLIMIT	(1<<20) /* 1  Ki packets */

#define CONFIG_PATHS 			{ ".clsync.conf", "/etc/clsync/clsync.conf", "/etc/clsync.conf", "/usr/local/etc/clsync/clsync.conf", "/usr/local/etc/clsync.conf", NULL } /* "~/.clsync.conf", "/etc/clsync/clsync.conf" ... */

#define API_PREFIX			"clsyncapi_"

#define DUMP_DIRMODE			0750
#define DUMP_FILEMODE			0644

#define DEFAULT_CP_PATH			"cp"
#define	DEFAULT_RSYNC_PATH		"rsync"

// size of event chain size to be processes at a time
#define KQUEUE_EVENTLISTSIZE		256

#define AUDITPIPE_PATH "/dev/auditpipe"
#define AUDIT_CONTROL_PATH "/etc/security/audit_control"
#define AUDIT_CONTROL_INITSCRIPT "/etc/rc.d/auditd"
#define AUDIT_CONTROL_HEADER "#clsync\n"
#define AUDIT_CONTROL_CONTENT "\n\
dir:/var/audit\n\
flags:fc,fd,fw,fm,cl\n\
minfree:0\n\
naflags:fc,fd,fw,fm,cl\n\
policy:cnt\n\
filesz:1M\n\
expire-after:20M\n\
"

#define DTRACE_PATH			"dtrace"

#define PIVOT_AUTO_DIR			"/dev/shm/clsync-rootfs"
#define	TMPDIR_TEMPLATE			"/tmp/clsync-XXXXXX"

#define SYSLOG_BUFSIZ			(1<<16)
#define SYSLOG_FLAGS			(LOG_PID|LOG_CONS)
#define SYSLOG_FACILITY			LOG_DAEMON

#define CLSYNCSOCK_WINDOW		(1<<8)

#define DEFAULT_SYNCHANDLER_ARGS_SIMPLE		"sync \%label\% \%EVENT-MASK\% \%INCLUDE-LIST\%"
#define DEFAULT_SYNCHANDLER_ARGS_DIRECT		"\%INCLUDE-LIST\% \%destination-dir\%/"
#define DEFAULT_SYNCHANDLER_ARGS_SHELL_NR	"synclist \%label\% \%INCLUDE-LIST-PATH\%"
#define DEFAULT_SYNCHANDLER_ARGS_SHELL_R	"initialsync \%label\% \%INCLUDE-LIST\%"
#define DEFAULT_SYNCHANDLER_ARGS_RDIRECT_E	"-aH --delete --exclude-from \%EXCLUDE-LIST-PATH\% --include-from \%INCLUDE-LIST-PATH\% --exclude=* \%watch-dir\%/ \%destination-dir\%/"
#define DEFAULT_SYNCHANDLER_ARGS_RDIRECT_I	"-aH --delete --include-from \%INCLUDE-LIST-PATH\% --exclude=* \%watch-dir\%/ \%destination-dir\%/"
#define DEFAULT_SYNCHANDLER_ARGS_RSHELL_E	"rsynclist \%label% \%INCLUDE-LIST-PATH\% %EXCLUDE-LIST-PATH%"
#define DEFAULT_SYNCHANDLER_ARGS_RSHELL_I	"rsynclist \%label% \%INCLUDE-LIST-PATH\%"

#define RSYNC_ARGS_E	{ 		\
		"-aH", 			\
		"--delete", 		\
		"--exclude-from",	\
		"\%EXCLUDE-LIST-PATH\%",\
		"--include-from",	\
		"\%INCLUDE-LIST-PATH\%",\
		"--exclude=*",		\
		NULL }

#define RSYNC_ARGS_I	{ 		\
		"-aH", 			\
		"--delete", 		\
		"--include-from",	\
		"\%INCLUDE-LIST-PATH\%",\
		"--exclude=*",		\
		NULL }

#define DEFAULT_PRESERVE_CAPABILITIES	( CAP_TO_MASK(CAP_DAC_READ_SEARCH) | CAP_TO_MASK(CAP_SETUID) | CAP_TO_MASK(CAP_SETGID) | CAP_TO_MASK(CAP_KILL) )

#define DEFAULT_USER			"nobody"
#define DEFAULT_GROUP			"nogroup"
#define DEFAULT_UID			65534
#define DEFAULT_GID			65534
#define DEFAULT_CAPS_INHERIT		CI_EMPTY
#define DEFAULT_PIVOT_MODE		(PW_OFF)

#define DEVZERO				"/dev/zero"

// How long to wait on highloaded locks before fallback to mutexes
// See: doc/devel/thread-splitting/highload-locks/clsync-graph-comma.odc
// But optimal value can be very different on different systems
#define HL_LOCK_TRIES_INITIAL		(1<<13)

// Enable run-time auto-adjustment
#define HL_LOCK_TRIES_AUTO
// Iterations delay between adjustments (power of 2; 2^x)
#define HL_LOCK_AUTO_INTERVAL		7	/* 128 */
// Initial adjustment factor
#define HL_LOCK_AUTO_K			1.1
// Delay detection error threshold
#define HL_LOCK_AUTO_THREADHOLD		0.2
// Adjustment factor denominator
#define HL_LOCK_AUTO_DECELERATION	1.1
// Don't adjust if the factor is less than
#define HL_LOCK_AUTO_K_FINISH		0.001
// Upper limit
#define HL_LOCK_AUTO_LIMIT_HIGH		(1<<20)

#define HL_LOCK_NONPRIV_TRIES		(HL_LOCK_AUTO_LIMIT_HIGH << 6)

//#define READWRITE_SIGNALLING

#define CG_DEV_CONSOLE	"c 5:1"
#define CG_DEV_ZERO	"c 1:5"
#define CG_DEV_RANDOM	"c 1:8"
#define CG_DEV_URANDOM	"c 1:9"
#define CG_DEV_NULL	"c 1:3"

#define CG_ALLOWED_DEVICES {		\
		CG_DEV_CONSOLE	" rw",	\
		CG_DEV_ZERO	" r",	\
		CG_DEV_URANDOM	" r",	\
		CG_DEV_RANDOM	" r",	\
		CG_DEV_NULL	" w",	\
		NULL			\
	}

#define DEFAULT_CG_GROUPNAME	"clsync/%PID%"

// In nanoseconds
#define OUTPUT_LOCK_TIMEOUT		(100*1000*1000)
#define WAITPID_TIMED_GRANULARITY	 (30*1000*1000)

#define BSM_QUEUE_LENGTH_MAX		(1024*1024)
#define GIO_QUEUE_LENGTH_MAX		BSM_QUEUE_LENGTH_MAX


#endif
