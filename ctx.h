/*
    clsync - file tree sync utility based on inotify

    Copyright (C) 2013  Dmitry Yu Okunev <dyokunev@ut.mephi.ru> 0x8E30679C

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


#ifndef __CLSYNC_CTX_H
#define __CLSYNC_CTX_H

#include <regex.h>
#ifdef CAPABILITIES_SUPPORT
#	include <sys/capability.h>	// __u32
#endif

#define	MAX_BLOCKTHREADS	(1<<4)

#define register_blockthread(thread) {\
		critical_on (ctx_p->blockthread_count >= MAX_BLOCKTHREADS);\
		ctx_p->blockthread[ctx_p->blockthread_count++] = pthread_self();\
		debug(3, "register_blockthread(): ctx_p->blockthread_count -> %i", ctx_p->blockthread_count);\
	}

#define OPTION_FLAGS		(1<<10)
#define OPTION_LONGOPTONLY	(1<<9)
#define OPTION_CONFIGONLY	(1<<8)
#define NOTOPTION		(3<<8)
enum flags_enum {
	WATCHDIR	= 'W',
	SYNCHANDLER	= 'S',
	RULESFILE	= 'R',
	DESTDIR		= 'D',
	SOCKETPATH	= 's',

	HELP		= 'h',
	CONFIGFILE	= 'H',
	CONFIGBLOCK	= 'K',
	BACKGROUND	= 'b',
	UID		= 'u',
	GID		= 'g',
	CAP_PRESERVE	= 'C',
	THREADING	= 'p',
	RETRIES		= 'r',
	OUTPUT_METHOD	= 'Y',
	EXCLUDEMOUNTPOINTS = 'X',
	PIDFILE		= 'z',
	CLUSTERIFACE	= 'c',
	CLUSTERMCASTIPADDR = 'm',
	CLUSTERMCASTIPPORT = 'P',
	CLUSTERTIMEOUT	= 'G',
	CLUSTERNODENAME = 'n',
	CLUSTERHDLMIN	= 'o',
	CLUSTERHDLMAX	= 'O',
	DELAY		= 't',
	BFILEDELAY	= 'T',
	SYNCDELAY	= 'w',
	BFILETHRESHOLD	= 'B',
	DEBUG		= 'd',
	QUIET		= 'q',
	VERBOSE		= 'v',
	OUTLISTSDIR	= 'L',
	AUTORULESW	= 'A',
	MODE		= 'M',
	IGNOREEXITCODE	= 'x',
	DONTUNLINK	= 'U',
	INITFULL	= 'F',
	SYNCTIMEOUT	= 'k',
	LABEL		= 'l',
	SHOW_VERSION	= 'V',

	HAVERECURSIVESYNC 	=  0 | OPTION_LONGOPTONLY,
	RSYNCINCLIMIT		=  1 | OPTION_LONGOPTONLY,
	RSYNCPREFERINCLUDE	=  2 | OPTION_LONGOPTONLY,
	SYNCLISTSIMPLIFY	=  3 | OPTION_LONGOPTONLY,
	ONEFILESYSTEM		=  4 | OPTION_LONGOPTONLY,
	STATUSFILE		=  5 | OPTION_LONGOPTONLY,
	SKIPINITSYNC		=  6 | OPTION_LONGOPTONLY,
	ONLYINITSYNC		=  7 | OPTION_LONGOPTONLY,
	EXITONNOEVENTS		=  8 | OPTION_LONGOPTONLY,
	STANDBYFILE		=  9 | OPTION_LONGOPTONLY,
	EXITHOOK		= 10 | OPTION_LONGOPTONLY,
	CLUSTERSDLMAX		= 11 | OPTION_LONGOPTONLY,
	PREEXITHOOK		= 12 | OPTION_LONGOPTONLY,
	SOCKETAUTH		= 13 | OPTION_LONGOPTONLY,
	SOCKETMOD		= 14 | OPTION_LONGOPTONLY,
	SOCKETOWN		= 15 | OPTION_LONGOPTONLY,
	MAXITERATIONS		= 16 | OPTION_LONGOPTONLY,
	IGNOREFAILURES		= 17 | OPTION_LONGOPTONLY,
	DUMPDIR			= 18 | OPTION_LONGOPTONLY,
	CONFIGBLOCKINHERITS	= 19 | OPTION_LONGOPTONLY,
	MONITOR			= 20 | OPTION_LONGOPTONLY,
	SYNCHANDLERARGS0	= 21 | OPTION_LONGOPTONLY,
	SYNCHANDLERARGS1	= 22 | OPTION_LONGOPTONLY,
	CUSTOMSIGNALS		= 23 | OPTION_LONGOPTONLY,
	CHROOT			= 24 | OPTION_LONGOPTONLY,
	MOUNTPOINTS		= 25 | OPTION_LONGOPTONLY,
	SPLITTING		= 26 | OPTION_LONGOPTONLY,
	SYNCHANDLERUID		= 27 | OPTION_LONGOPTONLY,
	SYNCHANDLERGID		= 28 | OPTION_LONGOPTONLY,
	CAPS_INHERIT		= 29 | OPTION_LONGOPTONLY,
	CHECK_EXECVP_ARGS	= 30 | OPTION_LONGOPTONLY,
	PIVOT_ROOT		= 31 | OPTION_LONGOPTONLY,
	DETACH_NETWORK		= 32 | OPTION_LONGOPTONLY,
	DETACH_MISCELLANEA	= 33 | OPTION_LONGOPTONLY,
	ADDPERMITTEDHOOKFILES	= 34 | OPTION_LONGOPTONLY,
	SECCOMP_FILTER		= 35 | OPTION_LONGOPTONLY,
	FORGET_PRIVTHREAD_INFO	= 36 | OPTION_LONGOPTONLY,
	SECURESPLITTING		= 37 | OPTION_LONGOPTONLY,
	FTS_EXPERIMENTAL_OPTIMIZATION = 38 | OPTION_LONGOPTONLY,
	FORBIDDEVICES		= 39 | OPTION_LONGOPTONLY,
	CG_GROUPNAME		= 40 | OPTION_LONGOPTONLY,
	PERMIT_MPROTECT		= 41 | OPTION_LONGOPTONLY,
	SHM_MPROTECT		= 42 | OPTION_LONGOPTONLY,
	MODSIGN			= 43 | OPTION_LONGOPTONLY,
	CANCEL_SYSCALLS		= 44 | OPTION_LONGOPTONLY,
	EXITONSYNCSKIP		= 45 | OPTION_LONGOPTONLY,
	DETACH_IPC		= 46 | OPTION_LONGOPTONLY,
	PRIVILEGEDUID		= 47 | OPTION_LONGOPTONLY,
	PRIVILEGEDGID		= 48 | OPTION_LONGOPTONLY,
};
typedef enum flags_enum flags_t;

enum detachnetwork_way {
	DN_OFF = 0,
	DN_NONPRIVILEGED,
	DN_EVERYWHERE,
};
typedef enum detachnetwork_way detachnetwork_way_t;

enum pivotroot_way {
	PW_OFF    = 0,
	PW_DIRECT,
	PW_AUTO,
	PW_AUTORO,
};
typedef enum pivotroot_way pivotroot_way_t;

enum capsinherit {
	CI_DONTTOUCH = 0,
	CI_PERMITTED,
	CI_CLSYNC,
	CI_EMPTY,
};
typedef enum capsinherit capsinherit_t;

enum mode_id {
	MODE_UNSET	= 0,
	MODE_SIMPLE,
	MODE_DIRECT,
	MODE_SHELL,
	MODE_RSYNCSHELL,
	MODE_RSYNCDIRECT,
	MODE_RSYNCSO,
	MODE_SO,
};
typedef enum mode_id mode_id_t;

enum queue_id {
	QUEUE_NORMAL,
	QUEUE_BIGFILE,
	QUEUE_INSTANT,
	QUEUE_LOCKWAIT,

	QUEUE_MAX,
	QUEUE_AUTO
};
typedef enum queue_id queue_id_t;

enum ruleactionsign_enum {
	RS_REJECT	= 0,
	RS_PERMIT	= 1
};
typedef enum ruleactionsign_enum ruleactionsign_t;

enum ruleaction_enum {
	RA_NONE			 = 0x00,
	RA_MONITOR		 = 0x01,
	RA_SYNC			 = 0x02,
	RA_WALK			 = 0x04,
	RA_ALL			 = 0x0f,
};
typedef enum ruleaction_enum ruleaction_t;

// signals (man 7 signal)
enum sigusr_enum {
	SIGUSR_THREAD_GC	= 10,
	SIGUSR_INITSYNC  	= 12,
	SIGUSR_BLOPINT		= 16,
	SIGUSR_DUMP		= 29,
};

struct rule {
	int		num;
	regex_t		expr;
	mode_t		objtype;
	ruleaction_t	perm;
	ruleaction_t	mask;
};
typedef struct rule rule_t;

struct queueinfo {
	unsigned int 	collectdelay;
	time_t		stime;
};
typedef struct queueinfo queueinfo_t;

struct api_functs {
	api_funct_init   init;
	api_funct_sync   sync;
	api_funct_rsync  rsync;
	api_funct_deinit deinit;
};
typedef struct api_functs api_functs_t;

struct notifyenginefuncts {
	int ( *wait ) ( struct ctx *ctx_p, struct indexes *indexes_p, struct timeval *tv_p );
	int ( *handle ) ( struct ctx *ctx_p, struct indexes *indexes_p );
	int ( *add_watch_dir ) ( struct ctx *ctx_p, struct indexes *indexes_p, const char *const accpath );
};

enum shflags {
	SHFL_NONE		= 0x00,
	SHFL_RSYNC_ARGS		= 0x01,
	SHFL_INCLUDE_LIST	= 0x02,
	SHFL_INCLUDE_LIST_PATH	= 0x04,
	SHFL_EXCLUDE_LIST_PATH	= 0x08,
};
typedef enum shflags shflags_t;

enum shargsid {
	SHARGS_PRIMARY = 0,
	SHARGS_INITIAL,
	SHARGS_MAX,
};

struct synchandler_args {
	char	*v[MAXARGUMENTS];
	int	 c;
	char	 isexpanded[MAXARGUMENTS];
};
typedef struct synchandler_args synchandler_args_t;

#define STATE_STARTING(state_p) (state_p == NULL)
enum state_enum {
	STATE_EXIT 	= 0,
	STATE_STARTING,
	STATE_RUNNING,
	STATE_SYNCHANDLER_ERR,
	STATE_REHASH,
	STATE_PREEXIT,
	STATE_TERM,
	STATE_THREAD_GC,
	STATE_INITSYNC,
	STATE_HOLDON,
	STATE_UNKNOWN
};
typedef enum state_enum state_t;

enum stat_fields {
	STAT_FIELD_RESET		= 0x0000,
	STAT_FIELD_DEV			= 0x0001,
	STAT_FIELD_INO			= 0x0002,
	STAT_FIELD_MODE			= 0x0004,
	STAT_FIELD_NLINK		= 0x0008,
	STAT_FIELD_UID			= 0x0010,
	STAT_FIELD_GID			= 0x0020,
	STAT_FIELD_RDEV			= 0x0040,
	STAT_FIELD_SIZE			= 0x0080,
	STAT_FIELD_BLKSIZE		= 0x0100,
	STAT_FIELD_BLOCKS		= 0x0200,
	STAT_FIELD_ATIME		= 0x0400,
	STAT_FIELD_MTIME		= 0x0800,
	STAT_FIELD_CTIME		= 0x1000,

	STAT_FIELD_ALL			= 0x1ff7,
};

enum syscall_bitmask {
	CSC_RESET	= 0x00,
	CSC_MON_STAT	= 0x01,
};

#define CAP_PRESERVE_TRY (1<<16)

struct ctx {
#ifndef LIBCLSYNC
	volatile state_t state;
	pid_t  pid;
	char   pid_str[65];
	size_t pid_str_len;
	uid_t uid;
	gid_t gid;
	uid_t privileged_uid;
	gid_t privileged_gid;
	uid_t synchandler_uid;
	gid_t synchandler_gid;
#ifdef CAPABILITIES_SUPPORT
	__u32 caps;
#endif
	pid_t child_pid[MAXCHILDREN];	// Used only for non-pthread mode
	int   children;			// Used only for non-pthread mode
	uint32_t iteration_num;
	rule_t rules[MAXRULES];
	size_t rules_count;
	dev_t st_dev;
#endif
	char *flags_values_raw[OPTION_FLAGS];
	int flags[OPTION_FLAGS];
	int flags_set[OPTION_FLAGS];
#ifndef LIBCLSYNC
	char *config_path;
	const char *config_block;
	char *customsignal[MAXSIGNALNUM + 1];
	char *label;
	char *watchdir;
	char *pidfile;
	char *standbyfile;
	char *exithookfile;
	char *preexithookfile;
	char *destdir;
	char *destproto;
	char *watchdirwslash;
	char *destdirwslash;
	char *statusfile;
	char *socketpath;
	char *dump_path;
#ifdef CGROUP_SUPPORT
	char *cg_groupname;
#endif
	int socket;
	mode_t socketmod;
	uid_t  socketuid;
	gid_t  socketgid;
#ifdef CLUSTER_SUPPORT
	char *cluster_iface;
	char *cluster_mcastipaddr;
	char *cluster_nodename;
	uint32_t cluster_nodename_len;
	uint16_t cluster_mcastipport;
	uint16_t cluster_hash_dl_min;
	uint16_t cluster_hash_dl_max;
	uint16_t cluster_scan_dl_max;
	unsigned int cluster_timeout;
#endif
	size_t watchdirlen;
	size_t destdirlen;
	size_t watchdirsize;
	size_t destdirsize;
	size_t watchdirwslashsize;
	size_t destdirwslashsize;
	short int watchdir_dirlevel;
	char *handlerfpath;
	void *handler_handle;
	api_functs_t handler_funct;
	char  *rulfpath;
	size_t rulfpathsize;
	char *listoutdir;
	struct notifyenginefuncts notifyenginefunct;
	int retries;
	size_t bfilethreshold;
	unsigned int syncdelay;
	queueinfo_t _queues[QUEUE_MAX];	// TODO: remove this from here
	unsigned int rsyncinclimit;
	time_t synctime;
	unsigned int synctimeout;
	sigset_t *sigset;
	char isignoredexitcode[ ( 1 << 8 )];
	pthread_t blockthread[MAX_BLOCKTHREADS];
	size_t    blockthread_count;

	char *chroot_dir;

#ifdef CAPABILITIES_SUPPORT
	char *permitted_hookfile[MAXPERMITTEDHOOKFILES + 1];
	int   permitted_hookfiles;
#endif

#ifdef UNSHARE_SUPPORT
# ifdef GETMNTENT_SUPPORT
	char *mountpoint[MAXMOUNTPOINTS + 1];
	int   mountpoints;
# endif
#endif

	synchandler_args_t synchandler_args[SHARGS_MAX];
	shflags_t synchandler_argf;
#endif // ifndef LIBCLSYNC
	void *indexes_p;
	void *fsmondata;
};
typedef struct ctx ctx_t;

#endif

