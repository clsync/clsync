/*
    clsync - file tree sync utility based on fanotify and inotify

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

#define _GNU_SOURCE
#define _XOPEN_SOURCE 700
#define _LARGEFILE64_SOURCE

#define PROGRAM "clsync"
#define VERSION_MAJ	0
#define VERSION_MIN	1
#define AUTHOR "Dmitry Yu Okunev <dyokunev@ut.mephi.ru> 0x8E30679C"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <getopt.h>
#include <limits.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <errno.h>
#include <ctype.h>
#include <regex.h>
#include <signal.h>
#include <wait.h>
#include <fts.h>
#ifdef FANOTIFY_SUPPORT
#include <sys/fanotify.h>
#endif
#include <sys/inotify.h>
#include <sys/time.h>
#include <dirent.h>
#include <glib.h>
#include <sys/utsname.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <libgen.h>
#include <pthread.h>

#ifdef HAVE_CAPABILITIES
#include <sys/capability.h>	// for capset()/capget() for --preserve-file-access
#include <sys/prctl.h>		// for prctl() for --preserve-fil-access
#endif

#include "configuration.h"
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef MIN
#define MIN(a,b) ((a)>(b)?(b):(a))
#endif

#ifndef MAX
#define MAX(a,b) ((a)>(b)?(a):(b))
#endif

#ifndef IN_CREATE_SELF
#define IN_CREATE_SELF IN_CREATE
#endif

#ifdef _DEBUG
#define DEBUGV(...) __VA_ARGS__
#else
#define DEBUGV(...)
#endif

#ifdef PARANOID
#define PARANOIDV(...) __VA_ARGS__
#else
#define PARANOIDV(...)
#endif

#define TOSTR(a) # a
#define XTOSTR(a) TOSTR(a)

#define COLLECTDELAY_INSTANT ((unsigned int)~0)

#define OPTION_CONFIGONLY (1<<8)
enum flags_enum {
	HELP		= 'h',
	CONFIGPATH	= 'H',
	CONFIGBLOCK	= 'K',
	BACKGROUND	= 'b',
	UID		= 'u',
	GID		= 'g',
	CAP_PRESERVE_FILEACCESS = 'C',
	PTHREAD		= 'p',
	SYSLOG		= 'Y',
	PIDFILE		= 'z',
#ifdef CLUSTER_SUPPORT
	CLUSTERIFACE	= 'c',
	CLUSTERMCASTIPADDR = 'm',
	CLUSTERMCASTIPPORT = 'P',
	CLUSTERTIMEOUT	= 'W',
	CLUSTERNODENAME = 'n',
	CLUSTERHDLMIN	= 'o',
	CLUSTERHDLMAX	= 'O',
	CLUSTERSDLMAX	= 's',
#endif
	DELAY		= 't',
	BFILEDELAY	= 'T',
	SYNCDELAY	= 'w',
	BFILETHRESHOLD	= 'B',
	DEBUG		= 'D',
	QUIET		= 'q',
	VERBOSE		= 'v',
	OUTLISTSDIR	= 'd',
	ENABLEINITIALSYNC = 'S',
	SYNCLISTSIMPLIFY= 'Z',
	AUTORULESW	= 'A',
	SYNCHANDLERSO	= 'M',
	RSYNC		= 'R',
	RSYNCINCLIMIT	= 'L',
	RSYNC_PREFERINCLUDE= 'I',
	IGNOREEXITCODE	= 'x',
	DONTUNLINK	= 'U',
	INITFULL	= 'F',
	SYNCTIMEOUT	= 'k',
#ifdef FANOTIFY_SUPPORT
	FANOTIFY	= 'f',
#endif
	INOTIFY		= 'i',
	LABEL		= 'l',
	SHOW_VERSION	= 'V',

	WATCHDIR	= 0|OPTION_CONFIGONLY,
	SYNCHANDLER	= 1|OPTION_CONFIGONLY,
	RULESPATH	= 2|OPTION_CONFIGONLY,
	DESTDIR		= 3|OPTION_CONFIGONLY,

};
typedef enum flags_enum flags_t;

enum queue_enum {
	QUEUE_NORMAL,
	QUEUE_BIGFILE,
	QUEUE_INSTANT,
	QUEUE_MAX,
	QUEUE_AUTO
};
typedef enum queue_enum queue_id_t;

enum ruleactionsign_enum {
	RS_REJECT	= 0,
	RS_PERMIT	= 1
};
typedef enum ruleactionsign_enum ruleactionsign_t;

enum ruleaction_enum {
	RA_NONE		 = 0x00,
	RA_MONITOR	 = 0x01,
	RA_WALK		 = 0x02,
	RA_ALL		 = 0xff
};
typedef enum ruleaction_enum ruleaction_t;

enum paramsource_enum {
	PS_UNKNOWN	 = 0,
	PS_ARGUMENT,
	PS_CONFIG
};
typedef enum paramsource_enum paramsource_t;

// signals (man 7 signal)
enum sigusr_enum {
	SIGUSR_PTHREAD_GC	= 10,
	SIGUSR_INITSYNC  	= 12,
	SIGUSR_BLOPINT		= 16
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

struct api_eventinfo {
	uint32_t	 evmask;
	uint32_t	 flags;
	size_t		 path_len;
	const char	*path;
};
typedef struct api_eventinfo api_eventinfo_t;

struct options;
struct indexes;
typedef int(*api_funct_init)  (struct options *, struct indexes *);
typedef int(*api_funct_sync)  (int n, api_eventinfo_t *);
typedef int(*api_funct_deinit)();

struct api_functs {
	api_funct_init   init;
	api_funct_sync   sync;
	api_funct_deinit deinit;
};
typedef struct api_functs api_functs_t;

struct options {
	uid_t uid;
	gid_t gid;
	rule_t rules[MAXRULES];
	int flags[1<<10];
	int flags_set[1<<10];
	char *config_path;
	char *config_block;
	char *label;
	char *watchdir;
	char *pidfile;
	char *destdir;
	char *watchdirwslash;
	char *destdirwslash;
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
	char *rulfpath;
	char *listoutdir;
	int notifyengine;
	size_t bfilethreshold;
	unsigned int syncdelay;
	queueinfo_t _queues[QUEUE_MAX];	// TODO: remove this from here
	unsigned int rsyncinclimit;
	time_t synctime;
	unsigned int synctimeout;
	sigset_t *sigset;
	char isignoredexitcode[(1<<8)];
};
typedef struct options options_t;

enum notifyengine_enum {
	NE_UNDEFINED = 0,
#ifdef FANOTIFY_SUPPORT
	NE_FANOTIFY,
#endif
	NE_INOTIFY
};
typedef enum notifyengine_enum notifyenfine_t;

#define STATE_STARTING(state_p) (state_p == NULL)
enum state_enum {
	STATE_EXIT 	= 0,
	STATE_RUNNING,
	STATE_REHASH,
	STATE_TERM,
	STATE_PTHREAD_GC,
	STATE_INITSYNC
};
typedef enum state_enum state_t;

enum eventinfo_flags {
	EVIF_RECURSIVELY	= 0x00000001
};

struct eventinfo {
	uint32_t	evmask;
	int		wd;
	size_t		fsize;
	uint32_t	flags;
};
typedef struct eventinfo eventinfo_t;

struct indexes {
	GHashTable *wd2fpath_ht;			// watching descriptor -> file path
	GHashTable *fpath2wd_ht;			// file path -> watching descriptor
	GHashTable *fpath2ei_ht;			// file path -> event information
	GHashTable *exc_fpath_ht;			// excluded file path
	GHashTable *exc_fpath_coll_ht[QUEUE_MAX];	// excluded file path aggregation hashtable for every queue
	GHashTable *fpath2ei_coll_ht[QUEUE_MAX];	// "file path -> event information" aggregation hashtable for every queue
	GHashTable *out_lines_aggr_ht;			// output lines aggregation hashtable
};
typedef struct indexes indexes_t;

typedef int (*thread_callbackfunct_t)(options_t *options_p, char **argv);
struct threadinfo {
	int			  thread_num;
	thread_callbackfunct_t 	  callback;
	char 			**argv;
	pthread_t		  pthread;
	int			  exitcode;
	int			  errcode;
	state_t			  state;
	options_t		 *options_p;
	time_t			  starttime;
	time_t			  expiretime;
	int			  child_pid;
};
typedef struct threadinfo threadinfo_t;

enum pthread_mutex_id {
	PTHREAD_MUTEX_STATE,
	PTHREAD_MUTEX_MAX
};


struct threadsinfo {
	pthread_mutex_t		  mutex[PTHREAD_MUTEX_MAX];
	pthread_cond_t		  cond [PTHREAD_MUTEX_MAX];
	char			  mutex_init;
	int			  allocated;
	int			  used;
	threadinfo_t 		 *threads;
	threadinfo_t 		**threadsstack;	// stack of threadinfo_t to be used on thread_new()
	int			  stacklen;
};
typedef struct threadsinfo threadsinfo_t;

struct dosync_arg {
	int evcount;
	char excf_path[PATH_MAX+1];
	char outf_path[PATH_MAX+1];
	FILE *outf;
	options_t *options_p;
	indexes_t *indexes_p;
	void *data;
	int linescount;
	api_eventinfo_t *api_ei;
	size_t api_ei_size;
	char buf[BUFSIZ+1];
};

struct doubleentry {
	size_t  size0;
	size_t  size1;
	size_t  alloc0;
	size_t  alloc1;
	void   *dat0;
	void   *dat1;
};

struct pushdoubleentry_arg {
	int			 allocated;
	int			 total;
	size_t			 size;
	struct doubleentry	*entry;
};

struct entry {
	size_t  size;
	size_t  alloc;
	void   *dat;
};

struct pushentry_arg {
	int		 allocated;
	int		 total;
	size_t		 size;
	struct entry	*entry;
};

enum initsync {
	INITSYNC_UNKNOWN = 0,
	INITSYNC_FULL,
	INITSYNC_SUBDIR
};
typedef enum initsync initsync_t;

struct sighandler_arg {
//	options_t *options_p;
//	indexes_t *indexes_p;
	pthread_t  pthread_parent;
	int	  *exitcode_p;
	sigset_t  *sigset_p;
};
typedef struct sighandler_arg sighandler_arg_t;


