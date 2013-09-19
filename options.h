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

#include <regex.h>

#define OPTION_LONGOPTONLY (1<<9)
#define OPTION_CONFIGONLY  (1<<8)
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
	CLUSTERMCASTIPADDR='m',
	CLUSTERMCASTIPPORT='P',
	CLUSTERTIMEOUT	= 'G',
	CLUSTERNODENAME = 'n',
	CLUSTERHDLMIN	= 'o',
	CLUSTERHDLMAX	= 'O',
	CLUSTERSDLMAX	= 's',
#endif
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
#ifdef FANOTIFY_SUPPORT
	FANOTIFY	= 'f',
#endif
	INOTIFY		= 'i',
	LABEL		= 'l',
	SHOW_VERSION	= 'V',

	WATCHDIR	= 'W',
	SYNCHANDLER	= 'S',
	RULESPATH	= 'R',
	DESTDIR		= 'D',

	HAVERECURSIVESYNC 	= 0|OPTION_LONGOPTONLY,
	RSYNCINCLIMIT		= 1|OPTION_LONGOPTONLY,
	RSYNCPREFERINCLUDE	= 2|OPTION_LONGOPTONLY,
	SYNCLISTSIMPLIFY	= 3|OPTION_LONGOPTONLY,
};
typedef enum flags_enum flags_t;

enum mode_id {
	MODE_UNSET	= 0,
	MODE_SIMPLE,
	MODE_SHELL,
	MODE_RSYNCSHELL,
	MODE_RSYNCDIRECT,
	MODE_SO,
};
typedef enum mode_id mode_id_t;

enum queue_id {
	QUEUE_NORMAL,
	QUEUE_BIGFILE,
	QUEUE_INSTANT,
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
	RA_NONE		 = 0x00,
	RA_MONITOR	 = 0x01,
	RA_WALK		 = 0x02,
	RA_ALL		 = 0xff
};
typedef enum ruleaction_enum ruleaction_t;

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

