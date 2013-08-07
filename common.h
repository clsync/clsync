/*
    clsync - file tree sync utility based on fanotify and inotify

    Copyright (C) 2013  Dmitry Yu Okunev <xai@mephi.ru> 0x8E30679C

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

#define ALLOC_PORTION	(1<<10)

#define AUTHOR "Dmitry Yu Okunev <xai@mephi.ru> 0x8E30679C"

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
#include <dirent.h>
#include <glib.h>
#include "config.h"

#ifndef MIN
#define MIN(a,b) (a>b?b:a)
#endif

#ifndef MAX
#define MAX(a,b) (a>b?a:b)
#endif

#ifndef IN_CREATE_SELF
#define IN_CREATE_SELF IN_CREATE
#endif

#define COLLECTDELAY_INSTANT ((unsigned int)~0)

enum flags_enum {
	BACKGROUND	= 'b',
	PTHREAD		= 'p',
	HELP		= 'h',
	DELAY		= 't',
	BFILEDELAY	= 'T',
	COMMONDELAY	= 'w',
	DEBUG		= 'D',
	QUITE		= 'q',
	VERBOSE		= 'v',
	OUTLISTSDIR	= 'd',
	RSYNC		= 'R',
	RSYNCINCLIMIT	= 'L',
	RSYNC_PREFERINCLUDE= 'I',
	DONTUNLINK	= 'U',
	INITFULL	= 'F',
#ifdef FANOTIFY_SUPPORT
	FANOTIFY	= 'f',
#endif
	INOTIFY		= 'i',
	LABEL		= 'l',
	BFILETHRESHOLD	= 'B',
	VERSION		= 'V',
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

enum ruleaction_enum {
	RULE_END = 0,	// Terminator. To be able to end rules' chain
	RULE_ACCEPT,
	RULE_REJECT
};
typedef enum ruleaction_enum ruleaction_t;

// signals (man 7 signal)
enum sigusr_enum {
	SIGUSR_PTHREAD_GC = 10
};

struct rule {
	regex_t		expr;
	mode_t		objtype;
	ruleaction_t	action;
};
typedef struct rule rule_t;

struct queueinfo {
	unsigned int 	collectdelay;
	time_t		stime;
};
typedef struct queueinfo queueinfo_t;

struct options {
	rule_t rules[MAXRULES];
	int flags[1<<8];
	char *label;
	char *watchdir;
	size_t watchdirlen;
	char *actfpath;
	char *rulfpath;
	char *listoutdir;
	int notifyengine;
	size_t bfilethreshold;
	unsigned int commondelay;
	queueinfo_t _queues[QUEUE_MAX];	// TODO: remove this from here
	unsigned int rsyncinclimit;
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
	STATE_PTHREAD_GC
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
	state_t			  state;
};
typedef struct threadinfo threadinfo_t;

struct threadsinfo {
#ifdef PTHREAD_MUTEX
	pthread_mutex_t  _mutex;
	char		 _mutex_init;
#endif
	int		 allocated;
	int		 used;
	threadinfo_t 	*threads;
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
	char buf[BUFSIZ+1];
};

