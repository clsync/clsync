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


#ifndef __CLSYNC_COMMON_H
#define __CLSYNC_COMMON_H

#ifndef __linux__
#	ifdef HAVE_CAPABILITIES
#		undef HAVE_CAPABILITIES
#		warning Capabilities support can be built only on Linux
#	endif
#endif

#define _GNU_SOURCE
//#define _XOPEN_SOURCE 700
#define _LARGEFILE64_SOURCE

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
#include <signal.h>
#ifdef KQUEUE_SUPPORT
#	include <sys/event.h>
#endif
#ifdef INOTIFY_SUPPORT
#	include <sys/inotify.h>
#endif
#ifdef FANOTIFY_SUPPORT
#	include <sys/fanotify.h>
#endif
#include <sys/wait.h>
#include <fts.h>
#include <sys/time.h>
#include <dirent.h>
#include <sys/utsname.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <libgen.h>
#include <pthread.h>
#include <glib.h>

#include "configuration.h"
#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif

#include "clsync.h"
#include "port-hacks.h"
#include "posix-hacks.h"
#include "ctx.h"
#include "program.h"

#include <sys/param.h>

#ifndef IN_CREATE_SELF
#	define IN_CREATE_SELF IN_CREATE
#endif

#ifdef _DEBUG
#	define DEBUGV(...) __VA_ARGS__
#else
#	define DEBUGV(...)
#endif

#ifdef PARANOID
#	define PARANOIDV(...) __VA_ARGS__
#else
#	define PARANOIDV(...)
#endif

#ifdef _GNU_SOURCE
#	ifndef likely
#		define likely(x)    __builtin_expect(!!(x), 1)
#	endif
#	ifndef unlikely
#		define unlikely(x)  __builtin_expect(!!(x), 0)
#	endif
#else
#	ifndef likely
#		define likely(x)   (x)
#	endif
#	ifndef unlikely
#		define unlikely(x) (x)
#	endif
#endif

#ifndef offsetof
#	define offsetof(a, b) __builtin_offsetof(a, b)
#endif

// clang defines "__GNUC__", but not compatible with gnuc. Fixing.
#ifdef __clang__
#	ifdef __GNUC__
#		undef __GNUC__
#	endif
#endif

#define TOSTR(a) # a
#define XTOSTR(a) TOSTR(a)

#define COLLECTDELAY_INSTANT ((unsigned int)~0)


#define MSG_SECURITY_PROBLEM(a) "Security problem: "a". Don't use this application until the bug will be fixed. Report about the problem to: "AUTHOR

#define require_strlen_le(str, limit) \
	if (strlen(str) >= limit)\
		critical("length of "TOSTR(str)" (\"%s\") >= "TOSTR(limit));\

#define SAFE(code, onfail) ({\
	long _SAFE_rc;\
	if ((_SAFE_rc = code)) {\
		error("Got error while "TOSTR(code));\
		onfail;\
	} \
	_SAFE_rc;\
})

enum paramsource_enum {
	PS_UNKNOWN	 = 0,
	PS_ARGUMENT,
	PS_CONFIG,
	PS_CONTROL,
	PS_DEFAULTS,
};
typedef enum paramsource_enum paramsource_t;


enum notifyengine_enum {
	NE_UNDEFINED = 0,
	NE_FANOTIFY,
	NE_INOTIFY,
	NE_KQUEUE,
	NE_BSM,
	NE_BSM_PREFETCH,
	NE_DTRACEPIPE,
	NE_GIO,
};
typedef enum notifyengine_enum notifyengine_t;

enum threadingmode {
	PM_OFF	= 0,
	PM_SAFE,
	PM_FULL
};
typedef enum threadingmode threadingmode_t;

enum splittingmode_enum {
	SM_OFF		= 0,
	SM_THREAD,
	SM_PROCESS,
};
typedef enum splittingmode_enum splittingmode_t;

/*
struct excludeinfo {
	unsigned int	seqid_min;
	unsigned int	seqid_max;
	eventobjtype_t	objtype_old;
	eventobjtype_t	objtype_new;
	uint32_t	flags;
};
typedef struct eventinfo eventinfo_t;
*/
struct eventinfo {
	uint32_t	evmask;
	unsigned int	seqid_min;
	unsigned int	seqid_max;
	eventobjtype_t	objtype_old;
	eventobjtype_t	objtype_new;
	int		wd;
	size_t		fsize;
	uint32_t	flags;
};
typedef struct eventinfo eventinfo_t;

struct thread_callbackfunct_arg {
	char *excfpath;
	char *incfpath;
};
typedef struct thread_callbackfunct_arg thread_callbackfunct_arg_t;

typedef int (*thread_callbackfunct_t)(ctx_t *ctx_p, thread_callbackfunct_arg_t *arg_p);
struct threadinfo {
	int				  thread_num;
	uint32_t			  iteration;
	thread_callbackfunct_t 		  callback;
	thread_callbackfunct_arg_t 	 *callback_arg;
	char				**argv;
	pthread_t			  pthread;
	int				  exitcode;
	int				  errcode;
	state_t				  state;
	ctx_t				 *ctx_p;
	time_t				  starttime;
	time_t				  expiretime;
	int				  child_pid;

	GHashTable			 *fpath2ei_ht;		// file path -> event information

	int				  try_n;

	// for so-synchandler
	int				  n;
	api_eventinfo_t			 *ei;
};
typedef struct threadinfo threadinfo_t;

enum pthread_mutex_id {
	PTHREAD_MUTEX_STATE,
	PTHREAD_MUTEX_SELECT,
	PTHREAD_MUTEX_THREADSINFO,
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
	ctx_t *ctx_p;
	struct indexes *indexes_p;
	void *data;
	int linescount;
	api_eventinfo_t *api_ei;
	int api_ei_count;
	char buf[BUFSIZ+1];

// for be read by sync_parameter_get():
	const char *include_list[MAXARGUMENTS+2];
	size_t      include_list_count;
	const char *list_type_str;
	const char *evmask_str;
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

struct myentry {
	size_t  size;
	size_t  alloc;
	void   *dat;
};

struct pushentry_arg {
	int		 allocated;
	int		 total;
	size_t		 size;
	struct myentry	*entry;
};

enum initsync {
	INITSYNC_UNKNOWN = 0,
	INITSYNC_FULL,
	INITSYNC_SUBDIR
};
typedef enum initsync initsync_t;

struct sighandler_arg {
	ctx_t     *ctx_p;
//	indexes_t *indexes_p;
	pthread_t  pthread_parent;
	int	  *exitcode_p;
	sigset_t  *sigset_p;
};
typedef struct sighandler_arg sighandler_arg_t;

#endif

