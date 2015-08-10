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

#define CLSYNC_ITSELF

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

#include "macros.h"

enum paramsource_enum {
	PS_UNKNOWN	 = 0,
	PS_ARGUMENT,
	PS_CONFIG,
	PS_CONTROL,
	PS_DEFAULTS,
//	PS_REHASH,
	PS_CORRECTION,
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

enum pthread_mutex_id {
	PTHREAD_MUTEX_STATE,
	PTHREAD_MUTEX_SELECT,
	PTHREAD_MUTEX_THREADSINFO,
	PTHREAD_MUTEX_MAX
};

enum dosync_listid {
	DOSYNC_LIST_WALK = 0,
	DOSYNC_LIST_INCLUDE,
	DOSYNC_LIST_EXCLUDE,
	DOSYNC_LIST__MAX,
};
typedef enum dosync_listid dosync_listid_t;

struct dosync_arg {
	int		 evcount;
	char		 outf_path[DOSYNC_LIST__MAX][PATH_MAX+1];
	FILE		*outf[DOSYNC_LIST__MAX];
	ctx_t		*ctx_p;
	struct indexes	*indexes_p;
	void		*data;
	int		 linescount;
	api_eventinfo_t	*api_ei;
	int		 api_ei_count;
	char		 buf[DOSYNC_LIST__MAX][BUFSIZ+1];

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

enum initsync_flags {
	INITSYNC_NONE		= 0x00,
	INITSYNC_FULL		= 0x02,
	INITSYNC_DIR		= 0x04,
	INITSYNC_INSTANT	= 0x08,
};

enum initsync {
	INITSYNC_UNKNOWN = 0,						// Error
	INITSYNC_FULL_NONINSTANT= INITSYNC_FULL,			// With grandchildren,		non-instant
	INITSYNC_FULL_INSTANT	= INITSYNC_FULL|INITSYNC_INSTANT,	// With grandchildren,		instant
	INITSYNC_DIR_INSTANT	= INITSYNC_DIR|INITSYNC_INSTANT,	// Without grandchildren,	instant
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

