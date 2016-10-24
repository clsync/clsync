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

#include <glib.h>	// GHashTable


struct thread_callbackfunct_arg {
	char *excfpath;
	char *incfpath;
};
typedef struct thread_callbackfunct_arg thread_callbackfunct_arg_t;

typedef int ( *thread_callbackfunct_t ) ( ctx_t *ctx_p, thread_callbackfunct_arg_t *arg_p );
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


extern int sync_run ( struct ctx *ctx );
extern int sync_dump ( struct ctx *ctx, const char *const dest_dir );
extern int sync_term ( int exitcode );
extern int threads_foreach ( int ( *funct ) ( threadinfo_t *, void * ), state_t state, void *arg );
extern threadsinfo_t *thread_info();
extern time_t thread_nextexpiretime();
extern int sync_prequeue_loadmark
(
    int fsmon_d,

    struct ctx     *ctx_p,
    struct indexes *indexes_p,

    const char *path_full,
    const char *path_rel,

    stat64_t *lstat_p,

    eventobjtype_t objtype_old,
    eventobjtype_t objtype_new,

    uint32_t event_mask,
    int      event_wd,
    mode_t st_mode,
    off_t  st_size,

    char  **path_buf_p,
    size_t *path_buf_len_p,

    struct eventinfo *evinfo
);
extern int sync_prequeue_unload ( struct ctx *ctx_p, struct indexes *indexes_p );
extern const char *sync_parameter_get ( const char *variable_name, void *_dosync_arg_p );
extern pthread_t pthread_sighandler;

