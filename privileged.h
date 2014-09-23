/*
    clsync - file tree sync utility based on inotify/kqueue
    
    Copyright (C) 2013-2014 Dmitry Yu Okunev <dyokunev@ut.mephi.ru> 0x8E30679C
    
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

#ifdef HL_LOCK_TRIES_AUTO
# define IF_HL_LOCK_TRIES_AUTO(a) a
#else
# define IF_HL_LOCK_TRIES_AUTO(a) {}
#endif

#ifdef CAPABILITIES_SUPPORT

enum priv_callid {
	PC_DEFAULT = 0,
	PC_SYNC_INIIALSYNC_WALK_FTS_OPEN,
	PC_SYNC_INIIALSYNC_WALK_FTS_READ,
	PC_SYNC_INIIALSYNC_WALK_FTS_CLOSE,
	PC_SYNC_MARK_WALK_FTS_OPEN,
	PC_SYNC_MARK_WALK_FTS_READ,
	PC_SYNC_MARK_WALK_FTS_CLOSE,
	PC_INOTIFY_ADD_WATCH_DIR,

	PC_MAX
};

extern FTS *(*_privileged_fts_open)		(
		char * const *path_argv,
		int options,
		int (*compar)(const FTSENT **, const FTSENT **)
# ifdef HL_LOCK_TRIES_AUTO
		, int callid
# endif
	);

extern FTSENT *(*_privileged_fts_read)		(
		FTS *ftsp
# ifdef HL_LOCK_TRIES_AUTO
		, int callid
# endif
	);

extern int (*_privileged_fts_close)		(
		FTS *ftsp
# ifdef HL_LOCK_TRIES_AUTO
		, int callid
# endif
	);

extern int (*_privileged_inotify_init)		();
extern int (*_privileged_inotify_init1)		(int flags);

extern int (*_privileged_inotify_add_watch)	(
		int fd,
		const char *pathname,
		uint32_t mask
# ifdef HL_LOCK_TRIES_AUTO
		, int callid
# endif
	);

extern int (*_privileged_inotify_rm_watch)	(
		int fd,
		int wd
	);

#ifdef CGROUP_SUPPORT
extern int (*_privileged_clsync_cgroup_deinit)	(ctx_t *ctx_p);
#endif

extern pid_t (*_privileged_waitpid)		(pid_t pid, int *status, int options);

extern int privileged_check();

# ifdef HL_LOCK_TRIES_AUTO
#  define privileged_fts_open(a,b,c,d)		_privileged_fts_open(a,b,c,d)
#  define privileged_fts_read(a,b)		_privileged_fts_read(a,b)
#  define privileged_fts_close(a,b)		_privileged_fts_close(a,b)
#  define privileged_inotify_add_watch(a,b,c,d)	_privileged_inotify_add_watch(a,b,c,d)
# else
#  define privileged_fts_open(a,b,c,d)		_privileged_fts_open(a,b,c)
#  define privileged_fts_read(a,b)		_privileged_fts_read(a)
#  define privileged_fts_close(a,b)		_privileged_fts_close(a)
#  define privileged_inotify_add_watch(a,b,c,d)	_privileged_inotify_add_watch(a,b,c)
# endif

# define privileged_inotify_init		_privileged_inotify_init
# define privileged_inotify_init1		_privileged_inotify_init1
# define privileged_inotify_rm_watch		_privileged_inotify_rm_watch
# define privileged_clsync_cgroup_deinit	_privileged_clsync_cgroup_deinit
# define privileged_waitpid			_privileged_waitpid

#else

# define privileged_check(...)			{}

# define privileged_fts_open(a,b,c,d)		fts_open(a,b,c)
# define privileged_fts_read(a,b)		fts_read(a)
# define privileged_fts_close(a,b)		fts_close(a)
# define privileged_inotify_init		inotify_init
# define privileged_inotify_init1		inotify_init1
# define privileged_inotify_add_watch(a,b,c,d)	inotify_add_watch(a,b,c)
# define privileged_inotify_rm_watch		inotify_rm_watch
# ifdef CGROUP_SUPPORT
#  define privileged_clsync_cgroup_deinit	clsync_cgroup_deinit
# endif
# define privileged_waitpid			inotify_waitpid
#endif

extern int (*_privileged_kill_child)(
		pid_t pid,
		int sig
	);

extern int (*_privileged_fork_execvp)(
		const char *file,
		char *const argv[]
	);

#define privileged_kill_child			_privileged_kill_child
#define privileged_fork_execvp			_privileged_fork_execvp

extern int privileged_init(struct ctx *ctx_p);
extern int privileged_deinit(struct ctx *ctx_p);

