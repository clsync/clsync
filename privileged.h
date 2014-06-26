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

#ifdef CAPABILITIES_SUPPORT

extern FTS *(*privileged_fts_open)		(
		char * const *path_argv,
		int options,
		int (*compar)(const FTSENT **, const FTSENT **)
	);

extern FTSENT *(*privileged_fts_read)		(FTS *ftsp);
extern int (*privileged_fts_close)		(FTS *ftsp);
extern int (*privileged_inotify_init)		();
extern int (*privileged_inotify_init1)		(int flags);

extern int (*privileged_inotify_add_watch)	(
		int fd,
		const char *pathname,
		uint32_t mask
	);

extern int (*privileged_inotify_rm_watch)	(
		int fd,
		int wd
	);

#else

#define privileged_fts_open		fts_open
#define privileged_fts_read		fts_read
#define privileged_fts_close		fts_close
#define privileged_inotify_init		inotify_init
#define privileged_inotify_init1	inotify_init1
#define privileged_inotify_add_watch	inotify_add_watch
#define privileged_inotify_rm_watch	inotify_rm_watch

#endif

extern int (*privileged_fork_execvp)(const char *file, char *const argv[]);

extern int privileged_init(struct ctx *ctx_p);
extern int privileged_deinit(struct ctx *ctx_p);

