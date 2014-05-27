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

#include "common.h"
#include "port-hacks.h"
#include "error.h"
#include "sync.h"
#include "indexes.h"
#include "inotify.h"

int inotify_add_watch_dir(ctx_t *ctx_p, indexes_t *indexes_p, const char *const accpath) {
	int inotify_d = (int)(long)ctx_p->fsmondata;
	return inotify_add_watch(inotify_d, accpath, INOTIFY_MARKMASK);
}

int inotify_wait(ctx_t *ctx_p, struct timeval *tv_p) {
	int inotify_d = (int)(long)ctx_p->fsmondata;

	debug(3, "select with timeout %li secs.", tv_p->tv_sec);
	fd_set rfds;
	FD_ZERO(&rfds);
	FD_SET(inotify_d, &rfds);
	return select(inotify_d+1, &rfds, NULL, NULL, tv_p);
}

#define INOTIFY_HANDLE_CONTINUE {\
	ptr += sizeof(struct inotify_event) + event->len;\
	count++;\
	continue;\
}

int inotify_handle(ctx_t *ctx_p, indexes_t *indexes_p) {
	static struct timeval tv={0};
	int inotify_d = (int)(long)ctx_p->fsmondata;

	int count = 0;

	fd_set rfds;
	FD_ZERO(&rfds);
	FD_SET(inotify_d, &rfds);

	char   *path_rel	= NULL;
	size_t  path_rel_len	= 0;
	char   *path_full	= NULL;
	size_t  path_full_size	= 0;
	while (select(FD_SETSIZE, &rfds, NULL, NULL, &tv)) {

		char buf[BUFSIZ + 1];
		size_t r = read(inotify_d, buf, BUFSIZ);
		if (r <= 0) {
			error("Got error while reading events from inotify with read().");
			count = -1;
			goto l_inotify_handle_end;
		}

#ifdef PARANOID
		g_hash_table_remove_all(indexes_p->fpath2ei_ht);
#endif

		char *ptr =  buf;
		char *end = &buf[r];
		while (ptr < end) {
			struct inotify_event *event = (struct inotify_event *)ptr;

			// Removing stale wd-s

			if(event->mask & IN_IGNORED) {
				debug(2, "Cleaning up info about watch descriptor %i.", event->wd);
				indexes_remove_bywd(indexes_p, event->wd);
				INOTIFY_HANDLE_CONTINUE;
			}

			// Getting path

			char *fpath = indexes_wd2fpath(indexes_p, event->wd);

			if(fpath == NULL) {
				debug(2, "Event %p on stale watch (wd: %i).", (void *)(long)event->mask, event->wd);
				INOTIFY_HANDLE_CONTINUE;
			}
			debug(2, "Event %p on \"%s\" (wd: %i; fpath: \"%s\").", (void *)(long)event->mask, event->len>0?event->name:"", event->wd, fpath);

			// Getting full path

			size_t path_full_memreq = strlen(fpath) + event->len + 2;
			if (path_full_size < path_full_memreq) {
				path_full      = xrealloc(path_full, path_full_memreq);
				path_full_size = path_full_memreq;
			}

			if (event->len>0)
				sprintf(path_full, "%s/%s", fpath, event->name);
			else
				sprintf(path_full, "%s", fpath);

			// Getting infomation about file/dir/etc

			stat64_t lstat;
			mode_t st_mode;
			size_t st_size;
			if (lstat64(path_full, &lstat)) {
				debug(2, "Cannot lstat64(\"%s\", lstat). Seems, that the object disappeared.", path_full);
				if(event->mask & IN_ISDIR)
					st_mode = S_IFDIR;
				else
					st_mode = S_IFREG;
				st_size = 0;
			} else {
				st_mode = lstat.st_mode;
				st_size = lstat.st_size;
			}

			if (sync_prequeue_loadmark(1, ctx_p, indexes_p, path_full, NULL, event->mask, event->wd, st_mode, st_size, &path_rel, &path_rel_len, NULL)) {
				count = -1;
				goto l_inotify_handle_end;
			}

			INOTIFY_HANDLE_CONTINUE;
		}

		// Globally queueing captured events:
		// Moving events from local queue to global ones
		sync_prequeue_unload(ctx_p, indexes_p);
	}

l_inotify_handle_end:
	if(path_full != NULL)
		free(path_full);

	if(path_rel != NULL)
		free(path_rel);

	return count;
}

int inotify_deinit(ctx_t *ctx_p) {
	int inotify_d = (int)(long)ctx_p->fsmondata;
	debug(3, "Closing inotify_d");
	return close(inotify_d);
}

