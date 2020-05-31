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
#include "error.h"
#include "sync.h"
#include "indexes.h"
#include "privileged.h"
#include "mon_inotify.h"

enum event_bits {
	UEM_DIR		= 0x01,
	UEM_CREATED	= 0x02,
	UEM_DELETED	= 0x04,
};

struct recognize_event_return {
	eventobjtype_t objtype_old;
	eventobjtype_t objtype_new;
};

static inline void recognize_event ( struct recognize_event_return *r, uint32_t event )
{
	eventobjtype_t type;
	int is_created;
	int is_deleted;
	type = ( event & IN_ISDIR ? EOT_DIR : EOT_FILE );
	is_created = event & ( IN_CREATE | IN_MOVED_TO );
	is_deleted = event & ( IN_DELETE_SELF | IN_DELETE | IN_MOVED_FROM );
	debug ( 4, "type == %x; is_created == %x; is_deleted == %x", type, is_created, is_deleted );
	r->objtype_old = ( is_created ? EOT_DOESNTEXIST : type );
	r->objtype_new = ( is_deleted ? EOT_DOESNTEXIST : type );
	return;
}

int inotify_add_watch_dir ( ctx_t *ctx_p, indexes_t *indexes_p, const char *const accpath )
{
	( void ) indexes_p;
	int inotify_d = ( int ) ( long ) ctx_p->fsmondata;
	return privileged_inotify_add_watch ( inotify_d, accpath, INOTIFY_MARKMASK, PC_INOTIFY_ADD_WATCH_DIR );
}

int inotify_wait ( ctx_t *ctx_p, struct indexes *indexes_p, struct timeval *tv_p )
{
	( void ) indexes_p;
	int inotify_d = ( int ) ( long ) ctx_p->fsmondata;
	debug ( 3, "select with timeout %li secs (fd == %u).", tv_p->tv_sec, inotify_d );
	fd_set rfds;
	FD_ZERO ( &rfds );
	FD_SET ( inotify_d, &rfds );
	return select ( inotify_d + 1, &rfds, NULL, NULL, tv_p );
}

#define INOTIFY_HANDLE_CONTINUE {\
		ptr += sizeof(struct inotify_event) + event->len;\
		count++;\
		continue;\
	}

int inotify_handle ( ctx_t *ctx_p, indexes_t *indexes_p )
{
	static struct timeval tv = {0};
	int inotify_d = ( int ) ( long ) ctx_p->fsmondata;
	int count = 0;
	fd_set rfds;
	FD_ZERO ( &rfds );
	FD_SET ( inotify_d, &rfds );
	char   *path_rel	= NULL;
	size_t  path_rel_len	= 0;
	char   *path_full	= NULL;
	size_t  path_full_size	= 0;

	while ( select ( FD_SETSIZE, &rfds, NULL, NULL, &tv ) ) {
		char buf[BUFSIZ + 1];
		size_t r = read ( inotify_d, buf, BUFSIZ );

		if ( r <= 0 ) {
			error ( "Got error while reading events from inotify with read()." );
			count = -1;
			goto l_inotify_handle_end;
		}

#ifdef PARANOID
		g_hash_table_remove_all ( indexes_p->fpath2ei_ht );
#endif
		char *ptr =  buf;
		char *end = &buf[r];

		while ( ptr < end ) {
			struct inotify_event *event = ( struct inotify_event * ) ptr;

			// Removing stale wd-s

			if ( event->mask & IN_IGNORED ) {
				debug ( 2, "Cleaning up info about watch descriptor %i.", event->wd );
				indexes_remove_bywd ( indexes_p, event->wd );
				INOTIFY_HANDLE_CONTINUE;
			}

			// Getting path
			char *fpath = indexes_wd2fpath ( indexes_p, event->wd );

			if ( fpath == NULL ) {
				debug ( 2, "Event %p on stale watch (wd: %i).", ( void * ) ( long ) event->mask, event->wd );
				INOTIFY_HANDLE_CONTINUE;
			}

			debug ( 2, "Event %p on \"%s\" (wd: %i; fpath: \"%s\").", ( void * ) ( long ) event->mask, event->len > 0 ? event->name : "", event->wd, fpath );
			// Getting full path
			size_t path_full_memreq = strlen ( fpath ) + event->len + 2;

			if ( path_full_size < path_full_memreq ) {
				path_full      = xrealloc ( path_full, path_full_memreq );
				path_full_size = path_full_memreq;
			}

			if ( event->len > 0 )
				sprintf ( path_full, "%s/%s", fpath, event->name );
			else
				sprintf ( path_full, "%s", fpath );

			// Getting infomation about file/dir/etc
			struct  recognize_event_return r = {0};
			recognize_event ( &r, event->mask );
			stat64_t lst, *lst_p;
			mode_t st_mode;
			size_t st_size;

			if ( ( r.objtype_new == EOT_DOESNTEXIST ) || ( ctx_p->flags[CANCEL_SYSCALLS]&CSC_MON_STAT ) || privileged_lstat64 ( path_full, &lst, PC_MON_HANDLE_LSTAT64 ) ) {
				debug ( 2, "Cannot lstat64(\"%s\", lst). Seems, that the object had been deleted (%i) or option \"--cancel-syscalls mon_stat\" (%i) is set.", path_full, r.objtype_new == EOT_DOESNTEXIST, ctx_p->flags[CANCEL_SYSCALLS]&CSC_MON_STAT );
				st_mode = ( event->mask & IN_ISDIR ? S_IFDIR : S_IFREG );
				st_size = 0;
				lst_p = NULL;
			} else {
				st_mode = lst.st_mode;
				st_size = lst.st_size;
				lst_p = &lst;
			}

			if ( sync_prequeue_loadmark ( 1, ctx_p, indexes_p, path_full, NULL, lst_p, r.objtype_old, r.objtype_new, event->mask, event->wd, st_mode, st_size, &path_rel, &path_rel_len, NULL ) ) {
				count = -1;
				goto l_inotify_handle_end;
			}

			INOTIFY_HANDLE_CONTINUE;
		}

		// Globally queueing captured events:
		// Moving events from local queue to global ones
		sync_prequeue_unload ( ctx_p, indexes_p );
	}

l_inotify_handle_end:

	if ( path_full != NULL )
		free ( path_full );

	if ( path_rel != NULL )
		free ( path_rel );

	return count;
}

int inotify_deinit ( ctx_t *ctx_p )
{
	int inotify_d = ( int ) ( long ) ctx_p->fsmondata;
	debug ( 3, "Closing inotify_d" );
	return close ( inotify_d );
}

