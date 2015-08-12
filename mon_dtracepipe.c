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
#include "malloc.h"
#include "error.h"
#include "indexes.h"
#include "sync.h"
#include "mon_dtracepipe.h"

#define DTRACE_SCRIPT "BEGIN\
{\
    dir = $1;\
    dirlen = strlen(dir);\
}\
\
syscall::open*:entry\
/\
arg1 & (O_WRONLY|O_RDWR) &&\
    substr(copyinstr(arg0),0,dirlen)==dir\
/\
{\
    printf("%s\n",copyinstr(arg0));\
}\
\
syscall::mkdir*:entry\
/\
    substr(copyinstr(arg0),0,dirlen)==dir\
/\
{\
    printf("%s\n",copyinstr(arg0));\
}"

struct mondata {
	FILE *pipe;
};
typedef struct mondata mondata_t;

#define DTRACEPIPE_INIT_ERROR {\
		free(ctx_p->fsmondata);\
		ctx_p->fsmondata = NULL;\
		return -1;\
	}

int dtracepipe_init ( ctx_t *ctx_p )
{
	char cmd[BUFSIZ];
	ctx_p->fsmondata = xcalloc ( sizeof ( mondata_t ), 1 );
	mondata_t *mondata = ctx_p->fsmondata;

	if ( snprintf ( cmd, "%s -n '%s' '%s'", DTRACE_PATH, DTRACE_SCRIPT, ) >= BUFSIZ ) {
		errno = EMSGSIZE;
		error ( "Too long cmd." );
		DTRACEPIPE_INIT_ERROR;
	}

	FILE *pipe = popen ( cmd, "r" );

	if ( pipe == NULL ) {
		error ( "Cannot popen(\""DTRACE_PATH"\", \"r\")" );
		DTRACEPIPE_INIT_ERROR;
	}

	if ( setvbuf ( pipe, NULL, _IONBF, 0 ) ) {
		error ( "Cannot set unbuffered mode for pipe of \""DTRACE_PATH"\" process" );
		DTRACEPIPE_INIT_ERROR;
	}

	mondata->pipe = pipe;
	return 0;
}

char  *dtracepipe_wait_line = NULL;
size_t dtracepipe_wait_line_siz;
int dtracepipe_wait ( struct ctx *ctx_p, struct indexes *indexes_p, struct timeval *timeout_p )
{
	mondata_t *mondata = ctx_p->fsmondata;
	struct timeval timeout_abs, tv_abs;
	int dontwait = 0;
	struct dtracepipe_event *event_p = &mondata->event;

	if ( timeout_p->tv_sec == 0 && timeout_p->tv_usec == 0 )
		dontwait = 1;

	if ( !dontwait ) {
		gettimeofday ( &tv_abs, NULL );
		timeradd ( &tv_abs, timeout_p, &timeout_abs );
	}

	int pipe_fd = fileno ( mondata->pipe );

	while ( 42 ) {
		int path_count;

		// Checking if there already a recond in mondata
		if ( *event_p->path ) {
			debug ( 2, "we have an event. return 1." );
			return 1;
		}

		// Getting a record
		{
			debug ( 3, "select() with timeout %li.%06li secs (dontwait == %u).", timeout_p->tv_sec, timeout_p->tv_usec, dontwait );
			fd_set rfds;
			FD_ZERO ( &rfds );
			FD_SET ( pipe_fd, &rfds );
			int rc = select ( pipe_fd + 1, &rfds, NULL, NULL, timeout_p );

			if ( rc == 0 || rc == -1 )
				return rc;

			line_len = getline ( &dtracepipe_wait_line, &dtracepipe_wait_line_siz, mondata->pipe );

			if ( line_len == -1 ) {
				error ( "Cannot read line from \""DTRACE_PATH"\" pipe [using getline()]" );
				return -1;
			}

			if ( !dontwait ) {
				debug ( 5, "old timeout_p->: tv_sec == %lu; tv_usec == %lu", timeout_p->tv_sec, timeout_p->tv_usec );
				gettimeofday ( &tv_abs, NULL );

				if ( timercmp ( &timeout_abs, &tv_abs, < ) )
					timersub ( &timeout_abs, &tv_abs, timeout_p );
				else
					memset ( timeout_p, 0, sizeof ( *timeout_p ) );

				debug ( 5, "new timeout_p->: tv_sec == %lu; tv_usec == %lu", timeout_p->tv_sec, timeout_p->tv_usec );
			}
		}
		// Parsing the record
		path_count = 0;
		debug ( 3, "parsing the event" );

		while ( au_parsed < au_len ) {
			if ( au_fetch_tok ( &tok, &au_buf[au_parsed], au_len - au_parsed ) == -1 )
				return -1;

			au_parsed += tok.len;

			switch ( tok.id ) {
				case AUT_HEADER32:
				case AUT_HEADER32_EX:
				case AUT_HEADER64:
				case AUT_HEADER64_EX: {
						event_p->type = tok.tt.hdr32.e_type;
						path_count = 0;
						break;
					}

				case AUT_PATH: {
						char *ptr;
						int dir_wd, dir_iswatched;
						ptr = memrchr ( tok.tt.path.path, '/', tok.tt.path.len );
#ifdef PARANOID

						if ( ptr == NULL )
							critical ( "relative path received from au_fetch_tok(): \"%s\" (len: %u)", tok.tt.path.path, tok.tt.path.len );

#endif
						debug ( 6, "Event on \"%s\".", tok.tt.path.path );
						*ptr = 0;
						dir_wd = indexes_fpath2wd ( indexes_p, tok.tt.path.path );
						dir_iswatched = ( dir_wd != -1 );
						debug ( 7, "Directory is \"%s\". dir_wd == %i; dir_iswatched == %u", tok.tt.path.path, dir_wd, dir_iswatched );
						*ptr = '/';

						if ( dir_iswatched ) {
							debug ( 5, "Event on \"%s\" is watched. Pushing. path_count == %u", tok.tt.path.path, path_count );

							switch ( path_count ) {
								case 0:
									memcpy ( event_p->path,    tok.tt.path.path, tok.tt.path.len + 1 );
									break;

								case 1:
									memcpy ( event_p->path_to, tok.tt.path.path, tok.tt.path.len + 1 );
									break;
#ifdef PARANOID

								default:
									warning ( "To many paths on BSM event: \"%s\" (already count: %u)", tok.tt.path.path, path_count );
									break;
#endif
							}
						}

						path_count++;
						break;
					}

				default:
					continue;
			}
		}

		// Cleanup
		debug ( 4, "clean up" );
		free ( au_buf );
		au_buf    = NULL;
		au_len    = 0;
		au_parsed = 0;
	}

	return -1;
}
int dtracepipe_handle ( struct ctx *ctx_p, struct indexes *indexes_p )
{
	return -1;
}
int dtracepipe_add_watch_dir ( struct ctx *ctx_p, struct indexes *indexes_p, const char *const accpath )
{
	return -1;
}
int dtracepipe_deinit ( ctx_t *ctx_p )
{
	mondata_t *mondata = ctx_p->fsmondata;
	free ( dtracepipe_wait_line );
	free ( mondata );
	return -1;
}
