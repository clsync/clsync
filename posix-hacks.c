/*
    clsync - file tree sync utility based on inotify/kqueue/bsm/gio

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

#ifdef __FreeBSD__

#define _GNU_SOURCE

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#define __POSIX_HACKS_C

int reserved_fd[FOPEN_MAX + 1] = { -1};
int reserved_fd_used;


static inline int reserve_fdpair ( int idx )
{
	int pipe_fds[2];

	if ( pipe2 ( pipe_fds, O_CLOEXEC | O_NONBLOCK ) )
		return errno;

	reserved_fd[ idx     ] = pipe_fds[0];
	reserved_fd[ idx + 1 ] = pipe_fds[1];
	return 0;
}

int posixhacks_init()
{
	int i;
	// Reserving file descriptors from start to bypass FOPEN_MAX limit on fopen()/fdopen()
	i = 0;

	while ( i < ( FOPEN_MAX + 1 ) / 2 ) {
		if ( reserve_fdpair ( i << 1 ) )
			return errno;

		i++;
	}

	reserved_fd_used = 0;
	return 0;
}

FILE *posixhacks_fopen ( const char *path, const char *mode )
{
	close ( reserved_fd[reserved_fd_used++] );
	return fopen ( path, mode );
}

int posixhacks_fclose ( FILE *fp )
{
	int rc;
	int pipe_fds[2];
	rc = fclose ( fp );

	// reserving the file descriptor
	if ( ! ( reserved_fd_used & 1 ) )
		close ( reserved_fd[reserved_fd_used++] );

	reserved_fd_used -= 2;

	if ( reserve_fdpair ( reserved_fd_used ) )
		return errno;

	return rc;
}

int posixhacks_deinit()
{
	int i;
	i = 0;

	while ( i < ( FOPEN_MAX + 1 ) / 2 ) {
		close ( reserved_fd[ ( i << 1 )     ] );
		close ( reserved_fd[ ( i << 1 ) + 1 ] );
		i++;
	}

	return 0;
}

#endif

extern int make_iso_compilers_happy; // anti-warning

