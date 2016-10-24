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

extern int pivot_root ( const char *new_root, const char *old_root );

static inline ssize_t read_inf ( int fd, void *buf, size_t count )
{
	ssize_t ret;
	errno = 0;

	do {
		ret = read ( fd, buf, count );
	} while ( ( ret == -1 ) && ( errno == EINTR ) );

	return ret;
}

static inline ssize_t write_inf ( int fd, const void *buf, size_t count )
{
	ssize_t ret;
	errno = 0;

	do {
		ret = write ( fd, buf, count );
	} while ( ( ret == -1 ) && ( errno == EINTR ) );

	return ret;
}

