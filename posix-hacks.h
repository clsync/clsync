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

#	ifndef __POSIX_HACKS_C
#		define fopen	posixhacks_fopen
#		define fdopen	posixhacks_fdopen
#		define fclose	posixhacks_fclose
#	endif


extern int posixhacks_init();
extern FILE *posixhacks_fopen ( const char *path, const char *mode );
extern int posixhacks_fclose ( FILE *fp );
extern int posixhacks_deinit();
#else
#	define posixhacks_init() (0)
#	define posixhacks_deinit() (0)
#endif
