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

extern char *fd2fpath_malloc ( int fd );

extern int fileutils_copy ( const char *path_from, const char *path_to );
extern short int fileutils_calcdirlevel ( const char *path );
extern int mkdirat_open ( const char *const dir_path, int dirfd_parent, mode_t dir_mode );
extern uint32_t stat_diff ( stat64_t *a, stat64_t *b );

