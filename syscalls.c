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

/* based on busybox's code:
 *	http://git.busybox.net/busybox/plain/libbb/syscalls.c?h=0_60_stable
 * /

#include <sys/syscall.h>

#ifdef __NR_pivot_root
int pivot_root(const char *new_root, const char *old_root) {
	return(syscall(__NR_pivot_root, new_root, put_old));
}
#else
int pivot_root(const char *new_root, const char *old_root) {
	return errno=ENOSYS;
}
#endif
 */
