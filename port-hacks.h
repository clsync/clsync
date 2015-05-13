/*
    clsync - file tree sync utility based on fanotify and inotify

    Copyright (C) 2014  Dmitry Yu Okunev <dyokunev@ut.mephi.ru> 0x8E30679C

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

#ifndef __PORT_HACKS_H
#define __PORT_HACKS_H

#ifndef ETIME
#define ETIME ETIMEDOUT
#endif

#include <sys/types.h>
#include <sys/stat.h>

#if __FreeBSD__ || __FreeBSD_kernel__
#	include <sys/syslimits.h>

#	define O_PATH 0

#	include <pthread.h>

#	ifdef THREADING_SUPPORT
	static inline int pthread_tryjoin_np(pthread_t thread, void **retval) {
		struct timespec abstime;
		int rc;

		abstime.tv_sec  = 0;
		abstime.tv_nsec = 0;

		extern int pthread_timedjoin_np(pthread_t thread, void **value_ptr, const struct timespec *abstime);

		rc = pthread_timedjoin_np(thread, retval, &abstime);

		if (rc == ETIMEDOUT)
			rc = EBUSY;

		return rc;
	}
#	endif

#	ifndef __USE_LARGEFILE64
	typedef struct stat stat64_t;
	static inline int lstat64(const char *pathname, struct stat *buf) {
		return lstat(pathname, buf);
	}
#	else
	typedef struct stat64 stat64_t;
#	endif

#else
	typedef struct stat64 stat64_t;
#endif

#ifdef CLSYNC_ITSELF
#	ifndef O_PATH
#		warning O_PATH is not set
#		define O_PATH 0
#	endif
#endif

#endif // __PORT_HACKS_H

