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

#include <string.h>
#include <pthread.h>
#include "pthreadex.h"
#include "malloc.h"

int pthread_mutex_init_shared(pthread_mutex_t **mutex_p) {
	static pthread_mutex_t mutex_initial = PTHREAD_MUTEX_INITIALIZER;
	*mutex_p = shm_malloc_try(sizeof(**mutex_p));
	memcpy(*mutex_p, &mutex_initial, sizeof(mutex_initial));

	pthread_mutexattr_t attr;
	pthread_mutexattr_init(&attr);
	pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
	return pthread_mutex_init(*mutex_p, &attr);
}

int pthread_mutex_destroy_shared(pthread_mutex_t *mutex_p) {
	int rc;
	rc = pthread_mutex_destroy(mutex_p);
	shm_free(mutex_p);
	return rc;
}

int pthread_cond_init_shared(pthread_cond_t **cond_p) {
	static pthread_cond_t cond_initial = PTHREAD_COND_INITIALIZER;
	*cond_p = shm_malloc(sizeof(**cond_p));
	memcpy(*cond_p, &cond_initial, sizeof(cond_initial));

	pthread_condattr_t attr;
	pthread_condattr_init(&attr);
	pthread_condattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
	return pthread_cond_init(*cond_p, &attr);
}

int pthread_cond_destroy_shared(pthread_cond_t *cond_p) {
	int rc;
	rc = pthread_cond_destroy(cond_p);
	shm_free(cond_p);
	return rc;
}

int pthread_mutex_reltimedlock(pthread_mutex_t *mutex_p, long tv_sec, long tv_nsec) {
	struct timespec abs_time;

	if (clock_gettime(CLOCK_REALTIME, &abs_time))
		return -1;

	abs_time.tv_sec  += tv_sec;
	abs_time.tv_nsec += tv_nsec;

	if (abs_time.tv_nsec > 1000*1000*1000) {
		abs_time.tv_sec++;
		abs_time.tv_nsec -= 1000*1000*1000;
	}

	return pthread_mutex_timedlock(mutex_p, &abs_time);
}

