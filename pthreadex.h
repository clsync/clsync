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

#include <pthread.h>

extern int pthread_mutex_init_shared ( pthread_mutex_t **mutex_p );
extern int pthread_mutex_destroy_shared ( pthread_mutex_t *mutex_p );
extern int pthread_cond_init_shared ( pthread_cond_t **cond_p );
extern int pthread_cond_destroy_shared ( pthread_cond_t *cond_p );
extern int pthread_mutex_reltimedlock ( pthread_mutex_t *mutex_p, long tv_sec, long tv_nsec );

