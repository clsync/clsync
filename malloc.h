/*
    clsync - file tree sync utility based on fanotify and inotify

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

#include <sys/types.h>

extern void *xmalloc ( size_t size );
extern void *xcalloc ( size_t nmemb, size_t size );
extern void *xrealloc ( void *oldptr, size_t size );
#ifdef CAPABILITIES_SUPPORT
extern void *malloc_align ( size_t size );
extern void *calloc_align ( size_t nmemb, size_t size );
extern char *strdup_protect ( const char *src, int prot );
# ifdef SECCOMP_SUPPORT
extern int is_protected ( void *addr );
# endif
#endif
extern void *shm_malloc ( size_t size );
extern void *shm_malloc_try ( size_t size );
extern void *shm_calloc ( size_t nmemb, size_t size );
extern void shm_free ( void *ptr );

extern int memory_init();

