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

#include <stdlib.h>
#include <string.h>
#ifdef CAPABILITIES_SUPPORT
# include <unistd.h>
# include <sys/mman.h>
# ifdef SECCOMP_SUPPORT
#  include <sys/stat.h>
#  include <fcntl.h>
# endif
#endif

#include "malloc.h"
#include "error.h"
#include "configuration.h"

#ifdef CAPABILITIES_SUPPORT
long pagesize;
# ifdef SECCOMP_SUPPORT
int  devzero_fd;
# endif
#endif

void *xmalloc(size_t size) {
#ifdef _DEBUG
	debug(20, "(%li)", size);
#endif
#ifdef PARANOID
	size++;	// Just in case
#endif

	void *ret = malloc(size);

	if (ret == NULL)
		critical("(%li): Cannot allocate memory.", size);

#ifdef PARANOID
	memset(ret, 0, size);
#endif
	return ret;
}

void *xcalloc(size_t nmemb, size_t size) {
#ifdef _DEBUG
	debug(20, "(%li, %li)", nmemb, size);
#endif
#ifdef PARANOID
	nmemb++; // Just in case
	size++;	 // Just in case
#endif

	void *ret = calloc(nmemb, size);

	if (ret == NULL)
		critical("(%li): Cannot allocate memory.", size);

//	memset(ret, 0, nmemb*size);	// Just in case
	return ret;
}

void *xrealloc(void *oldptr, size_t size) {
#ifdef _DEBUG
	debug(20, "(%p, %li)", oldptr, size);
#endif
#ifdef PARANOID
	size++;	// Just in case
#endif

	void *ret = realloc(oldptr, size);

	if (ret == NULL)
		critical("(%p, %li): Cannot reallocate memory.", oldptr, size);

	return ret;
}

#ifdef CAPABILITIES_SUPPORT
void *malloc_align(size_t size) {
	size_t total_size;
	void *ret;
# ifdef _DEBUG
	debug(20, "(%li)", size);
# endif
# ifdef PARANOID
	size++;	 // Just in case
# endif

	total_size  = size;
# ifdef PARANOID
	total_size += pagesize-1;
	total_size /= pagesize;
	total_size *= pagesize;
# endif

	if (posix_memalign(&ret, pagesize, total_size))
		critical("(%li): Cannot allocate memory.", size);

# ifdef PARANOID
	if (ret == NULL)
		critical("(%li): ptr == NULL.", size);
# endif

//	memset(ret, 0, nmemb*size);	// Just in case
	return ret;
}

void *calloc_align(size_t nmemb, size_t size) {
	size_t total_size;
	void *ret;
# ifdef _DEBUG
	debug(20, "(%li, %li)", nmemb, size);
# endif
# ifdef PARANOID
	nmemb++; // Just in case
	size++;	 // Just in case
# endif

	total_size = nmemb*size;
	ret = malloc_align(total_size);
	memset(ret, 0, total_size);

	return ret;
}

char *strdup_protect(const char *src, int prot) {
	size_t len = strlen(src);
	char *dst  = malloc_align(len);
	strcpy(dst, src);
	if (mprotect(dst, len, prot))
		critical("(%p, 0x%o): Got error from mprotect(%p, %lu, 0x%o)", src, prot, dst, len, prot);

	return dst;
}

# ifdef SECCOMP_SUPPORT
int is_protected(void *addr) {
	char *_addr = addr, t;
	int is_protected;
	t = *_addr;

	is_protected = (read(devzero_fd, addr, 1) == -1);

	if (!is_protected)
		*_addr = t;

	return is_protected;
}
# endif

#endif

int memory_init() {
#ifdef CAPABILITIES_SUPPORT
	pagesize   = sysconf(_SC_PAGE_SIZE);

	if (pagesize == -1)
		critical("Got error from sysconf(_SC_PAGE_SIZE)");

# ifdef SECCOMP_SUPPORT
	devzero_fd = open(DEVZERO, O_RDONLY);

	if (devzero_fd == -1)
		critical("Got error while open(\""DEVZERO"\", O_RDONLY)");
# endif
#endif

	return 0;
}

