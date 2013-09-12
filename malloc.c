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

#include "common.h"
#include "malloc.h"
#include "output.h"

char *xmalloc(size_t size) {
	size++;	// Just in case

	char *ret = (char *)malloc(size);

	if(ret == NULL) {
		printf_e("xmalloc(%i): Cannot allocate memory (#%i: %s).\n", size, errno, strerror(errno));
		exit(errno);
	}

#ifdef PARANOID
	memset(ret, 0, size);
#endif
	return ret;
}

char *xcalloc(size_t nmemb, size_t size) {
	nmemb++; // Just in case
	size++;	 // Just in case

	char *ret = (char *)calloc(nmemb, size);

	if(ret == NULL) {
		printf_e("xcalloc(%i): Cannot allocate memory (#%i: %s).\n", size, errno, strerror(errno));
		exit(errno);
	}

//	memset(ret, 0, nmemb*size);	// Just in case
	return ret;
}

char *xrealloc(char *oldptr, size_t size) {
	size++;	// Just in case

	char *ret = (char *)realloc(oldptr, size);

	if(ret == NULL) {
		printf_e("xrealloc(%p, %i): Cannot reallocate memory (#%i: %s).\n", oldptr, size, errno, strerror(errno));
		exit(errno);
	}

	return ret;
}

