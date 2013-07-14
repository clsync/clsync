/*
    clsync - file tree sync utility based on fanotify and inotify
    
    Copyright (C) 2013  Dmitry Yu Okunev <xai@mephi.ru> 0x8E30679C
    
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
#include "output.h"
#include "malloc.h"


char *fd2fpath_malloc(int fd) {
	struct stat64 lstat;

	if(fd <= 0) {
		printf_e("Error: Invalid file descriptor supplied: fd2fpath_malloc(%i).\n", fd);
		errno = EINVAL;
		return NULL;
	}


	char *fpath = xmalloc((1<<8) + 2);
	sprintf(fpath, "/proc/self/fd/%i", fd);

	if(lstat64(fpath, &lstat)) {
		printf_e("Error: Cannot fstat(%i, fstat): %s (errno: %i).\n", fd, strerror(errno), errno);
		return NULL;
	}

	ssize_t fpathlen = lstat.st_size;

	if(fpathlen > (1<<8))
		fpath = xrealloc(fpath, fpathlen+2);

	printf_ddd("Debug2: Getting file path from symlink \"%s\". Path length is: %i.\n", fpath, fpathlen);
	if((fpathlen = readlink(fpath, fpath, fpathlen+1)) < 0) {
		printf_e("Error: Cannot readlink(\"%s\", fpath, bufsize).\n", fpath);
		return NULL;
	}
	printf_ddd("Debug2: The path is: \"%s\"\n", fpath);

	fpath[fpathlen] = 0;
	return fpath;
}


