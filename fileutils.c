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
		printf_e("Error: Cannot lstat(\"%s\", lstat): %s (errno: %i).\n", fpath, strerror(errno), errno);
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

/**
 * @brief 			Copies file
 * 
 * @param[in] 	path_from 	Source file path
 * @param[in] 	path_to		Destination file path
 *
 * @retval	zero 		Successfully copied
 * @retval	non-zero 	Got error, while copying
 * 
 */

int fileutils_copy(char *path_from, char *path_to) {
	char buf[BUFSIZ];
	FILE *from, *to;

	from = fopen(path_from, "r");
	if(from == NULL) {
		printf_e("Error: fileutils_copy(\"%s\", \"%s\"): Cannot open file \"%s\" for reading: %s (errno: %i)\n", 
			path_from, path_to, path_from, strerror(errno), errno);
		return errno;
	}

	to   = fopen(path_to,   "w");
	if(to == NULL) {
		printf_e("Error: fileutils_copy(\"%s\", \"%s\"): Cannot open file \"%s\" for writing: %s (errno: %i)\n", 
			path_from, path_to, path_to, strerror(errno), errno);
		return errno;
	}

	while(!feof(from)) {
		int err;
		size_t r, w;

		r =  fread(buf, 1, BUFSIZ, from);
		if((err=ferror(from))) {
			printf_e("Error: fileutils_copy(\"%s\", \"%s\"): Cannot read from file \"%s\": %s (errno: %i)\n",
				path_from, path_to, path_from, strerror(errno), errno);
			return errno;	// CHECK: Is the "errno" should be used in fread() case?
		}

		w = fwrite(buf, 1, r,      to);
		if((err=ferror(to))) {
			printf_e("Error: fileutils_copy(\"%s\", \"%s\"): Cannot write to file \"%s\": %s (errno: %i)\n",
				path_from, path_to, path_to, strerror(errno), errno);
			return errno;	// CHECK: is the "errno" should be used in fwrite() case?
		}
		if(r != w) {
			printf_e("Error: fileutils_copy(\"%s\", \"%s\"): Got error while writing to file \"%s\" (%u != %u): %s (errno: %i)\n",
				path_from, path_to, path_to, r, w, strerror(errno), errno);
			return errno;	// CHECK: is the "errno" should be used in case "r != w"?
		}
	}

	return 0;
}

