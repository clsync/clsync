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

#include "common.h"

#include "error.h"
#include "malloc.h"


char *fd2fpath_malloc ( int fd )
{
#if __linux__
	stat64_t st64;

	if ( fd <= 0 ) {
		error ( "Invalid file descriptor supplied: fd2fpath_malloc(%i).", fd );
		errno = EINVAL;
		return NULL;
	}

	char *fsym = xmalloc ( ( 1 << 8 ) + 2 );
	sprintf ( fsym, "/proc/self/fd/%i", fd );

	if ( lstat64 ( fsym, &st64 ) ) {
		error ( "Cannot lstat64(\"%s\", st64).", fsym );
		return NULL;
	}

	ssize_t fpathlen = st64.st_size;

	char *fpath = xmalloc ( fpathlen + 2 );

	debug ( 3, "Getting file path from symlink \"%s\". Path length is: %i.", fsym, fpathlen );

	if ( ( fpathlen = readlink ( fsym, fpath, fpathlen + 1 ) ) < 0 ) {
		error ( "Cannot readlink(\"%s\", fpath, bufsize).", fsym );
        free(fsym);
		return NULL;
	}

	fpath[fpathlen] = 0;
	debug ( 3, "The path is: \"%s\"", fpath );
	free(fsym);
	return fpath;
#else
	critical ( "Function fd2fpath_malloc() is not supported in this OS" );
	return NULL;
#endif
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

int fileutils_copy ( const char *path_from, const char *path_to )
{
	char buf[BUFSIZ];
	FILE *from, *to;
	from = fopen ( path_from, "r" );

	if ( from == NULL ) {
		error ( "fileutils_copy(\"%s\", \"%s\"): Cannot open file \"%s\" for reading",
		        path_from, path_to, path_from );
		return errno;
	}

	to   = fopen ( path_to,   "w" );

	if ( to == NULL ) {
		error ( "fileutils_copy(\"%s\", \"%s\"): Cannot open file \"%s\" for writing",
		        path_from, path_to, path_to );
		return errno;
	}

	while ( !feof ( from ) ) {
		int err;
		size_t r, w;
		r =  fread ( buf, 1, BUFSIZ, from );

		if ( ( err = ferror ( from ) ) ) {
			error ( "fileutils_copy(\"%s\", \"%s\"): Cannot read from file \"%s\"",
			        path_from, path_to, path_from );
			return errno;	// CHECK: Is the "errno" should be used in fread() case?
		}

		w = fwrite ( buf, 1, r,      to );

		if ( ( err = ferror ( to ) ) ) {
			error ( "fileutils_copy(\"%s\", \"%s\"): Cannot write to file \"%s\"",
			        path_from, path_to, path_to );
			return errno;	// CHECK: is the "errno" should be used in fwrite() case?
		}

		if ( r != w ) {
			error ( "fileutils_copy(\"%s\", \"%s\"): Got error while writing to file \"%s\" (%u != %u)",
			        path_from, path_to, path_to, r, w );
			return errno;	// CHECK: is the "errno" should be used in case "r != w"?
		}
	}

	return 0;
}


/**
 * @brief 				Calculates directory level of a canonized path (actually it just counts "/"-s)
 *
 * @param[in] 	path 			Canonized path (with realpath())
 *
 * @retval	zero or prositive	Direcory level
 * @retval	negative 		Got error, while calculation. Error-code is placed to errno.
 *
 */

short int fileutils_calcdirlevel ( const char *path )
{
	short int dirlevel = 0;
	const char *ptr = path;

	if ( path == NULL ) {
		error ( "path is NULL." );
		errno = EINVAL;
		return -1;
	}

	if ( *path == 0 ) {
		error ( "path has zero length." );
		errno = EINVAL;
		return -2;
	}

	if ( *path != '/' ) {
		error ( "path \"%s\" is not canonized.", path );
		errno = EINVAL;
		return -3;
	}

	while ( * ( ptr++ ) )
		if ( *ptr == '/' )
			dirlevel++;

	return dirlevel;
}

/**
 * @brief 			Combination of mkdirat() and openat()
 *
 * @param[in]	dir_path	Path to directory to create and open
 @ @param[in]	dirfd_parent	File descriptor of directory for relative paths
 @ @param[in]	dir_mode	Modes for newly created directory (e.g. 750)
 *
 * @retval	dirfd		File descriptor to newly created directory
 * @retval	NULL		On error
 *
 */
int mkdirat_open ( const char *const dir_path, int dirfd_parent, mode_t dir_mode )
{
	int dirfd;
	debug ( 5, "mkdirat(%u, \"%s\", %o)", dirfd_parent, dir_path, dir_mode );

	if ( mkdirat ( dirfd_parent, dir_path, dir_mode ) )
		return -1;

	debug ( 5, "openat(%u, \"%s\", %x)", dirfd_parent, dir_path, O_RDWR | O_DIRECTORY | O_PATH );
	dirfd = openat ( dirfd_parent, dir_path, O_RDWR | O_DIRECTORY | O_PATH );

	if ( dirfd == -1 )
		return -1;

	return dirfd;
}

/**
 * @brief 			Opens a directory with open()
 *
 * @param[out]	fd_p		Pointer to the result file descriptor
 @ @param[in]	dir_path	Path to the directory
 *
 * @retval	*fd_p		On success
 * @retval	-1		On error
 *
 * /
int open_dir(int *fd_p, const char *const dir_path) {
	int fd = open(dir_path, O_RDONLY|O_DIRECTORY|O_PATH);
	if (fd == -1) {
		error("Got error while open(\"%s\", O_RDWR|O_DIRECTORY|O_PATH)", dir_path);
		return fd;
	}

	*fd_p = fd;
	return fd;
}
*/


uint32_t stat_diff ( stat64_t *a, stat64_t *b )
{
	uint32_t difference;
#ifdef PARANOID
	critical_on ( a == NULL );
	critical_on ( b == NULL );
#endif
	difference = 0x0000;
#define STAT_COMPARE(bit, field)	\
	if (a->field != b->field)	\
		difference |= bit;
	STAT_COMPARE ( STAT_FIELD_DEV,	st_dev );
	STAT_COMPARE ( STAT_FIELD_INO,	st_ino );
	STAT_COMPARE ( STAT_FIELD_MODE,	st_mode );
	STAT_COMPARE ( STAT_FIELD_NLINK,	st_nlink );
	STAT_COMPARE ( STAT_FIELD_UID,	st_uid );
	STAT_COMPARE ( STAT_FIELD_GID,	st_gid );
	STAT_COMPARE ( STAT_FIELD_RDEV,	st_rdev );
	STAT_COMPARE ( STAT_FIELD_SIZE,	st_size );
	STAT_COMPARE ( STAT_FIELD_BLKSIZE, st_blksize );
	STAT_COMPARE ( STAT_FIELD_BLOCKS,	st_blocks );
	STAT_COMPARE ( STAT_FIELD_ATIME,	st_atime );
	STAT_COMPARE ( STAT_FIELD_MTIME,	st_mtime );
	STAT_COMPARE ( STAT_FIELD_CTIME,	st_ctime );
#undef STAT_COMPARE
	return difference;
}

