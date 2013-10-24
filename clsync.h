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

#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>

#define CLSYNC_API_VERSION 2

enum eventobjtype {
	EOT_UNKNOWN	= 0,		// Unknown
	EOT_DOESNTEXIST	= 1,		// Doesn't exists (not created yet or already deleted)
	EOT_FILE	= 2,		// File
	EOT_DIR		= 3,		// Directory
};
typedef enum eventobjtype eventobjtype_t;

struct api_eventinfo {
	uint32_t	 evmask;	// event mask, see /usr/include/linux/inotify.h
	uint32_t	 flags;		// flags, see "enum eventinfo_flags"
	size_t		 path_len;	// strlen(path)
	const char	*path;		// path
	eventobjtype_t   objtype_old;	// type of object by path "path" before the event
	eventobjtype_t   objtype_new;	// type of object by path "path" after  the event
};
typedef struct api_eventinfo api_eventinfo_t;

struct options;
struct indexes;
typedef int(*api_funct_init)  (struct options *, struct indexes *);
typedef int(*api_funct_sync)  (int n, api_eventinfo_t *);
typedef int(*api_funct_rsync) (const char *inclist, const char *exclist);
typedef int(*api_funct_deinit)();

enum eventinfo_flags {
	EVIF_NONE		= 0x00000000,	// No modifier
	EVIF_RECURSIVELY	= 0x00000001,	// Need to be synced recursively
	EVIF_CONTENTRECURSIVELY	= 0x00000002,	// Affects recursively only on content of this dir
};
typedef enum eventinfo_flags eventinfo_flags_t;

/**
 * @brief 			Writes the list to list-file for "--include-from" option of rsync using array of api_eventinfo_t
 * 
 * @param[in]	indexes_p	Pointer to "indexes"
 * @param[in]	listfile	File identifier to write to
 * @param[in]	n		Number of records in apievinfo
 * @param[in]	apievinfo	Pointer to api_eventinfo_t records
 * 
 * @retval	zero		Successful
 * @retval	non-zero	If got error while deleting the message. The error-code is placed into returned value.
 * 
 */
extern int apievinfo2rsynclist(struct indexes *indexes_p, FILE *listfile, int n, api_eventinfo_t *apievinfo); // Not tested, yet

/**
 * @brief 			Returns currect API version
 * 
 * @retval	api_version	Version of clsync's API
 * 
 */
extern int clsyncapi_getapiversion();

/**
 * @brief 			clsync's wrapper for function "fork()". Should be used instead of "fork()" directly, to notify clsync about child's pid.
 *
 * @param[in]	options_p	Pointer to "options"
 * 
 * @retval	-1		If error (see "man 2 fork", added error code "ECANCELED" if too many children)
 * @retval	0		If child
 * @retval	pid		Pid of child of parent. (see "man 2 fork")
 * 
 */
extern pid_t clsyncapi_fork(struct options *options_p);

