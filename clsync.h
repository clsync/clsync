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

#include <stdint.h>
#include <sys/types.h>

struct api_eventinfo {
	uint32_t	 evmask;
	uint32_t	 flags;
	size_t		 path_len;
	const char	*path;
};
typedef struct api_eventinfo api_eventinfo_t;

struct options;
struct indexes;
typedef int(*api_funct_init)  (struct options *, struct indexes *);
typedef int(*api_funct_sync)  (int n, api_eventinfo_t *);
typedef int(*api_funct_deinit)();

enum eventinfo_flags {
	EVIF_NONE		= 0x00000000,
	EVIF_RECURSIVELY	= 0x00000001,
};

