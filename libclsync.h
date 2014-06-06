/*
    clsync - file tree sync utility based on inotify
    
    Copyright (C) 2014  Dmitry Yu Okunev <dyokunev@ut.mephi.ru> 0x8E30679C
    
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

#include "socket.h"

struct clsyncproc {
	clsyncsock_t 		*sock_p;
	clsyncsock_procfunct_t	 procfunct;
};
typedef struct clsyncproc clsyncproc_t;

extern int libclsync_init(int quite, int verbosity, int debug);
extern clsyncproc_t *clsync_listen_unix (const char *const socket_path, clsyncsock_procfunct_t procfunct, sockprocflags_t flags);
extern clsyncproc_t *clsync_connect_unix(const char *const socket_path, clsyncsock_procfunct_t procfunct, sockprocflags_t flags);

