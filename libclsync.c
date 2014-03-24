/*
    libclsyncmgr - clsync control socket API
    
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

#include "common.h"

#include <sys/un.h>	// for "struct sockaddr_un"

#include "socket.h"
#include "malloc.h"
#include "output.h"

printf_funct _printf_ddd=NULL;
printf_funct _printf_dd=NULL;
printf_funct _printf_d=NULL;
printf_funct _printf_v=NULL;
printf_funct printf_e=printf_stderr;
write_funct _write_ddd=NULL;
write_funct _write_dd=NULL;
write_funct _write_d=NULL;
write_funct _write_v=NULL;
write_funct write_e=NULL;

struct clsync {
	clsyncconn_t 		*conn_p;
	clsyncconn_procfunct_t	 procfunct;
};
typedef struct clsync clsync_t;


int libclsync_procclsyncconn(socket_connthreaddata_t *arg, sockcmd_t *sockcmd_p) {
	clsync_t		*clsync_p     = arg->arg;
	clsyncconn_t		*clsyncconn_p = clsync_p->conn_p;
	clsyncconn_procfunct_t   procfunct    = clsync_p->procfunct;

#ifdef PARANOID
	if (procfunct == NULL) {
		printf_e("Error: libclsync_procclsyncconn(): procfunct == NULL\n");
		return 0;
	}
#endif

	switch(sockcmd_p->cmd_id) {
		default:
			if(procfunct(arg, sockcmd_p))
				socket_sendinvalid(clsyncconn_p, sockcmd_p);
			break;
	}

	return 0;
}

static inline int _clsync_connect_setthreaddata(socket_connthreaddata_t *threaddata_p, clsync_t *clsync_p) {
	threaddata_p->procfunct		=  libclsync_procclsyncconn;
	threaddata_p->clsyncconn_p	=  clsync_p->conn_p;
	threaddata_p->arg		=  clsync_p;
	threaddata_p->running		=  NULL;
	threaddata_p->authtype		=  SOCKAUTH_NULL;
	threaddata_p->flags		=  0;

	return 0;
}

clsync_t *clsync_connect_unix(const char *const socket_path, clsyncconn_procfunct_t procfunct) {
	clsync_t *clsync_p = xmalloc(sizeof(*clsync_p));
	memset(clsync_p, 0, sizeof(*clsync_p));

	if (procfunct == NULL) {
		errno = EINVAL;
		return NULL;
	}

	clsync_p->conn_p = socket_connect_unix(socket_path);
	if(clsync_p->conn_p == NULL) {
		free(clsync_p);
		if(errno == EUSERS) {
			printf_e("Error: clsync_connect_unix(): Too many connections.\n");
			return NULL;
		}

		// Got unknown error. Closing control socket just in case.
		printf_e("Error: clsync_connect_unix(): Cannot socket_accept(): %s (errno: %i)\n", strerror(errno), errno);
		return NULL;
	}

	socket_connthreaddata_t *threaddata_p = socket_thread_attach(clsync_p->conn_p);
	if (threaddata_p == NULL) {
		socket_cleanup(clsync_p->conn_p);
		free(clsync_p);
		return NULL;
	}

	_clsync_connect_setthreaddata(threaddata_p, clsync_p);

	clsync_p->procfunct		=  procfunct;
	socket_thread_start(threaddata_p);

	return clsync_p;
}



