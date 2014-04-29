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

#include <sys/un.h>	// for "struct sockaddr_un"

#include "error.h"
#include "sync.h"
#include "control.h"
#include "socket.h"

static pthread_t pthread_control;

int control_procclsyncsock(socket_sockthreaddata_t *arg, sockcmd_t *sockcmd_p) {
	clsyncsock_t	*clsyncsock_p =              arg->clsyncsock_p;
	glob_t 	*glob_p    = (glob_t *)arg->arg;

	switch(sockcmd_p->cmd_id) {
		case SOCKCMD_REQUEST_INFO: {
			socket_send(clsyncsock_p, SOCKCMD_REPLY_INFO, glob_p->config_block, glob_p->label, glob_p->flags, glob_p->flags_set);
			break;
		}
		case SOCKCMD_REQUEST_DIE: {
			sync_term(SIGTERM);
			break;
		}
		default:
			return EINVAL;
	}

	return 0;
}

static inline void closecontrol(glob_t *glob_p) {
	if(glob_p->socket) {
		close(glob_p->socket);
		glob_p->socket = 0;
	}
}

int control_loop(glob_t *glob_p) {

	// Starting

	debug(1, "started (glob_p->socket == %u)", glob_p->socket);
	int s;

	while((s=glob_p->socket)) {

		// Check if the socket is still alive
		if(socket_check_bysock(s)) {
			debug(1, "Control socket closed [case 0]: %s", strerror(errno));
			closecontrol(glob_p);
			continue;
		}

		// Waiting for event
		debug(3, "waiting for events on the socket");
		fd_set rfds;

		FD_ZERO(&rfds);
		FD_SET(s, &rfds);

		int count = select(s+1, &rfds, NULL, NULL, NULL);

		// Processing the events
		debug(2, "got %i events with select()", count);

		// Processing the events: checks
		if(count == 0) {
			debug(2, "select() timed out.");
			continue;
		}

		if(count < 0) {
			debug(1, "Got negative events count. Closing the socket.");
			closecontrol(glob_p);
			continue;
		}

		if(!FD_ISSET(s, &rfds)) {
			error("Got event, but not on the control socket. Closing the socket (cannot use \"select()\").");
			closecontrol(glob_p);
			continue;
		}

		// Processing the events: accepting new clsyncsock

		clsyncsock_t *clsyncsock_p = socket_accept(s);
		if(clsyncsock_p == NULL) {

			if(errno == EUSERS)	// Too many connections. Just ignoring the new one.
				continue;

			// Got unknown error. Closing control socket just in case.
			error("Cannot socket_accept()");
			closecontrol(glob_p);
			continue;
		}

		debug(2, "Starting new thread for new connection.");
		socket_sockthreaddata_t *threaddata_p = socket_thread_attach(clsyncsock_p);

		if (threaddata_p == NULL) {
			error("Cannot create a thread for connection");
			closecontrol(glob_p);
			continue;
		}

		threaddata_p->procfunct		=  control_procclsyncsock;
		threaddata_p->clsyncsock_p	=  clsyncsock_p;
		threaddata_p->arg		=  glob_p;
		threaddata_p->running		= &glob_p->socket;
		threaddata_p->authtype		=  glob_p->flags[SOCKETAUTH];
		threaddata_p->flags		=  0;

		if (socket_thread_start(threaddata_p)) {
			error("Cannot start a thread for connection");
			closecontrol(glob_p);
			continue;
		}
#ifdef DEBUG
		// To prevent too often connections
		sleep(1);
#endif
	}

	// Cleanup

	debug(1, "control_loop() finished");
	return 0;
}

int control_run(glob_t *glob_p) {
	if(glob_p->socketpath != NULL) {
		int ret =  0;
		int s   = -1;

		// initializing clsync-socket subsystem
		if ((ret = socket_init()))
			error("Cannot init clsync-sockets subsystem.");


		if (!ret) {
			clsyncsock_t *clsyncsock = socket_listen_unix(glob_p->socketpath);
			if (clsyncsock == NULL) {
				ret = errno;
			} else {
				s = clsyncsock->sock;
				socket_cleanup(clsyncsock);
			}
		}

		// fixing privileges
		if (!ret) {
			if(glob_p->flags[SOCKETMOD])
				if(chmod(glob_p->socketpath, glob_p->socketmod)) {
					error("Error, Cannot chmod(\"%s\", %o)", 
						glob_p->socketpath, glob_p->socketmod);
					ret = errno;
				}
			if(glob_p->flags[SOCKETOWN])
				if(chown(glob_p->socketpath, glob_p->socketuid, glob_p->socketgid)) {
					error("Error, Cannot chown(\"%s\", %u, %u)", 
						glob_p->socketpath, glob_p->socketuid, glob_p->socketgid);
					ret = errno;
				}
		}

		// finish
		if (ret) {
			close(s);
			return ret;
		}

		glob_p->socket = s;

		debug(2, "glob_p->socket = %u", glob_p->socket);

		ret = pthread_create(&pthread_control, NULL, (void *(*)(void *))control_loop, glob_p);
	}
	
	return 0;
}

int control_cleanup(glob_t *glob_p) {
	if(glob_p->socketpath != NULL) {
		unlink(glob_p->socketpath);
		closecontrol(glob_p);
		// TODO: kill pthread_control and join
//		pthread_join(pthread_control, NULL);
		socket_deinit();
	}
	return 0;
}

