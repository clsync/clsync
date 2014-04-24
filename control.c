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

#include "output.h"
#include "sync.h"
#include "control.h"
#include "socket.h"

static pthread_t pthread_control;

int control_procclsyncsock(socket_sockthreaddata_t *arg, sockcmd_t *sockcmd_p) {
	clsyncsock_t	*clsyncsock_p =              arg->clsyncsock_p;
	options_t 	*options_p    = (options_t *)arg->arg;

	switch(sockcmd_p->cmd_id) {
		case SOCKCMD_REQUEST_INFO: {
			socket_send(clsyncsock_p, SOCKCMD_REPLY_INFO, options_p->config_block, options_p->label, options_p->flags, options_p->flags_set);
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

static inline void closecontrol(options_t *options_p) {
	if(options_p->socket) {
		close(options_p->socket);
		options_p->socket = 0;
	}
}

int control_loop(options_t *options_p) {

	// Starting

	printf_d("Debug2: control_loop() started (options_p->socket == %u)\n", options_p->socket);
	int s;

	while((s=options_p->socket)) {

		// Check if the socket is still alive
		if(socket_check_bysock(s)) {
			printf_d("Debug: Control socket closed [case 0]: %s\n", strerror(errno));
			closecontrol(options_p);
			continue;
		}

		// Waiting for event
		printf_ddd("Debug3: control_loop(): waiting for events on the socket\n");
		fd_set rfds;

		FD_ZERO(&rfds);
		FD_SET(s, &rfds);

		int count = select(s+1, &rfds, NULL, NULL, NULL);

		// Processing the events
		printf_dd("Debug2: control_loop(): got %i events with select()\n", count);

		// Processing the events: checks
		if(count == 0) {
			printf_dd("Debug2: control_loop(): select() timed out.\n");
			continue;
		}

		if(count < 0) {
			printf_d("Debug: control_loop(): Got negative events count. Closing the socket.\n");
			closecontrol(options_p);
			continue;
		}

		if(!FD_ISSET(s, &rfds)) {
			printf_e("Error: control_loop(): Got event, but not on the control socket. Closing the socket (cannot use \"select()\").\n");
			closecontrol(options_p);
			continue;
		}

		// Processing the events: accepting new clsyncsock

		clsyncsock_t *clsyncsock_p = socket_accept(s);
		if(clsyncsock_p == NULL) {

			if(errno == EUSERS)	// Too many connections. Just ignoring the new one.
				continue;

			// Got unknown error. Closing control socket just in case.
			printf_e("Error: control_loop(): Cannot socket_accept(): %s (errno: %i)\n", strerror(errno), errno);
			closecontrol(options_p);
			continue;
		}

		printf_dd("Debug2: control_loop(): Starting new thread for new connection.\n");
		socket_sockthreaddata_t *threaddata_p = socket_thread_attach(clsyncsock_p);

		if (threaddata_p == NULL) {
			printf_e("Error: control_loop(): Cannot create a thread for connection: %s (errno: %i)\n", strerror(errno), errno);
			closecontrol(options_p);
			continue;
		}

		threaddata_p->procfunct		=  control_procclsyncsock;
		threaddata_p->clsyncsock_p	=  clsyncsock_p;
		threaddata_p->arg		=  options_p;
		threaddata_p->running		= &options_p->socket;
		threaddata_p->authtype		=  options_p->flags[SOCKETAUTH];
		threaddata_p->flags		=  0;

		if (socket_thread_start(threaddata_p)) {
			printf_e("Error: control_loop(): Cannot start a thread for connection: %s (errno: %i)\n", strerror(errno), errno);
			closecontrol(options_p);
			continue;
		}
#ifdef DEBUG
		// To prevent too often connections
		sleep(1);
#endif
	}

	// Cleanup

	printf_d("Debug2: control_loop() finished\n");
	return 0;
}

int control_run(options_t *options_p) {
	if(options_p->socketpath != NULL) {
		int ret =  0;
		int s   = -1;

		// initializing clsync-socket subsystem
		if ((ret = socket_init()))
			printf_e("Error: Cannot init clsync-sockets subsystem.\n");


		if (!ret) {
			clsyncsock_t *clsyncsock = socket_listen_unix(options_p->socketpath);
			if (clsyncsock == NULL) {
				ret = errno;
			} else {
				s = clsyncsock->sock;
				socket_cleanup(clsyncsock);
			}
		}

		// fixing privileges
		if (!ret) {
			if(options_p->flags[SOCKETMOD])
				if(chmod(options_p->socketpath, options_p->socketmod)) {
					printf_e("Error, Cannot chmod(\"%s\", %o): %s (errno: %i)\n", 
						options_p->socketpath, options_p->socketmod, strerror(errno), errno);
					ret = errno;
				}
			if(options_p->flags[SOCKETOWN])
				if(chown(options_p->socketpath, options_p->socketuid, options_p->socketgid)) {
					printf_e("Error, Cannot chown(\"%s\", %u, %u): %s (errno: %i)\n", 
						options_p->socketpath, options_p->socketuid, options_p->socketgid, strerror(errno), errno);
					ret = errno;
				}
		}

		// finish
		if (ret) {
			close(s);
			return ret;
		}

		options_p->socket = s;

		printf_dd("Debug2: control_run(): options_p->socket = %u\n", options_p->socket);

		ret = pthread_create(&pthread_control, NULL, (void *(*)(void *))control_loop, options_p);
	}
	
	return 0;
}

int control_cleanup(options_t *options_p) {
	if(options_p->socketpath != NULL) {
		unlink(options_p->socketpath);
		closecontrol(options_p);
		// TODO: kill pthread_control and join
//		pthread_join(pthread_control, NULL);
		socket_deinit();
	}
	return 0;
}

