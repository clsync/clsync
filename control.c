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
#include "socket.h"
#include "control.h"

static pthread_t pthread_control;

int control_procclsyncconn(socket_procconnproc_arg_t *arg, sockcmd_t *sockcmd_p) {
	clsyncconn_t	*clsyncconn_p =              arg->clsyncconn_p;
	options_t 	*options_p    = (options_t *)arg->arg;

	switch(sockcmd_p->cmd_id) {
		case SOCKCMD_INFO: {
			socket_send(clsyncconn_p, SOCKCMD_INFO, options_p->config_block, options_p->label, options_p->flags, options_p->flags_set);
			break;
		}
		case SOCKCMD_DIE: {
			sync_term(SIGTERM);
			break;
		}
	}

	return EINVAL;
}

static inline void closecontrol(options_t *options_p) {
	if(options_p->socket) {
		close(options_p->socket);
		options_p->socket = 0;
	}
}

int control_loop(options_t *options_p) {
	pthread_t	clsyncconns_threads[SOCKET_MAX_CLSYNC+1];
	struct socket_procconnproc_arg clsyncconns_args[SOCKET_MAX_CLSYNC+1] = {{0}};

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

		// Cleaning up after died connections

		int i=clsyncconns_last+1;
		while(i) {
			i--;
			switch(clsyncconns_args[i].state) {
				case CLSTATE_DIED:
					printf_ddd("Debug3: control_loop(): Forgeting clsyncconn #%u\n", i);
					pthread_join(clsyncconns_threads[i], NULL);
					clsyncconns_args[i].state = CLSTATE_NONE;
					break;
				default:
					break;
			}
		}

		// Processing the events: accepting new clsyncconn

		clsyncconn_t *clsyncconn_p = socket_accept(s);
		if(clsyncconn_p == NULL) {

			if(errno == EUSERS)	// Too many connections. Just ignoring the new one.
				continue;

			// Got unknown error. Closing control socket just in case.
			printf_e("Error: control_loop(): Cannot socket_accept(): %s (errno: %i)\n", strerror(errno), errno);
			closecontrol(options_p);
			continue;
		}

		struct socket_procconnproc_arg *connproc_arg = &clsyncconns_args[clsyncconns_num];

#ifdef PARANOID
		// Processing the events: checking if previous check were been made right

		if(connproc_arg->state != CLSTATE_NONE) {
			// This's not supposed to be
			printf_e("Internal-Error: control_loop(): connproc_arg->state != CLSTATE_NONE\n");
			closecontrol(options_p);
			continue;
		}
#endif

		// Processing the events: creating a thread for new connection

		printf_ddd("Debug3: control_loop(): clsyncconns_count == %u;\tclsyncconns_last == %u;\tclsyncconn_num == %u\n", 
			clsyncconns_count, clsyncconns_last, clsyncconns_num);

		clsyncconns_last = MAX(clsyncconns_last, clsyncconns_num);

		clsyncconns_count++;

		connproc_arg->procfunct		=  control_procclsyncconn;
		connproc_arg->clsyncconn_p	=  clsyncconn_p;
		connproc_arg->arg		=  options_p;
		connproc_arg->running		= &options_p->socket;
		connproc_arg->authtype		=  options_p->flags[SOCKETAUTH];
		connproc_arg->flags		=  0;

		printf_dd("Debug2: control_loop(): Starting new thread for new connection.\n");
		if(pthread_create(&clsyncconns_threads[clsyncconns_num], NULL, (void *(*)(void *))socket_procclsyncconn, connproc_arg)) {
			printf_e("Error: control_loop(): Cannot create a thread for connection: %s (errno: %i)\n", strerror(errno), errno);
			closecontrol(options_p);
			continue;
		}
#ifdef DEBUG
		// Too prevent to often connections
		sleep(1);
#endif
	}

	// Cleanup

	printf_d("Debug2: control_loop() finished\n");
	return 0;
}

int control_run(options_t *options_p) {
	if(options_p->socketpath != NULL) {
		int ret = 0;

		// initializing clsync-socket subsystem
		if((ret = socket_init()))
			printf_e("Error: Cannot init clsync-sockets subsystem.\n");

		// creating a simple unix socket
		int s = -1;
		if(!ret)
			s = socket(AF_UNIX, SOCK_STREAM, 0);

		// checking the path
		if(!ret) {
			// already exists? - unlink
			if(!access(options_p->socketpath, F_OK))
				if(unlink(options_p->socketpath)) {
					printf_e("Error: Cannot unlink() \"%s\": %s (errno: %i).\n", 
						options_p->socketpath, strerror(errno), errno);
					ret = errno;
				}
		}

		// binding
		if(!ret) {
			struct sockaddr_un addr;
			memset(&addr, 0, sizeof(addr));
			addr.sun_family = AF_UNIX;
			strncpy(addr.sun_path, options_p->socketpath, sizeof(addr.sun_path)-1);
			if(bind(s, (struct sockaddr *)&addr, sizeof(addr))) {
				printf_e("Error: Cannot bind() on address \"%s\": %s (errno: %i).\n",
					options_p->socketpath, strerror(errno), errno);
				ret = errno;
			}
		}

		// starting to listening
		if(!ret) {
			if(listen(s, SOCKET_BACKLOG)) {
				printf_e("Error: Cannot listen() on address \"%s\": %s (errno: %i).\n",
					options_p->socketpath, strerror(errno), errno);
				ret = errno;
			}
		}

		// fixing privileges
		if(!ret) {
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
		if(ret) {
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

