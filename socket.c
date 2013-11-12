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

static pthread_t pthread_socket;

int socket_loop(options_t *options_p) {

	// Configuring signals
	sigset_t sigset;
	sigemptyset(&sigset);
	sigaddset(&sigset, SIGTERM);

	int ret = pthread_sigmask(SIG_BLOCK, &sigset, NULL);
	if(ret)	return ret;


	// Starting

	printf_d("Debug2: socket_loop() started\n");
	int s;

	while((s=options_p->socket)) {

		// Checking for new signals
		int signal = sigwait(&sigset, &signal);

		if(signal) {
			switch(signal) {
				case SIGTERM:
					close(options_p->socket);
					options_p->socket=0;
					break;
				default:
					printf_e("Warning: Got unknown signal %i. Ignoring\n", signal);
					break;
			}
			continue;
		}

		// Check if the socket is still alive
		int error_code, ret;
		socklen_t error_code_len = sizeof(error_code);

		if((ret=getsockopt(s, SOL_SOCKET, SO_ERROR, &error_code, &error_code_len))) {
			printf_d("Debug: Control socket closed [case 0]: %s\n", strerror(ret));
			options_p->socket=0;
			continue;
		}
		if(error_code) {
			printf_d("Debug: Control socket closed [case 1]: %s\n", strerror(error_code));
			options_p->socket=0;
			continue;
		}

		// Waiting for event
		fd_set rfds;

		FD_ZERO(&rfds);
		FD_SET(s, &rfds);

		int count = select(s+1, &rfds, NULL, NULL, NULL);

		// Processing the events
		(void) count;
	}

	// Cleanup

	printf_d("Debug2: socket_loop() finished\n");
	return 0;
}

int socket_run(options_t *options_p) {
	if(options_p->socketpath != NULL) {
		int ret = 0;
		int s = socket(AF_UNIX, SOCK_STREAM, 0);

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

		// finish
		if(ret) {
			close(s);
			return ret;
		}

		options_p->socket = s;

		ret = pthread_create(&pthread_socket, NULL, (void *(*)(void *))socket_loop, &options_p);
	}
	
	return 0;
}

int socket_cleanup(options_t *options_p) {
	pthread_kill(pthread_socket, SIGTERM);
	return pthread_join(pthread_socket, NULL);
}

