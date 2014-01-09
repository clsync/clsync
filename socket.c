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

#ifdef ENABLE_SOCKET

#include "common.h"

#include <sys/un.h>	// for "struct sockaddr_un"

#include "output.h"
#include "sync.h"
#include "socket.h"

static pthread_t pthread_socket;

static inline int socketcheck(int sock) {
	int error_code, ret;
	socklen_t error_code_len = sizeof(error_code);

	if((ret=getsockopt(sock, SOL_SOCKET, SO_ERROR, &error_code, &error_code_len))) {
		return errno;
	}
	if(error_code) {
		errno = error_code;
		return error_code;
	}

	return 0;
}

int socket_send(client_t *client, sockcmd_id_t cmd_id, ...) {
	va_list ap;
	int ret;

	va_start(ap, cmd_id);
/*	static char bufs[SOCKET_CLIENTS_MAX][SOCKET_BUFSIZ], prebufs0[SOCKET_CLIENTS_MAX][SOCKET_BUFSIZ], prebufs1[SOCKET_CLIENTS_MAX][SOCKET_BUFSIZ];
	char *prebuf0 = prebufs0[client_sock], *prebuf1 = prebufs1[client_sock], *sendbuf = bufs[client_sock];
*/
	char prebuf0[SOCKET_BUFSIZ], prebuf1[SOCKET_BUFSIZ], sendbuf[SOCKET_BUFSIZ];

	ret = 0;

	switch(client->prot) {
		case 0:
			switch(client->subprot) {
				case SUBPROT0_TEXT: {
					va_list ap_copy;


					if(textmessage_args[cmd_id]) {
						va_copy(ap_copy, ap);
						vsprintf(prebuf0, textmessage_args[cmd_id], ap_copy);
					} else
						*prebuf0 = 0;

					va_copy(ap_copy, ap);
					vsprintf(prebuf1, textmessage_descr[cmd_id], ap);

					size_t sendlen = sprintf(sendbuf, "%03u %s :%s\n", cmd_id, prebuf0, prebuf1);

					send(client->sock, sendbuf, sendlen, 0);
					break;
				}
/*				case SUBPROT0_BINARY:
					break;*/
				default:
					printf_e("Error: socket_send(): Unknown subprotocol with id %u.\n", client->subprot);
					ret = EINVAL;
					goto l_socket_send_end;
			}
			break;
		default:
			printf_e("Error: socket_send(): Unknown protocol with id %u.\n", client->prot);
			ret = EINVAL;
			goto l_socket_send_end;
	}

l_socket_send_end:
	va_end(ap);
	return ret;
}

static inline int socket_overflow_fix(char *buf, char **data_start_p, char **data_end_p) {
	printf_ddd("Debug3: socket_overflow_fix(): buf==%p; data_start==%p; data_end==%p\n", buf, *data_start_p, *data_end_p);
	if(buf == *data_start_p)
		return 0;

	size_t ptr_diff = *data_start_p - buf;

	if(*data_start_p != *data_end_p) {
		*data_start_p = buf;
		*data_end_p   = buf;
		return ptr_diff;
	}

	size_t data_length = *data_end_p - *data_start_p;

	memmove(buf, *data_start_p, data_length);
	*data_start_p =  buf;
	*data_end_p   = &buf[data_length];

	return ptr_diff;
}

static char *recv_stps[SOCKET_CLIENTS_MAX];
static char *recv_ptrs[SOCKET_CLIENTS_MAX];
int socket_recv(client_t *client, sockcmd_t *sockcmd) {
	static char bufs[SOCKET_CLIENTS_MAX][SOCKET_BUFSIZ];
	char *buf, *ptr, *start, *end;
	int client_sock;
	size_t filled_length, rest_length, recv_length, filled_length_new;

	client_sock = client->sock;

	buf = bufs[client_sock];

	start =  recv_stps[client_sock];
	start = (start==NULL ? buf : start);

	ptr   =  recv_ptrs[client_sock];
	ptr   = (ptr==NULL   ? buf : ptr);

	printf_ddd("Debug3: socket_recv(): buf==%p; start==%p; ptr==%p\n", buf, start, ptr);

	while(1) {
		filled_length = ptr-buf;
		rest_length = SOCKET_BUFSIZ-filled_length-16;

		if(rest_length <= 0) {
			if(!socket_overflow_fix(buf, &start, &ptr)) {
				printf_d("Debug: socket_recv(): Got too big message. Ignoring.\n");
				ptr = buf;
			}
			continue;
		}

		recv_length = recv(client_sock, ptr, rest_length, 0);
		filled_length_new = filled_length + recv_length;

		if(recv_length <= 0)
			return errno;

		switch(client->prot) {
			case 0: {
				// Checking if binary
				uint16_t cmd_id_binary = *(uint16_t *)buf;
				client->subprot = (cmd_id_binary == SOCKCMD_NEGOTIATION) ? SUBPROT0_BINARY : SUBPROT0_TEXT;

				// Processing
				switch(client->subprot) {
					case SUBPROT0_TEXT:
						if((end=strchr(ptr, '\n'))!=NULL) {
							if(sscanf(start, "%03u", (unsigned int *)&sockcmd->cmd_id) != 1)
								return EBADRQC;

							// TODO Process message here

							goto l_socket_recv_end;
						}
						break;
					default:
						return ENOPROTOOPT;
				}
				break;
			}
			default:
				return ENOPROTOOPT;
		}

		
	}

l_socket_recv_end:
	
	//       ----------------------------------
	//       buf    ptr    end    filled
	// cut:  ---------------
	//                    start    ptr
	//                     new     new

	start = &end[1];
	ptr   = &buf[filled_length_new];

	// No data buffered. Reset "start" and "ptr".

	if(start == ptr) {
		start = buf;
		ptr   = buf;
	}

	// Remembering the values

	recv_stps[client_sock] = start;
	recv_ptrs[client_sock] = ptr;

	printf_ddd("Debug3: socket_recv(): buf==%p; ptr==%p; end==%p, filled=%p, buf_end==%p\n", buf, ptr, end, &buf[filled_length_new], &buf[SOCKET_BUFSIZ]);

	sockcmd->cmd_num++;
	return 0;
}

struct socket_procclient_arg {
	int		 num;
	int 		 sock;
	options_t 	*options_p;
	client_state_t	 state;
};
int socket_procclient(struct socket_procclient_arg *arg) {
#define SL(a) a,sizeof(a)-1
	client_t client = {0};
	char		_sockcmd[SOCKET_BUFSIZ]={0};
	sockcmd_t	*sockcmd = (sockcmd_t *)_sockcmd;
	int		 client_sock  = arg->sock;
	options_t 	*options_p    = arg->options_p;

	sockcmd->cmd_num = -1;

	client.sock    = client_sock;
	client.prot    = SOCKET_DEFAULT_PROT;
	client.subprot = SOCKET_DEFAULT_SUBPROT;

	enum auth_flags {
		AUTHFLAG_ENTERED_LOGIN = 0x01,
	};
	typedef enum auth_flags auth_flags_t;
	auth_flags_t	 auth_flags = 0;

	printf_ddd("Debug3: socket_procclient(): Started new thread for new client connection.\n");

	arg->state = (options_p->flags[SOCKETAUTH] == SOCKAUTH_NULL) ? CLSTATE_MAIN : CLSTATE_AUTH;
	socket_send(&client, SOCKCMD_NEGOTIATION);

	while(options_p->socket && (arg->state==CLSTATE_AUTH || arg->state==CLSTATE_MAIN)) {
		printf_ddd("Debug3: socket_procclient(): Iteration.\n");

		// Receiving message
		int ret;
		if((ret = socket_recv(&client, sockcmd))) {
			printf_e("Error: socket_procclient(): Got error while receiving a message from client #%u: %s (errno: %u)\n", 
				arg->num, strerror(ret), ret);
			break;
		}

		// Processing the message
		switch(sockcmd->cmd_id) {
			case SOCKCMD_NEGOTIATION: {
				struct sockcmd_negotiation *data = (struct sockcmd_negotiation *)sockcmd->data;
				switch(data->prot) {
					case 0:
						switch(data->subprot) {
							case SUBPROT0_TEXT:
							case SUBPROT0_BINARY:
								client.subprot = data->subprot;
								socket_send(&client, SOCKCMD_ACK,    sockcmd->cmd_id, sockcmd->cmd_num);
								break;
							default:
								socket_send(&client, SOCKCMD_EINVAL, sockcmd->cmd_id, sockcmd->cmd_num, "Incorrect subprotocol id");
						}
						break;
					default:
						socket_send(&client, SOCKCMD_EINVAL, sockcmd->cmd_id, sockcmd->cmd_num, "Incorrect protocol id");
				}
				break;
			}
			case SOCKCMD_VERSION: {
				socket_send(&client, SOCKCMD_VERSION, VERSION_MAJ, VERSION_MIN);
				break;
			}
			case SOCKCMD_QUIT: {
				socket_send(&client, SOCKCMD_BYE);
				arg->state = CLSTATE_DYING;
				break;
			}
			case SOCKCMD_INFO: {
				socket_send(&client, SOCKCMD_INFO, options_p->config_block, options_p->label, options_p->flags, options_p->flags_set);
				break;
			}
			case SOCKCMD_DIE: {
				sync_term(SIGTERM);
				break;
			}
			default:
				if(sockcmd->cmd_id >= 1000)
					socket_send(&client, SOCKCMD_INVALIDCMDID, sockcmd->cmd_num);
				else
					socket_send(&client, SOCKCMD_UNKNOWNCMD, sockcmd->cmd_id, sockcmd->cmd_num);
				break;
		}

		// Check if the socket is still alive
		if(socketcheck(client_sock)) {
			printf_d("Debug: Client socket error: %s\n", strerror(errno));
			break;
		}

		// Sending prompt
		switch(arg->state) {
			case CLSTATE_AUTH:
				if(!(auth_flags&AUTHFLAG_ENTERED_LOGIN))
					socket_send(&client, SOCKCMD_LOGIN);
				break;
			default:
				break;
		}
	}

	printf_ddd("Debug3: socket_procclient(): Ending a client connection thread.\n");

	recv_ptrs[client_sock] = NULL;
	recv_stps[client_sock] = NULL;

	if(arg->state != CLSTATE_DIED) {
		arg->state = CLSTATE_DIED;
		close(client_sock);
	}
	return 0;
#undef SL
}

static inline void closesocket(options_t *options_p) {
	if(options_p->socket) {
		close(options_p->socket);
		options_p->socket = 0;
	}
}

int socket_loop(options_t *options_p) {
	int		clients_last    = -1;
	int 		clients_count   =  0;
	pthread_t	clients_threads[SOCKET_CLIENTS_MAX+1];
	struct socket_procclient_arg clients_args[SOCKET_CLIENTS_MAX+1] = {{0}};

	// Starting

	printf_d("Debug2: socket_loop() started (options_p->socket == %u)\n", options_p->socket);
	int s;

	while((s=options_p->socket)) {

		// Check if the socket is still alive
		if(socketcheck(s)) {
			printf_d("Debug: Control socket closed [case 0]: %s\n", strerror(errno));
			closesocket(options_p);
			continue;
		}

		// Waiting for event
		printf_ddd("Debug3: socket_loop(): waiting for events on the socket\n");
		fd_set rfds;

		FD_ZERO(&rfds);
		FD_SET(s, &rfds);

		int count = select(s+1, &rfds, NULL, NULL, NULL);

		// Processing the events
		printf_dd("Debug2: socket_loop(): got %i events with select()\n", count);

		// Processing the events: checks
		if(count == 0) {
			printf_dd("Debug2: socket_loop(): select() timed out.\n");
			continue;
		}

		if(count < 0) {
			printf_d("Debug: socket_loop(): Got negative events count. Closing the socket.\n");
			closesocket(options_p);
			continue;
		}

		if(!FD_ISSET(s, &rfds)) {
			printf_e("Error: socket_loop(): Got event, but not on the control socket. Closing the socket (cannot use \"select()\").\n");
			closesocket(options_p);
			continue;
		}

		// Collecting died connections to free the space for new client and searching a free cell

		int client_num = -1;
		int i=clients_last+1;
		while(i) {
			i--;
			switch(clients_args[i].state) {
				case CLSTATE_DIED:
					printf_ddd("Debug3: socket_loop(): Forgeting client #%u\n", i);
					pthread_join(clients_threads[i], NULL);
					clients_args[i].state = CLSTATE_NONE;
					clients_count--;
					if(!clients_count)
						clients_last = -1;	// No clients
				case CLSTATE_NONE:
					if(clients_last == i+1)
						clients_last = i;
					client_num = i;
					break;
				default:
					break;
			}
		}

		// If there's no free cells, getting a new one

		client_num = clients_last+1;

		// Processing the events: checking the limit of clients
		if(client_num >= SOCKET_CLIENTS_MAX) {
			printf_e("Warning: socket_loop(): Too many connection to control socket. Closing the new one.\n");
			continue;
		}

		// Processing the events: accepting new client

		int client_sock = accept(s, NULL, NULL);
		if(client_sock == -1) {
			printf_e("Error: socket_loop(): Cannot accept(): %s (errno: %i)\n", strerror(errno), errno);
			closesocket(options_p);
			continue;
		}

		struct socket_procclient_arg *client_arg = &clients_args[client_num];

#ifdef PARANOID
		// Processing the events: checking if previous check were been made right

		if(client_arg->state != CLSTATE_NONE) {
			// This's not supposed to be
			printf_e("Internal-Error: socket_loop(): client_arg->state != CLSTATE_NONE\n");
			closesocket(options_p);
			continue;
		}
#endif

		// Processing the events: creating a thread for new client connection

		printf_ddd("Debug3: socket_loop(): clients_count == %u;\tclients_last == %u;\tclient_num == %u\n", 
			clients_count, clients_last, client_num);

		clients_last = MAX(clients_last, client_num);

		clients_count++;

		client_arg->num 	= client_num;
		client_arg->sock 	= client_sock;
		client_arg->options_p	= options_p;

		printf_dd("Debug2: socket_loop(): Starting new thread for new client connection.\n");
		if(pthread_create(&clients_threads[client_num], NULL, (void *(*)(void *))socket_procclient, client_arg)) {
			printf_e("Error: socket_loop(): Cannot create a thread for client connection: %s (errno: %i)\n", strerror(errno), errno);
			closesocket(options_p);
			continue;
		}
#ifdef DEBUG
		// Too prevent to often connections
		sleep(1);
#endif
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

		printf_dd("Debug2: socket_run(): options_p->socket = %u\n", options_p->socket);

		ret = pthread_create(&pthread_socket, NULL, (void *(*)(void *))socket_loop, options_p);
	}
	
	return 0;
}

int socket_cleanup(options_t *options_p) {
	if(options_p->socketpath != NULL) {
		unlink(options_p->socketpath);
		closesocket(options_p);
		// TODO: kill pthread_socket and join
//		pthread_join(pthread_socket, NULL);
	}
	return 0;
}

#endif

