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
#include "malloc.h"
#include "socket.h"

#if PIC
#	define SOCKET_MAX SOCKET_MAX_LIBCLSYNC
#else
#	define SOCKET_MAX SOCKET_MAX_CLSYNC
#endif

pthread_mutex_t socket_mutex = PTHREAD_MUTEX_INITIALIZER;

int clsyncconns_last	= -1;
int clsyncconns_count	=  0;
int clsyncconns_num	=  0;

char clsyncconn_busy[SOCKET_MAX+1] = {0};

static char *recv_stps[SOCKET_MAX];
static char *recv_ptrs[SOCKET_MAX];

const char *const textmessage_args[1000] = {
	[SOCKCMD_NEGOTIATION] 	= "%u",
	[SOCKCMD_ACK]		= "%03u %lu",
	[SOCKCMD_EINVAL]	= "%03u %lu",
	[SOCKCMD_VERSION]	= "%u %u %s",
	[SOCKCMD_INFO]		= "%s\003/ %s\003/ %x %x",
	[SOCKCMD_UNKNOWNCMD]	= "%03u %lu",
	[SOCKCMD_INVALIDCMDID]	= "%lu",
};

const char *const textmessage_descr[1000] = {
	[SOCKCMD_NEGOTIATION] 	= "Protocol version is %u.",
	[SOCKCMD_ACK]		= "Acknowledged command: id == %03u; num == %lu.",
	[SOCKCMD_EINVAL]	= "Rejected command: id == %03u; num == %lu. Invalid arguments: %s.",
	[SOCKCMD_LOGIN]		= "Enter your login and password, please.",
	[SOCKCMD_UNEXPECTEDEND]	= "Need to go, sorry. :)",
	[SOCKCMD_DIE]		= "Okay :(",
	[SOCKCMD_BYE]		= "Bye.",
	[SOCKCMD_VERSION]	= "clsync v%u.%u%s",
	[SOCKCMD_INFO]		= "config_block == \"%s\"; label == \"%s\"; flags == %x; flags_set == %x.",
	[SOCKCMD_UNKNOWNCMD]	= "Unknown command.",
	[SOCKCMD_INVALIDCMDID]	= "Invalid command id. Required: 0 <= cmd_id < 1000.",
};

int socket_check_bysock(int sock) {

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

static inline int socket_check(clsyncconn_t *clsyncconn_p) {
	return socket_check_bysock(clsyncconn_p->sock);
}

clsyncconn_t *socket_new(int clsyncconn_sock) {
	pthread_mutex_lock(&socket_mutex);

	if(clsyncconns_num >= SOCKET_MAX) {
		printf_e("Warning: socket_new(): Too many connection to control socket. Closing the new one.\n");
		close(clsyncconn_sock);
		errno = EUSERS;
		pthread_mutex_unlock(&socket_mutex);
		return NULL;
	}

	clsyncconn_t *clsyncconn_p = xmalloc(sizeof(*clsyncconn_p));
	
	printf_dd("Debug2: socket_new(): sock == %i; num == %i.\n", clsyncconn_sock, clsyncconns_num);

	clsyncconn_p->sock    = clsyncconn_sock;
	
	clsyncconn_p->prot    = SOCKET_DEFAULT_PROT;
	clsyncconn_p->subprot = SOCKET_DEFAULT_SUBPROT;

	clsyncconn_busy[clsyncconns_num]=1;
	// TODO: SECURITY: Possible DoS-attack on huge "SOCKET_MAX" value. Fix it.
	while(clsyncconn_busy[++clsyncconns_num]);

	pthread_mutex_unlock(&socket_mutex);
	return clsyncconn_p;
}

int socket_delete(clsyncconn_t *clsyncconn_p) {
	pthread_mutex_lock(&socket_mutex);

	int clsyncconn_sock = clsyncconn_p->sock;

	printf_dd("Debug2: socket_delete(): sock == %i; num == %i.\n", clsyncconn_sock, clsyncconn_p->num);

	recv_ptrs[clsyncconn_sock] = NULL;
	recv_stps[clsyncconn_sock] = NULL;

	close(clsyncconn_sock);

	clsyncconns_count--;

	if(clsyncconns_last == clsyncconn_p->num)
		clsyncconns_last = clsyncconn_p->num-1;

	clsyncconns_num = MIN(clsyncconn_p->num, clsyncconn_sock);

	clsyncconn_busy[clsyncconn_p->num]=0;

	free(clsyncconn_p);
	pthread_mutex_unlock(&socket_mutex);
	return 0;
}

clsyncconn_t *socket_accept(int sock) {
	int clsyncconn_sock = accept(sock, NULL, NULL);
	if(clsyncconn_sock == -1) {
		printf_e("Error: socket_accept(%i): Cannot accept(): %s (errno: %i)\n", sock, strerror(errno), errno);
		return NULL;
	}

	return socket_new(clsyncconn_sock);
}

int socket_send(clsyncconn_t *clsyncconn, sockcmd_id_t cmd_id, ...) {
	va_list ap;
	int ret;

	va_start(ap, cmd_id);
/*	static char bufs[SOCKET_MAX][SOCKET_BUFSIZ], prebufs0[SOCKET_MAX][SOCKET_BUFSIZ], prebufs1[SOCKET_MAX][SOCKET_BUFSIZ];
	char *prebuf0 = prebufs0[clsyncconn_sock], *prebuf1 = prebufs1[clsyncconn_sock], *sendbuf = bufs[clsyncconn_sock];
*/
	char prebuf0[SOCKET_BUFSIZ], prebuf1[SOCKET_BUFSIZ], sendbuf[SOCKET_BUFSIZ];

	ret = 0;

	switch(clsyncconn->prot) {
		case 0:
			switch(clsyncconn->subprot) {
				case SUBPROT0_TEXT: {
					va_list ap_copy;

					printf_ddd("Debug3: %p %p %p\n", prebuf0, textmessage_args[cmd_id], ap_copy);

					if(textmessage_args[cmd_id]) {
						va_copy(ap_copy, ap);
						vsprintf(prebuf0, textmessage_args[cmd_id], ap_copy);
					} else
						*prebuf0 = 0;

					va_copy(ap_copy, ap);
					vsprintf(prebuf1, textmessage_descr[cmd_id], ap);

					size_t sendlen = sprintf(sendbuf, "%03u %s :%s\n", cmd_id, prebuf0, prebuf1);

					send(clsyncconn->sock, sendbuf, sendlen, 0);
					break;
				}
/*				case SUBPROT0_BINARY:
					break;*/
				default:
					printf_e("Error: socket_send(): Unknown subprotocol with id %u.\n", clsyncconn->subprot);
					ret = EINVAL;
					goto l_socket_send_end;
			}
			break;
		default:
			printf_e("Error: socket_send(): Unknown protocol with id %u.\n", clsyncconn->prot);
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

int socket_recv(clsyncconn_t *clsyncconn, sockcmd_t *sockcmd_p) {
	static char bufs[SOCKET_MAX][SOCKET_BUFSIZ];
	char *buf, *ptr, *start, *end;
	int clsyncconn_sock;
	size_t filled_length, rest_length, recv_length, filled_length_new;

	clsyncconn_sock = clsyncconn->sock;

	buf = bufs[clsyncconn_sock];

	start =  recv_stps[clsyncconn_sock];
	start = (start==NULL ? buf : start);

	ptr   =  recv_ptrs[clsyncconn_sock];
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

		recv_length = recv(clsyncconn_sock, ptr, rest_length, 0);
		filled_length_new = filled_length + recv_length;

		if(recv_length <= 0)
			return errno;

		switch(clsyncconn->prot) {
			case 0: {
				// Checking if binary
				uint16_t cmd_id_binary = *(uint16_t *)buf;
				clsyncconn->subprot = (cmd_id_binary == SOCKCMD_NEGOTIATION) ? SUBPROT0_BINARY : SUBPROT0_TEXT;

				// Processing
				switch(clsyncconn->subprot) {
					case SUBPROT0_TEXT:
						if((end=strchr(ptr, '\n'))!=NULL) {
							if(sscanf(start, "%03u", (unsigned int *)&sockcmd_p->cmd_id) != 1)
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

	recv_stps[clsyncconn_sock] = start;
	recv_ptrs[clsyncconn_sock] = ptr;

	printf_ddd("Debug3: socket_recv(): sockcmd_p->cmd_id == %i; buf==%p; ptr==%p; end==%p, filled=%p, buf_end==%p\n",
		sockcmd_p->cmd_id, buf, ptr, end, &buf[filled_length_new], &buf[SOCKET_BUFSIZ]);

	sockcmd_p->cmd_num++;
	return 0;
}

static inline int socket_sendinvalid(clsyncconn_t *clsyncconn_p, sockcmd_t *sockcmd_p) {
	if(sockcmd_p->cmd_id >= 1000)
		return socket_send(clsyncconn_p, SOCKCMD_INVALIDCMDID, sockcmd_p->cmd_num);
	else
		return socket_send(clsyncconn_p, SOCKCMD_UNKNOWNCMD,   sockcmd_p->cmd_id, sockcmd_p->cmd_num);
}

int socket_procclsyncconn(socket_procconnproc_arg_t *arg) {
#define SL(a) a,sizeof(a)-1
//	clsyncconn_t clsyncconn = {0};
	char		_sockcmd_buf[SOCKET_BUFSIZ]={0};

	sockcmd_t		*sockcmd_p    = (sockcmd_t *)_sockcmd_buf;

	clsyncconn_t		*clsyncconn_p = arg->clsyncconn_p;
	clsyncconn_procfunct_t   procfunct    = arg->procfunct;
	sockprocflags_t		 flags        = arg->flags;

	sockcmd_p->cmd_num = -1;

	enum auth_flags {
		AUTHFLAG_ENTERED_LOGIN = 0x01,
	};
	typedef enum auth_flags auth_flags_t;
	auth_flags_t	 auth_flags = 0;

	printf_ddd("Debug3: socket_procclsyncconn(): Started new thread for new connection.\n");

	arg->state = (arg->authtype == SOCKAUTH_NULL) ? CLSTATE_MAIN : CLSTATE_AUTH;
	socket_send(clsyncconn_p, SOCKCMD_NEGOTIATION);

	while(*arg->running && (arg->state==CLSTATE_AUTH || arg->state==CLSTATE_MAIN)) {
		printf_ddd("Debug3: socket_procclsyncconn(): Iteration.\n");

		// Receiving message
		int ret;
		if((ret = socket_recv(clsyncconn_p, sockcmd_p))) {
			printf_e("Error: socket_procclsyncconn(): Got error while receiving a message from clsyncconn #%u: %s (errno: %u)\n", 
				arg->clsyncconn_p->num, strerror(ret), ret);
			break;
		}

		if(flags&SOCKPROCFLAG_OVERRIDECOMMON)
			goto l_socket_procclsyncconn_sw_default;

		// Processing the message
		switch(sockcmd_p->cmd_id) {
			case SOCKCMD_NEGOTIATION: {
				struct sockcmd_negotiation *data = (struct sockcmd_negotiation *)sockcmd_p->data;
				switch(data->prot) {
					case 0:
						switch(data->subprot) {
							case SUBPROT0_TEXT:
							case SUBPROT0_BINARY:
								clsyncconn_p->subprot = data->subprot;
								socket_send(clsyncconn_p, SOCKCMD_ACK,    sockcmd_p->cmd_id, sockcmd_p->cmd_num);
								break;
							default:
								socket_send(clsyncconn_p, SOCKCMD_EINVAL, sockcmd_p->cmd_id, sockcmd_p->cmd_num, "Incorrect subprotocol id");
						}
						break;
					default:
						socket_send(clsyncconn_p, SOCKCMD_EINVAL, sockcmd_p->cmd_id, sockcmd_p->cmd_num, "Incorrect protocol id");
				}
				break;
			}
			case SOCKCMD_VERSION: {
				socket_send(clsyncconn_p, SOCKCMD_VERSION, VERSION_MAJ, VERSION_MIN, REVISION);
				break;
			}
			case SOCKCMD_QUIT: {
				socket_send(clsyncconn_p, SOCKCMD_BYE);
				arg->state = CLSTATE_DYING;
				break;
			}
			default:
l_socket_procclsyncconn_sw_default:
				if(!procfunct(arg, sockcmd_p))
					socket_sendinvalid(clsyncconn_p, sockcmd_p);
				break;
		}

		// Check if the socket is still alive
		if(socket_check(clsyncconn_p)) {
			printf_d("Debug: clsyncconn socket error: %s\n", strerror(errno));
			break;
		}

		// Sending prompt
		switch(arg->state) {
			case CLSTATE_AUTH:
				if(!(auth_flags&AUTHFLAG_ENTERED_LOGIN))
					socket_send(clsyncconn_p, SOCKCMD_LOGIN);
				break;
			default:
				break;
		}
	}

	printf_ddd("Debug3: socket_procclsyncconn(): Ending a connection thread.\n");

	socket_delete(clsyncconn_p);

	arg->state = CLSTATE_DIED;

	return 0;
#undef SL
}

int socket_init() {
	return 0;
}

int socket_deinit() {
	return 0;
}


