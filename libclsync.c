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
#if 0
struct clsync {
	int	s;
};
typedef struct clsync clsync_t;

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

int clsyncsock_send(clsync_t *clsync, sockcmd_id_t cmd_id, ...) {
	va_list ap;
	int ret;

	va_start(ap, cmd_id);
	char prebuf0[SOCKET_BUFSIZ], prebuf1[SOCKET_BUFSIZ], sendbuf[SOCKET_BUFSIZ];

	ret = 0;

	switch(clsync->prot) {
		case 0:
			switch(clsync->subprot) {
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

					send(clsync->sock, sendbuf, sendlen, 0);
					break;
				}
/*				case SUBPROT0_BINARY:
					break;*/
				default:
					printf_e("Error: socket_send(): Unknown subprotocol with id %u.\n", clsync->subprot);
					ret = EINVAL;
					goto l_socket_send_end;
			}
			break;
		default:
			printf_e("Error: socket_send(): Unknown protocol with id %u.\n", clsync->prot);
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

static char *recv_stps[SOCKET_MAX_LIBCLSYNC];
static char *recv_ptrs[SOCKET_MAX_LIBCLSYNC];
int clsyncsock_recv(clsync_t *clsync, sockcmd_t *sockcmd) {
	static char bufs[SOCKET_MAX_LIBCLSYNC][SOCKET_BUFSIZ];
	char *buf, *ptr, *start, *end;
	int clsync_sock;
	size_t filled_length, rest_length, recv_length, filled_length_new;

	clsync_sock = clsync->sock;

	buf = bufs[clsync_sock];

	start =  recv_stps[clsync_sock];
	start = (start==NULL ? buf : start);

	ptr   =  recv_ptrs[clsync_sock];
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

		recv_length = recv(clsync_sock, ptr, rest_length, 0);
		filled_length_new = filled_length + recv_length;

		if(recv_length <= 0)
			return errno;

		switch(clsync->prot) {
			case 0: {
				// Checking if binary
				uint16_t cmd_id_binary = *(uint16_t *)buf;
				clsync->subprot = (cmd_id_binary == SOCKCMD_NEGOTIATION) ? SUBPROT0_BINARY : SUBPROT0_TEXT;

				// Processing
				switch(clsync->subprot) {
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

	recv_stps[clsync_sock] = start;
	recv_ptrs[clsync_sock] = ptr;

	printf_ddd("Debug3: socket_recv(): buf==%p; ptr==%p; end==%p, filled=%p, buf_end==%p\n", buf, ptr, end, &buf[filled_length_new], &buf[SOCKET_BUFSIZ]);

	sockcmd->cmd_num++;
	return 0;
}

clsync_t *clsyncsock_connect_unix(const char const *socket_path) {

	clsync_t clsync = xmalloc

	return 
}

#endif


