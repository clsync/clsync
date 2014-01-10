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

#define SOCKET_DEFAULT_PROT	0
#define SOCKET_DEFAULT_SUBPROT	SUBPROT0_TEXT

// buffer size
#define SOCKET_BUFSIZ			(1<<12)

struct clsyncconn {
	int sock;
	int num;
	uint16_t prot;
	uint16_t subprot;
};
typedef struct clsyncconn clsyncconn_t;

enum subprot0 {
	SUBPROT0_TEXT,
	SUBPROT0_BINARY,
};
typedef enum subprot0 subprot0_t;

struct sockcmd_negotiation {
	uint16_t prot;
	uint16_t subprot;
};

enum clsyncconn_state {
	CLSTATE_NONE	= 0,
	CLSTATE_AUTH,
	CLSTATE_MAIN,
	CLSTATE_DYING,
	CLSTATE_DIED,
};
typedef enum clsyncconn_state clsyncconn_state_t;

enum sockcmd_id {
	SOCKCMD_NEGOTIATION	=  00,
	SOCKCMD_ACK		=  50,
	SOCKCMD_UNKNOWNCMD	=  60,
	SOCKCMD_INVALIDCMDID	=  61,
	SOCKCMD_EINVAL		=  62,
	SOCKCMD_LOGIN		= 100,
	SOCKCMD_VERSION		= 201,
	SOCKCMD_INFO		= 202,
	SOCKCMD_DIE		= 210,
	SOCKCMD_UNEXPECTEDEND	= 300,
	SOCKCMD_QUIT		= 301,
	SOCKCMD_BYE		= 350,
};
typedef enum sockcmd_id sockcmd_id_t;

struct sockcmd {
	uint64_t	cmd_num;
	uint16_t	cmd_id;
	size_t		data_len;
	char		data[1];
};
typedef struct sockcmd sockcmd_t;

enum sockprocflags {
	SOCKPROCFLAG_NONE	= 0,
	SOCKPROCFLAG_OVERRIDECOMMON,
};
typedef enum sockprocflags sockprocflags_t;

enum sockauth_id {
	SOCKAUTH_UNSET	= 0,
	SOCKAUTH_NULL,
	SOCKAUTH_PAM,
};
typedef enum sockauth_id sockauth_id_t;

struct socket_procconnproc_arg;
typedef int (*clsyncconn_procfunct_t)(struct socket_procconnproc_arg *, sockcmd_t *);
struct socket_procconnproc_arg {
	clsyncconn_procfunct_t	 procfunct;
	clsyncconn_t		*clsyncconn_p;
	void			*arg;
	clsyncconn_state_t	 state;
	sockauth_id_t		 authtype;
	int			*running;		// Pointer to interger with non-zero value to continue running
	sockprocflags_t		 flags;
};
typedef struct socket_procconnproc_arg socket_procconnproc_arg_t;

extern int socket_send(clsyncconn_t *clsyncconn, sockcmd_id_t cmd_id, ...);
extern int socket_recv(clsyncconn_t *clsyncconn, sockcmd_t *sockcmd);
extern int socket_check_bysock(int sock);
extern int socket_close(clsyncconn_t *clsyncconn);
extern clsyncconn_t *socket_accept(int sock);
extern int socket_init();
extern int socket_deinit();
extern int socket_procclsyncconn(socket_procconnproc_arg_t *arg);

extern int clsyncconns_num;
extern int clsyncconns_count;
extern int clsyncconns_last;

extern const char *const textmessage_args[];
extern const char *const textmessage_descr[];

