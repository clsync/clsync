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

struct clsyncthread {
	clsyncconn_t *clsyncconn_p;
	void *arg;
	void *funct_arg_free;
};
typedef struct clsyncthread clsyncthread_t;

enum subprot0 {
	SUBPROT0_TEXT,
	SUBPROT0_BINARY,
};
typedef enum subprot0 subprot0_t;

enum clsyncconn_state {
	CLSTATE_NONE	= 0,
	CLSTATE_AUTH,
	CLSTATE_MAIN,
	CLSTATE_DYING,
	CLSTATE_DIED,
};
typedef enum clsyncconn_state clsyncconn_state_t;

enum sockcmd_id {
	SOCKCMD_REQUEST_NEGOTIATION	= 000,
	SOCKCMD_REPLY_NEGOTIATION	= 001,
	SOCKCMD_REPLY_ACK		= 150,
	SOCKCMD_REPLY_UNKNOWNCMD	= 160,
	SOCKCMD_REPLY_INVALIDCMDID	= 161,
	SOCKCMD_REPLY_EINVAL		= 162,
	SOCKCMD_REQUEST_LOGIN		= 200,
	SOCKCMD_REQUEST_VERSION		= 201,
	SOCKCMD_REQUEST_INFO		= 202,
	SOCKCMD_REQUEST_DIE		= 210,
	SOCKCMD_REQUEST_QUIT		= 250,
	SOCKCMD_REPLY_LOGIN		= 300,
	SOCKCMD_REPLY_VERSION		= 301,
	SOCKCMD_REPLY_INFO		= 302,
	SOCKCMD_REPLY_DIE		= 310,
	SOCKCMD_REPLY_UNEXPECTEDEND	= 300,
	SOCKCMD_REPLY_QUIT		= 301,
	SOCKCMD_REPLY_BYE		= 350,
	SOCKCMD_MAXID
};
typedef enum sockcmd_id sockcmd_id_t;

struct sockcmd_dat_negotiation {
	uint16_t prot;
	uint16_t subprot;
};
typedef struct sockcmd_dat_negotiation sockcmd_dat_negotiation_t;

struct sockcmd_dat_ack {
	uint64_t	 cmd_num;
	uint16_t	 cmd_id;
};
typedef struct sockcmd_dat_ack sockcmd_dat_ack_t;
#define sockcmd_dat_einval       sockcmd_dat_ack
#define sockcmd_dat_einval_t     sockcmd_dat_ack_t
#define sockcmd_dat_unknowncmd   sockcmd_dat_ack
#define sockcmd_dat_unknowncmd_t sockcmd_dat_ack_t

struct sockcmd_dat_invalidcmd {
	uint64_t	 cmd_num;
};
typedef struct sockcmd_dat_invalidcmd sockcmd_dat_invalidcmd_t;

struct sockcmd_dat_version {
	int		major;
	int		minor;
	char		revision[1<<8];
};
typedef struct sockcmd_dat_version sockcmd_dat_version_t;

struct sockcmd_dat_info {
	char		config_block[1<<8];
	char		label[1<<8];
	char		flags[OPTION_FLAGS];
	char		flags_set[OPTION_FLAGS];
};
typedef struct sockcmd_dat_info sockcmd_dat_info_t;

struct sockcmd {
	uint64_t	 cmd_num;
	uint16_t	 cmd_id;
	size_t		 data_len;
	char		*data;
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

struct socket_connthreaddata;
typedef int (*clsyncconn_procfunct_t)(struct socket_connthreaddata *, sockcmd_t *);
typedef int (*freefunct_t)(void *);
struct socket_connthreaddata {
	int			 id;
	clsyncconn_procfunct_t	 procfunct;
	freefunct_t		 freefunct_arg;
	clsyncconn_t		*clsyncconn_p;
	void			*arg;
	clsyncconn_state_t	 state;
	sockauth_id_t		 authtype;
	int			*running;		// Pointer to interger with non-zero value to continue running
	sockprocflags_t		 flags;
	pthread_t		 thread;
};
typedef struct socket_connthreaddata socket_connthreaddata_t;

extern int socket_send(clsyncconn_t *clsyncconn, sockcmd_id_t cmd_id, ...);
extern int socket_sendinvalid(clsyncconn_t *clsyncconn_p, sockcmd_t *sockcmd_p);
extern int socket_recv(clsyncconn_t *clsyncconn, sockcmd_t *sockcmd);
extern int socket_check_bysock(int sock);
extern clsyncconn_t *socket_accept(int sock);
extern int socket_cleanup(clsyncconn_t *clsyncconn_p);
extern int socket_init();
extern int socket_deinit();
extern int socket_procclsyncconn(socket_connthreaddata_t *arg);
extern clsyncconn_t *socket_connect_unix(const char *const socket_path);
extern int socket_listen_unix(const char *const socket_path);

extern socket_connthreaddata_t *socket_thread_attach(clsyncconn_t *clsyncconn_p);
extern int socket_thread_start(socket_connthreaddata_t *threaddata_p);

extern int clsyncconns_num;
extern int clsyncconns_count;
extern int clsyncconns_last;

extern const char *const textmessage_args[];
extern const char *const textmessage_descr[];

