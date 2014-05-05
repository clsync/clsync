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
#include <sys/stat.h>	// mkdir()
#include <sys/types.h>	// mkdir()
#include <fcntl.h>	// mkdirat()
#include <glib.h>	// g_hash_table_foreach()


#include "indexes.h"
#include "ctx.h"
#include "error.h"
#include "sync.h"
#include "control.h"
#include "socket.h"

static pthread_t pthread_control;


static inline int control_error(clsyncsock_t *clsyncsock_p, const char *const funct, const char *const args) {
	return socket_send(clsyncsock_p, SOCKCMD_REPLY_ECUSTOM, funct, args, errno, strerror(errno));
}

enum dump_dirfd_obj {
	DUMP_DIRFD_ROOT = 0,
	DUMP_DIRFD_QUEUE,
	DUMP_DIRFD_THREAD,

	DUMP_DIRFD_MAX
};

enum dump_ltype {
	DUMP_LTYPE_INCLUDE,
	DUMP_LTYPE_EXCLUDE,
	DUMP_LTYPE_EVINFO,
};

struct control_dump_arg {
	clsyncsock_t 	*clsyncsock_p;
	ctx_t 		*ctx_p;
	int 		 dirfd[DUMP_DIRFD_MAX];
	int		 fd_out;
	int		 data;
};

void control_dump_liststep(gpointer fpath_gp, gpointer evinfo_gp, gpointer arg_gp) {
	char *fpath			=         (char *)fpath_gp;
	eventinfo_t *evinfo		=  (eventinfo_t *)evinfo_gp;
	struct control_dump_arg *arg 	= 		  arg_gp;
	char act, num;

	switch (arg->data) {
		case DUMP_LTYPE_INCLUDE:
			act = '+';
			num = '1';
			break;
		case DUMP_LTYPE_EXCLUDE:
			act = '-';
			num = '1';
			break;
		case DUMP_LTYPE_EVINFO:
			act = '+';
			num = 	 evinfo->flags&EVIF_RECURSIVELY        ? '*' : 
				(evinfo->flags&EVIF_CONTENTRECURSIVELY ? '/' : '1');
			break;
		default:
			act = '?';
			num = '?';
	}

	dprintf(arg->fd_out, "%c%c %s\n", act, num, fpath);

	return;
}

int control_dump_thread(threadinfo_t *threadinfo_p, void *_arg) {
	struct control_dump_arg *arg = _arg;
	char buf[BUFSIZ];

	snprintf(buf, BUFSIZ, "%u-%u-%lx", threadinfo_p->iteration, threadinfo_p->thread_num, (long)threadinfo_p->pthread);

	arg->fd_out = openat(arg->dirfd[DUMP_DIRFD_THREAD], buf, O_WRONLY);
	if (arg->fd_out == -1)
		return errno;

	{
		char **argv;

		dprintf(arg->fd_out, 
			"thread:\n\titeration == %u;\n\tnum == %u;\n\tpthread == %lx;\n\tstarttime == %lu\n\texpiretime == %lu\n\tchild_pid == %u\n\ttry_n == %u\nCommand:",
				threadinfo_p->iteration,
				threadinfo_p->thread_num,
				(long)threadinfo_p->pthread,
				threadinfo_p->starttime,
				threadinfo_p->expiretime,
				threadinfo_p->child_pid,
				threadinfo_p->try_n
			);

		argv = threadinfo_p->argv;
		while (argv != NULL)
			dprintf(arg->fd_out, " \"%s\"", *(argv++));

		dprintf(arg->fd_out, "\n");
	}

	arg->data = DUMP_LTYPE_EVINFO;
	g_hash_table_foreach(threadinfo_p->fpath2ei_ht, control_dump_liststep, arg);

	close(arg->fd_out);

	return 0;
}

int control_mkdir_open(clsyncsock_t *clsyncsock_p, const char *const dir_path) {
	int dirfd;

	if (mkdir(dir_path, DUMP_DIRMODE)) {
		control_error(clsyncsock_p, "mkdir", dir_path);
		return -1;
	}

	dirfd = open(dir_path, O_RDWR);
	if (dirfd == -1) {
		control_error(clsyncsock_p, "open",  dir_path);
		return -1;
	}

	return dirfd;
}

int control_dump(ctx_t *ctx_p, clsyncsock_t *clsyncsock_p, sockcmd_t *sockcmd_p) {
	indexes_t	*indexes_p	= ctx_p->indexes_p;
	sockcmd_dat_dump_t *dat		= sockcmd_p->data;
	int rootfd, fd_out;
	struct control_dump_arg arg;
	enum dump_dirfd_obj dirfd_obj;

	static const char *const subdirs[] = {
		[DUMP_DIRFD_QUEUE]	= "queue",
		[DUMP_DIRFD_THREAD]	= "threads"
	};

	rootfd = control_mkdir_open(clsyncsock_p, dat->dir_path);
	if (rootfd == -1)
		goto l_control_dump_end;

	fd_out = openat(rootfd, "instance", O_WRONLY);
	if (fd_out == -1)
		goto l_control_dump_end;

	dprintf(fd_out, "status == %s\n", getenv("CLSYNC_STATUS"));

	close(fd_out);

	arg.dirfd[DUMP_DIRFD_ROOT] = rootfd;

	dirfd_obj = DUMP_DIRFD_ROOT+1;
	while (dirfd_obj < DUMP_DIRFD_MAX) {
		const char *const subdir = subdirs[dirfd_obj];

		arg.dirfd[dirfd_obj] = control_mkdir_open(clsyncsock_p, subdir);
		if (arg.dirfd[dirfd_obj] == -1)
			goto l_control_dump_end;

		dirfd_obj++;
	}

	arg.clsyncsock_p = clsyncsock_p;
	arg.ctx_p	 = ctx_p;

	int queue_id = 0;
	while (queue_id < QUEUE_MAX) {
		char buf[BUFSIZ];
		snprintf(buf, BUFSIZ, "%u", queue_id);

		arg.fd_out = openat(arg.dirfd[DUMP_DIRFD_QUEUE], buf, O_WRONLY);

		arg.data = DUMP_LTYPE_EVINFO;
		g_hash_table_foreach(indexes_p->fpath2ei_coll_ht[queue_id],  control_dump_liststep, &arg);
		arg.data = DUMP_LTYPE_EXCLUDE;
		g_hash_table_foreach(indexes_p->exc_fpath_coll_ht[queue_id], control_dump_liststep, &arg);

		close(arg.fd_out);
		queue_id++;
	}

	threads_foreach(control_dump_thread, STATE_RUNNING, &arg);

l_control_dump_end:
	dirfd_obj = DUMP_DIRFD_ROOT;
	while (dirfd_obj < DUMP_DIRFD_MAX) {
		if (arg.dirfd[dirfd_obj] != -1)
			close(arg.dirfd[dirfd_obj]);
		dirfd_obj++;
	}

	return errno ? errno : socket_send(clsyncsock_p, SOCKCMD_REPLY_DUMP);
}


int control_procclsyncsock(socket_sockthreaddata_t *arg, sockcmd_t *sockcmd_p) {
	clsyncsock_t	*clsyncsock_p =          arg->clsyncsock_p;
	ctx_t		*ctx_p        = (ctx_t *)arg->arg;

	switch(sockcmd_p->cmd_id) {
		case SOCKCMD_REQUEST_DUMP:
			control_dump(ctx_p, clsyncsock_p, sockcmd_p);
			break;
		case SOCKCMD_REQUEST_INFO:
			socket_send(clsyncsock_p, SOCKCMD_REPLY_INFO, ctx_p->config_block, ctx_p->label, ctx_p->flags, ctx_p->flags_set);
			break;
		case SOCKCMD_REQUEST_DIE:
			sync_term(SIGTERM);
			break;
		default:
			return EINVAL;
	}

	return 0;
}

static inline void closecontrol(ctx_t *ctx_p) {
	if(ctx_p->socket) {
		close(ctx_p->socket);
		ctx_p->socket = 0;
	}
}

int control_loop(ctx_t *ctx_p) {

	// Starting

	debug(1, "started (ctx_p->socket == %u)", ctx_p->socket);
	int s;

	while((s=ctx_p->socket)) {

		// Check if the socket is still alive
		if(socket_check_bysock(s)) {
			error("Control socket closed [case 0]");
			closecontrol(ctx_p);
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
			closecontrol(ctx_p);
			continue;
		}

		if(!FD_ISSET(s, &rfds)) {
			error("Got event, but not on the control socket. Closing the socket (cannot use \"select()\").");
			closecontrol(ctx_p);
			continue;
		}

		// Processing the events: accepting new clsyncsock

		clsyncsock_t *clsyncsock_p = socket_accept(s);
		if(clsyncsock_p == NULL) {

			if(errno == EUSERS)	// Too many connections. Just ignoring the new one.
				continue;

			// Got unknown error. Closing control socket just in case.
			error("Cannot socket_accept()");
			closecontrol(ctx_p);
			continue;
		}

		debug(2, "Starting new thread for new connection.");
		socket_sockthreaddata_t *threaddata_p = socket_thread_attach(clsyncsock_p);

		if (threaddata_p == NULL) {
			error("Cannot create a thread for connection");
			closecontrol(ctx_p);
			continue;
		}

		threaddata_p->procfunct		=  control_procclsyncsock;
		threaddata_p->clsyncsock_p	=  clsyncsock_p;
		threaddata_p->arg		=  ctx_p;
		threaddata_p->running		= &ctx_p->socket;
		threaddata_p->authtype		=  ctx_p->flags[SOCKETAUTH];
		threaddata_p->flags		=  0;

		if (socket_thread_start(threaddata_p)) {
			error("Cannot start a thread for connection");
			closecontrol(ctx_p);
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

int control_run(ctx_t *ctx_p) {
	if(ctx_p->socketpath != NULL) {
		int ret =  0;
		int s   = -1;

		// initializing clsync-socket subsystem
		if ((ret = socket_init()))
			error("Cannot init clsync-sockets subsystem.");


		if (!ret) {
			clsyncsock_t *clsyncsock = socket_listen_unix(ctx_p->socketpath);
			if (clsyncsock == NULL) {
				ret = errno;
			} else {
				s = clsyncsock->sock;
				clsyncsock->sock = -1;
				socket_cleanup(clsyncsock);
			}
		}

		// fixing privileges
		if (!ret) {
			if(ctx_p->flags[SOCKETMOD])
				if(chmod(ctx_p->socketpath, ctx_p->socketmod)) {
					error("Error, Cannot chmod(\"%s\", %o)", 
						ctx_p->socketpath, ctx_p->socketmod);
					ret = errno;
				}
			if(ctx_p->flags[SOCKETOWN])
				if(chown(ctx_p->socketpath, ctx_p->socketuid, ctx_p->socketgid)) {
					error("Error, Cannot chown(\"%s\", %u, %u)", 
						ctx_p->socketpath, ctx_p->socketuid, ctx_p->socketgid);
					ret = errno;
				}
		}

		// finish
		if (ret) {
			close(s);
			return ret;
		}

		ctx_p->socket = s;

		debug(2, "ctx_p->socket = %u", ctx_p->socket);

		ret = pthread_create(&pthread_control, NULL, (void *(*)(void *))control_loop, ctx_p);
	}
	
	return 0;
}

int control_cleanup(ctx_t *ctx_p) {
	if(ctx_p->socketpath != NULL) {
		unlink(ctx_p->socketpath);
		closecontrol(ctx_p);
		// TODO: kill pthread_control and join
//		pthread_join(pthread_control, NULL);
		socket_deinit();
	}
	return 0;
}

