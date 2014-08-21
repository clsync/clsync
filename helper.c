/*
    clsync - file tree sync utility based on inotify/kqueue/bsm

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

#include <sys/types.h>
#include <unistd.h>

/* select() */
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "common.h"
#include "helper.h"
#include "privileged.h"
#include "cgroup.h"
#include "error.h"
#include "malloc.h"
#include "stringex.h"

static pid_t  parent_pid = 0;
static pid_t  helper_pid = 0;
static int    use_args_check = 0;
static struct pa_options opts = {{{{0}}}};
static uid_t  exec_uid = 65535;
static gid_t  exec_gid = 65535;
static int    tohelperto;
static int    tohelperfrom;
static int    fromhelperto;
static int    fromhelperfrom;


extern int helper_submitcmd(void *ret_p, int cmdid, size_t size, void *buf);

enum helper_call_id {
	HC_FORK_EXECVP,
	HC_CLSYNC_CGROUP_DEINIT,
	HC_KILL_CHILD,
	HC_DIE,
};

static inline pid_t helperdo_fork_execvp(ctx_t *ctx_p, const char *file, char *const *argv) {
	return do_fork_execvp(ctx_p, use_args_check, &opts, file, argv, exec_uid, exec_gid);
}

pid_t helper_fork_execvp(
		const char *file,
		char *const argv[]
	)
{
	char   buf[BUFSIZ+1], *ptr, *ptr_num, **argv_p, *end;
	size_t size;
	int num;
	pid_t pid;

	ptr = buf;
	end = &buf[BUFSIZ];

	num = 0;
	argv_p = (char **)argv;
	ptr = str_addtobuf(ptr, end, strlen(file), file);
	ptr_num = ptr;
	ptr += sizeof(size_t);
	if (argv_p != NULL) {
		while (*argv_p != NULL) {
			ptr = str_addtobuf(ptr, end, strlen(*argv_p), *argv_p);
			argv_p++;
			num++;
		}
	}
	*(size_t *)ptr_num = num;

	size = ptr - buf;

	if (helper_submitcmd(&pid, HC_FORK_EXECVP, size, buf))
		return -1;

	return pid;
}

static inline int helperdo_clsync_cgroup_deinit(ctx_t *ctx_p)
{
	return clsync_cgroup_deinit(ctx_p);
}

int helper_clsync_cgroup_deinit(ctx_t *ctx_p)
{
	return helper_submitcmd(NULL, HC_CLSYNC_CGROUP_DEINIT, 0, NULL);
}

static inline int helperdo_kill_child(ctx_t *ctx_p, pid_t child_pid, int signal) {
	return __privileged_kill_child_itself(child_pid, signal);
}

struct helper_kill_child_args {
	pid_t pid;
	int signal;
};

int helper_kill_child(pid_t pid, int signal)
{
	struct helper_kill_child_args args;

	args.pid    = pid;
	args.signal = signal;

	return helper_submitcmd(NULL, HC_KILL_CHILD, sizeof(args), &args);
}

struct {
	size_t   size;
	uint16_t cmdid;
	char data[BUFSIZ];
} s;

struct {
	int   rc;
	void *ret;
} r;

static inline int parent_isalive() {
	debug(12, "parent_pid == %u", parent_pid);

	if (kill(parent_pid, 0))
		return 0;

	return 1;
}

static inline int helper_isalive() {
	int rc;
	debug(12, "helper_pid == %u", helper_pid);

	if ((rc=waitpid(helper_pid, NULL, WNOHANG))>=0)
		return 1;

	debug(1, "waitpid(%u, NULL, WNOHANG) => %i", helper_pid, rc);

	return 0;
}

int helper_submitcmd(void *ret_p, int cmdid, size_t size, void *buf) {
	s.cmdid = cmdid;
	if (buf != NULL)
		memcpy(s.data, buf, size);
	s.size  = size + sizeof(s.size) + sizeof(s.cmdid);

	critical_on(!helper_isalive());

	critical_on(write(tohelperfrom,  &s, s.size)      != s.size);

	sleep(1);
	critical_on(!helper_isalive());

	critical_on(read(fromhelperto, &r, sizeof(r)) != sizeof(r));

	critical_on(!helper_isalive());

	switch (cmdid) {
		case HC_FORK_EXECVP:
			*(pid_t *)ret_p = (pid_t)(long)r.ret;
			return 0;
		case HC_KILL_CHILD:
			return r.rc;
		case HC_CLSYNC_CGROUP_DEINIT:
			return r.rc;
		case HC_DIE:
			return 0;
	}

	critical("Invalid command id: %u", cmdid);
	return 0;	// Anti-warning
}

int helper_handler(ctx_t *ctx_p) {
/*
#ifdef CAPABILITIES_SUPPORT
	if (ctx_p->flags[CAP_PRESERVE])
		critical_on(cap_enable(ctx_p->caps));
#endif
*/
	while (1) {
		size_t r_size;
		fd_set rfds;
		struct timeval tv;
		int rc;

		// Anti-zombie
		do {

			if (!parent_isalive())
				exit(-1);

			FD_ZERO(&rfds);
			FD_SET(tohelperto, &rfds);
			tv.tv_sec  = 1;
			tv.tv_usec = 0;
			debug(30, "select()");
			rc = select(tohelperto+1, &rfds, NULL, NULL, &tv);

			if (rc == -1)
				exit(-1);

		} while (!rc);

		// Reading command
		size_t s_size = read(tohelperto, &s, BUFSIZ);
		critical_on(s_size != s.size);

		switch (s.cmdid) {
			case HC_FORK_EXECVP: {
				char *file, **argv;
				char *ptr;
				size_t size, num;
				int i;

				ptr = s.data;

				size = *(size_t *)ptr;
				ptr += sizeof(size);
				debug(15, "HC_FORK_EXECVP: file: size == %u", size);
				file = xmalloc(size+1);
				memcpy(file, ptr, size);
				file[size] = 0;
				ptr += size;

				i = 0;
				num = *(size_t *)ptr;
				ptr += sizeof(num);
				argv = xmalloc((num+1) * sizeof(*argv));
				while (i < num) {
					size = *(size_t *)ptr;
					ptr += sizeof(size);
					argv[i] = xmalloc(size);
					memcpy(argv[i], ptr, size);
					ptr += size;
					i++;
				}
				argv[i] = NULL;

				r.ret = (void *)(long)helperdo_fork_execvp(ctx_p, file, (char *const *)argv);
				break;
			}
			case HC_KILL_CHILD: {
				struct helper_kill_child_args *args_p = (void *)s.data;
				r.rc  = helperdo_kill_child(ctx_p, args_p->pid, args_p->signal);
				break;
			}
			case HC_CLSYNC_CGROUP_DEINIT: {
				r.rc  = helperdo_clsync_cgroup_deinit(NULL);
				break;
			}
			case HC_DIE: {
				exit(0);
			}
			default: {
				errno = ENOENT;
				critical("Unknown command id: %i", s.cmdid);
			}
		}

		r_size = write(fromhelperfrom, &r, sizeof(r));
		critical_on(r_size != sizeof(r));
	}

	exit(0);
	return -1;
}

int helper_init(ctx_t *ctx_p)
{
	int fds_to[2], fds_from[2];

	use_args_check = ctx_p->flags[CHECK_EXECVP_ARGS];
	pa_setup(&opts, ctx_p, &exec_uid, &exec_gid);

	critical_on(socketpair(AF_UNIX, SOCK_STREAM, 0, fds_to));

	tohelperto   = fds_to[0];
	tohelperfrom = fds_to[1];

	critical_on(socketpair(AF_UNIX, SOCK_STREAM, 0, fds_from));

	fromhelperto   = fds_from[0];
	fromhelperfrom = fds_from[1];

	helper_pid = fork();

	switch (helper_pid) {
		case -1:
			critical("Cannot fork");
			break;
		case 0:
			parent_pid = ctx_p->pid;
			critical_on(helper_handler(ctx_p));
			break;
	}

	return 0;
}

int helper_deinit()
{
	helper_submitcmd(NULL, HC_DIE, 0, NULL);

	close(tohelperto);
	close(fromhelperto);
	close(tohelperfrom);
	close(fromhelperfrom);
	return 0;
}

