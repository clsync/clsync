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

extern int ncpus;
extern pid_t parent_pid;

extern int main_rehash(ctx_t *ctx_p);
extern int main_status_update(ctx_t *ctx_p);
extern int ctx_set(ctx_t *ctx_p, const char *const parameter_name, const char *const parameter_value);
extern int config_block_parse(ctx_t *ctx_p, const char *const config_block_name);
extern int rules_count(ctx_t *ctx_p);
extern char *parameter_expand(
		ctx_t *ctx_p,
		char *arg,
		int exceptionflags,
		int *macros_count_p,
		int *expand_count_p,
		const char *(*parameter_get)(const char *variable_name, void *arg),
		void *parameter_get_arg
	);
extern pid_t fork_helper();
extern int parent_isalive();
extern int sethandler_sigchld(void (*handler)());
extern pid_t waitpid_timed(pid_t child_pid, int *status_p,  __time_t sec, __syscall_slong_t nsec);

