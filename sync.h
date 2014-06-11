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

extern int sync_run(struct ctx *ctx);
extern int sync_dump(struct ctx *ctx, const char *const dest_dir);
extern int sync_term(int exitcode);
extern int threads_foreach(int (*funct)(threadinfo_t *, void *), state_t state, void *arg);
extern threadsinfo_t *thread_info();
extern time_t thread_nextexpiretime();
extern int sync_prequeue_loadmark
	(
		int fsmon_d,

		struct ctx     *ctx_p,
		struct indexes *indexes_p,

		const char *path_full,
		const char *path_rel,

		eventobjtype_t objtype_old,
		eventobjtype_t objtype_new,

		uint32_t event_mask,
		int      event_wd,
		mode_t st_mode,
		off_t  st_size,

		char  **path_buf_p,
		size_t *path_buf_len_p,

		struct eventinfo *evinfo
	);
extern int sync_prequeue_unload(struct ctx *ctx_p, struct indexes *indexes_p);
extern int *state_p;
extern const char *sync_parameter_get(const char *variable_name, void *_dosync_arg_p);

