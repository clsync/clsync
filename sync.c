/*
    clsync - file tree sync utility based on fanotify and inotify
    
    Copyright (C) 2013  Dmitry Yu Okunev <xai@mephi.ru> 0x8E30679C
    
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
#include "output.h"
#include "fileutils.h"

int sync_exec(const char *actfpath, ...) {
	va_list list;
	va_start(list, actfpath);

	const char *argv[MAXARGUMENTS] = {NULL};
	argv[0] = actfpath;
	int i = 1;
	do {
		if(i >= MAXARGUMENTS) {
			printf_e("Error: Too many arguments (%i >= %i).\n", i, MAXARGUMENTS);
			return ENOMEM;
		}
		argv[i] = va_arg(list, const char *const);

		printf_dd("Debug2: argv[%i] = %s\n", i, argv[i]);
	} while(argv[i++] != NULL);

	pid_t pid;
	int status;

	pid = fork();
	switch(pid) {
		case -1: 
			printf_e("Error: Cannot fork(): %s (errno: %i).\n", strerror(errno), errno);
			return errno;
		case  0:
			execvp(actfpath, (char *const *)argv);
			return errno;
	}

	if(waitpid(pid, &status, 0) != pid) {
		printf_e("Error: Cannot waitid(): %s (errno: %i).\n", strerror(errno), errno);
		return errno;
	}

	int exitcode = WEXITSTATUS(status);

	if(exitcode) {
		printf_e("Error: Got non-zero exitcode while running \"%s\", exitcode is %i.\n", actfpath, exitcode);
		return exitcode;
	}

	return 0;
}

int sync_initialsync(const char *path, const char *actfpath) {
	return sync_exec(actfpath, "initialsync", path, NULL);
}

int sync_notify_mark(int notify_d, struct options *options, const char *path) {
	switch(options->notifyengine) {
		case NE_FANOTIFY: {
			int fanotify_d = notify_d;

			if((fanotify_mark(fanotify_d, FAN_MARK_ADD | FAN_MARK_DONT_FOLLOW,
				FANOTIFY_MARKMASK, AT_FDCWD, path)) == -1)
			{
				printf_e("Error: Cannot fanotify_mark() on \"%s\": %s (errno: %i).\n", 
					path, strerror(errno), errno);
				return errno;
			}
			return 0;
		}
		case NE_INOTIFY:
			return -1;
	}
	printf_e("Error: unknown notify-engine: %i\n", options->notifyengine);
	errno = EINVAL;
	return -1;
}

int sync_walk_notifymark(int notify_d, struct options *options, const char *dirpath, rule_t *rules) {
	const char *rootpaths[] = {dirpath, NULL};
	FTS *tree;
	printf_dd("Debug2: sync_walk_notifymark(%i, options, \"%s\", rules).\n", notify_d, dirpath);

	tree = fts_open((char *const *)&rootpaths, FTS_NOCHDIR|FTS_PHYSICAL, NULL);

	if(tree == NULL) {
		printf_e("Error: Cannot fts_open() on \"%s\": %s (errno: %i).\n", dirpath, strerror(errno), errno);
		return errno;
	}

	FTSENT *node;
	while((node = fts_read(tree))) {

		switch(node->fts_info) {
			case FTS_DP:	// Duplicates:
			case FTS_DEFAULT:
			case FTS_SL:
			case FTS_SLNONE:
			case FTS_F:
				continue;
			case FTS_D:	// To sync:
			case FTS_DOT:
				break;
			case FTS_ERR:	// Error cases:
			case FTS_NS:
			case FTS_NSOK:
			case FTS_DNR:
			case FTS_DC:
				printf_e("Error: Got error while fts_read(): %s (errno: %i; fts_info: %i).\n", strerror(errno), errno, node->fts_info);
				return errno;
			default:
				printf_e("Error: Got unknown fts_info vlaue while fts_read(): %i.\n", node->fts_info);
				return EINVAL;
		}

		int i = 0;
		rule_t *rule_p = rules;
		mode_t ftype = node->fts_statp->st_mode & S_IFMT;
		while(rule_p->action != RULE_END) {

			if(rule_p->objtype && (rule_p->objtype != ftype)) {
				rule_p = &rules[i++];
				continue;
			}

			if(!regexec(&rule_p->expr, node->fts_path, 0, NULL, 0))
				break;

			rule_p = &rules[i++];

		}

		ruleaction_t action = rule_p->action;
		if(action == RULE_END)
			action = RULE_DEFAULT;

		printf_dd("Debug2: matched to rule #%u for \"%s\":\t%i -> %i.\n", rule_p->action==RULE_END?-1:i, node->fts_accpath, rule_p->action, action);

		if(action == RULE_REJECT) {
			fts_set(tree, node, FTS_SKIP);
			continue;
		}

		printf_dd("Debug2: marking \"%s\" (depth %u)\n", node->fts_path, node->fts_level);
		sync_notify_mark(notify_d, options, node->fts_accpath);

	}
	if(errno) {
		printf_e("Error: Got error while fts_read() and related routines: %s (errno: %i).\n", strerror(errno), errno);
		return errno;
	}

	if(fts_close(tree)) {
		printf_e("Error: Got error while fts_close(): %s (errno: %i).\n", strerror(errno), errno);
		return errno;
	}

	return 0;
}

int sync_notify_init(struct options *options) {
	switch(options->notifyengine) {
		case NE_FANOTIFY: {
			int fanotify_d = fanotify_init(FANOTIFY_FLAGS, FANOTIFY_EVFLAGS);
			if(fanotify_d == -1) {
				printf_e("Error: cannot fanotify_init(%i, %i): %s (errno: %i).\n", FANOTIFY_FLAGS, FANOTIFY_EVFLAGS, strerror(errno), errno);
				return -1;
			}

			return fanotify_d;
		}
		case NE_INOTIFY: {
			return -1;
		}
	}
	printf_e("Error: unknown notify-engine: %i\n", options->notifyengine);
	errno = EINVAL;
	return -1;
}

int sync_fanotify_loop(int fanotify_d, struct options *options) {
	struct fanotify_event_metadata buf[BUFSIZ/sizeof(struct fanotify_event_metadata) + 1];
	int running=1;
	while(running) {
		struct fanotify_event_metadata *metadata;
		size_t len = read(fanotify_d, (void *)buf, sizeof(buf));
		metadata=buf;
		if(len == -1) {
			printf_e("Error: cannot read(%i, &metadata, sizeof(metadata)): %s (errno: %i).\n", fanotify_d, strerror(errno), errno);
			return errno;
		}
		while(FAN_EVENT_OK(metadata, len)) {
			printf_dd("Debug2: metadata->pid: %i; metadata->fd: %i\n", metadata->pid, metadata->fd);
			if (metadata->fd != FAN_NOFD) {
				if (metadata->fd >= 0) {
					char *fpath = fd2fpath_malloc(metadata->fd);
					printf_dd("Debug2: Event %i on \"%s\".\n", metadata->mask, fpath);
					free(fpath);
				}
			}
			close(metadata->fd);
			metadata = FAN_EVENT_NEXT(metadata, len);
		}
	}
	return 0;
}

int sync_inotify_loop(int inotify_d, struct options *options) {
	return 0;
}

int sync_notify_loop(int notify_d, struct options *options) {
	switch(options->notifyengine) {
		case NE_FANOTIFY:
			return sync_fanotify_loop(notify_d, options);
		case NE_INOTIFY:
			return sync_inotify_loop (notify_d, options);
	}
	printf_e("Error: unknown notify-engine: %i\n", options->notifyengine);
	errno = EINVAL;
	return -1;
}

int sync_run(struct options *options, rule_t *rules) {
	int ret;

	int notify_d = sync_notify_init(options);
	if(notify_d == -1) return errno;

	ret = sync_walk_notifymark(notify_d, options, options->watchdir, rules);
	if(ret) return ret;

	ret = sync_initialsync(options->watchdir, options->actfpath);
	if(ret) return ret;

	ret = sync_notify_loop(notify_d, options);
	if(ret) return ret;

	close(notify_d);

	return 0;
}

