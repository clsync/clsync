/*
    fasync - sync utility based on fanotify

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

int fasync_exec(const char *actfpath, ...) {
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

int fasync_initialsync(const char *path, const char *actfpath) {
	return fasync_exec(actfpath, "initialsync", path, NULL);
}

int fasync_walk_inotifyset(const char *path, rule_t *rules) {

	return 0;
}

int fasync_run(const char *path, const char *actfpath, rule_t *rules) {
	int ret;

	ret = fasync_initialsync(path, actfpath);
	if(ret) return ret;

	ret = fasync_walk_inotifyset(path, rules);
	if(ret) return ret;

	int fanotify_d = fanotify_init(FANOTIFY_FLAGS, FANOTIFY_EVFLAGS);
	if(fanotify_d == -1) {
		printf_e("Error: cannot fanotify_init(): %s (errno: %i).", strerror(errno), errno);
		return errno;
	}

	return 0;
}

