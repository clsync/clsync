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

/*
int fasync_walk_fanotifyset(const char *dirpath, rule_t *rules) {
	struct dirent *dent;
	DIR *dir;
	printf_dd("Debug2: fasync_walk_fanotifyset(\"%s\", rules).\n", dirpath);
	char path[FILENAME_MAX+1];
	size_t pathlen = strlen(dirpath);

	if(pathlen+2 >= FILENAME_MAX) {
		printf_e("Error: Too long path \"%s\" (#0)\n", dirpath);
		return EINVAL;
	}

	if(!(dir = opendir(dirpath))) {
		printf_e("Error: Cannot opendir() on directory \"%s\": %s (errno: %i).\n", dirpath, strerror(errno), errno);
		return errno;
	}

	memcpy(path, dir, pathlen+1);
	path[pathlen++] = '/';
	path[pathlen  ] = 0;		// Just in case

	while((dent = readdir(dir))) {
		if (!strcmp(dent->d_name, ".") || !strcmp(dent->d_name, ".."))			continue;

		size_t objnamelen = strlen(dent->d_name);

		if(pathlen + objnamelen + 1>= FILENAME_MAX) {
			printf_e("Error: Too long path \"%s/%s\" (#1)\n", dirpath, dent->d_name);
			return EINVAL;
		}
		memcpy(&path[pathlen], dent->d_name, objnamelen+1);

		printf_dd("Debug2: obj path <%s>\n", path);
	}

	return 0;
}
*/
/*
int fasync_fanotifyset(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
	printf_dd("Debug2: fasync_fanotifyset(\"%s\", sb, %i, ftwbuf).\n", fpath, typeflag);

	return FTW_CONTINUE;
}

int fasync_walk_fanotifyset(const char *dirpath, rule_t *rules) {
	if(nftw(dirpath, fasync_fanotifyset, MAXFOPEN, FTW_ACTIONRETVAL|FTW_PHYS)) {
		printf_e("Error: Cannot nftw() on \"%s\": %s (errno: %i).\n", dirpath, strerror(errno), errno);
		return errno;
	}
	return 0;
}
*/

static int fasync_walk_fanotifyset_cmp(const FTSENT **a, const FTSENT **b) {
	return 0;
}

int fasync_walk_fanotifyset(int fanotify_d, const char *dirpath, rule_t *rules) {
	const char *rootpaths[] = {dirpath, NULL};
	FTS *tree;
	printf_dd("Debug2: fasync_walk_fanotifyset(\"%s\", rules).\n", dirpath);

	tree = fts_open((char *const *)&rootpaths, FTS_NOCHDIR|FTS_PHYSICAL, fasync_walk_fanotifyset_cmp);

	if(tree == NULL) {
		printf_e("Error: Cannot fts_open() on \"%s\": %s (errno: %i).\n", dirpath, strerror(errno), errno);
		return errno;
	}

	FTSENT *node;
	while((node = fts_read(tree))) {
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
		printf_dd("test2\n");

		ruleaction_t action = rule_p->action;
		if(action == RULE_END)
			action = RULE_DEFAULT;

		printf_dd("Debug2: \"%s\" matched to rule #%i: %i -> %i.\n", node->fts_accpath, i, rule_p->action, action);

		if(action == RULE_REJECT) {
			fts_set(tree, node, FTS_SKIP);
			continue;
		}

		if((fanotify_mark(fanotify_d, FAN_MARK_ADD | FAN_MARK_DONT_FOLLOW,
			FANOTIFY_MARKMASK, FAN_NOFD, node->fts_accpath)) == -1)
		{
			printf_e("Error: Cannot fanotify_mark() on \"%s\": %s (errno: %i).\n", 
				node->fts_path, strerror(errno), errno);
			return errno;
		}

		printf_d("Debug: got file named %s at depth %d, "
		"accessible via %s from the current directory "
		"or via %s from the original starting directory\n",
		node->fts_name, node->fts_level,
		node->fts_accpath, node->fts_path);
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

int fasync_run(const char *path, const char *actfpath, rule_t *rules) {
	int ret;

	int fanotify_d = fanotify_init(FANOTIFY_FLAGS, FANOTIFY_EVFLAGS);
	if(fanotify_d == -1) {
		printf_e("Error: cannot fanotify_init(%i, %i): %s (errno: %i).\n", FANOTIFY_FLAGS, FANOTIFY_EVFLAGS, strerror(errno), errno);
		return errno;
	}

	ret = fasync_walk_fanotifyset(fanotify_d, path, rules);
	if(ret) return ret;

	ret = fasync_initialsync(path, actfpath);
	if(ret) return ret;


	return 0;
}

