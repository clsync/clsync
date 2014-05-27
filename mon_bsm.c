/*
    clsync - file tree sync utility based on inotify/kqueue
    
    Copyright (C) 2013-2014 Dmitry Yu Okunev <dyokunev@ut.mephi.ru> 0x8E30679C
    
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



int bsm_init(ctx_t *ctx_p) {
	char backup_path[4096];

	sprintf(backup_path, AUDIT_CONTROL_PATH"-%u", getpid());

	if (stat)

	rename(AUDIT_CONTROL_PATH, backup_path);

	int fd = open(AUDIT_CONTROL_PATH, O_WRONLY|O_CREAT);
	if (fd == -1)
		return -1;

	if (write(fd, AUDIT_CONTROL_CONTENT, sizeof(AUDIT_CONTROL_CONTENT)-1) != AUDIT_CONTROL_CONTENT-1)
		return -1;

	close(fd);

	debug(1, "Running \""AUDIT_CONTROL_INITSCRIPT" restart\"");

	pid_t pid = fork();
	switch (pid) {
		case -1: 
			error("Cannot fork().");
			return -1;
		case  0:
			execl(AUDIT_CONTROL_INITSCRIPT, "restart");
			return -1;
	}

	int status;
	if (waitpid(pid, &status, 0) != pid) {
		error("Cannot waitid().");
		return -1;
	}
	int exitcode = WEXITSTATUS(status);

	if (exitcode)
		error("Got error while running \""AUDIT_CONTROL_INITSCRIPT" restart\"");

	return exitcode;
}
int bsm_wait(struct ctx *ctx_p, struct timeval *tv_p) {
	return -1;
}
int bsm_handle(struct ctx *ctx_p, struct indexes *indexes_p) {
	return -1;
}
int bsm_add_watch_dir(struct ctx *ctx_p, struct indexes *indexes_p, const char *const accpath) {
	return -1;
}
int bsm_deinit(ctx_t *ctx_p) {
	char backup_path[4096];

	sprintf(backup_path, AUDIT_CONTROL_PATH"-%u", getpid());

	if (stat)

	rename(backup_path, AUDIT_CONTROL_PATH);
	return 0;
}

