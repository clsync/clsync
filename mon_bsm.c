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

#include "common.h"
#include "malloc.h"
#include "error.h"
#include "indexes.h"
#include "sync.h"
#include "mon_bsm.h"

#include <bsm/libbsm.h>
#include <bsm/audit_kevents.h>
#include <glib.h>

struct bsm_event {
	u_int16_t type;
	char path   [PATH_MAX];
	char path_to[PATH_MAX];
	int w_id;
};

struct mondata {
	FILE *pipe;
	int config_fd;
	struct bsm_event event;
};
typedef struct mondata mondata_t;

enum event_bits {
	UEM_DIR		= 0x01,
	UEM_CREATED	= 0x02,
	UEM_DELETED	= 0x04,
};

struct recognize_event_return {
	struct {
		eventobjtype_t objtype_old;
		eventobjtype_t objtype_new;
	} f;
	struct {
		eventobjtype_t objtype_old;
		eventobjtype_t objtype_new;
	} t;
};

static inline uint64_t recognize_event(struct recognize_event_return *r, uint32_t event) {
	int is_created, is_deleted, is_moved;
	eventobjtype_t type;

	type       = EOT_FILE;
	is_moved   = 0;
	is_created = 0;
	is_deleted = 0;
	switch (event) {
		case AUE_MKDIR:
		case AUE_MKDIRAT:
			type       = EOT_DIR;
		case AUE_OPEN_RC:
		case AUE_OPEN_RTC:
		case AUE_OPEN_WC:
		case AUE_OPEN_WTC:
		case AUE_OPEN_RWC:
		case AUE_OPEN_RWTC:
		case AUE_LINK:
		case AUE_LINKAT:
		case AUE_MKFIFO:
		case AUE_MKFIFOAT:
		case AUE_MKNOD:
		case AUE_MKNODAT:
		case AUE_SYMLINK:
		case AUE_SYMLINKAT:
			is_created = 1;
			break;
		case AUE_RMDIR:
#if AUE_RMDIRAT
		case AUE_RMDIRAT:
#endif
			type       = EOT_DIR;
		case AUE_UNLINK:
		case AUE_UNLINKAT:
			is_deleted = 1;
			break;
		case AUE_RENAME:
		case AUE_RENAMEAT:
			type       = EOT_DIR;
			is_moved   = 1;
			break;
		case AUE_CLOSE:
		case AUE_CLOSEFROM:
			break;
		default:
			warning("Unknown event: 0x%x", event);
			break;
	}

	r->f.objtype_old = type;

	if (is_moved) {
		r->f.objtype_new = EOT_DOESNTEXIST;
		r->t.objtype_old = EOT_DOESNTEXIST;
		r->t.objtype_new = type;

		return;
	}

	r->f.objtype_new = type;

	if (is_created)
		r->f.objtype_old = EOT_DOESNTEXIST;

	if (is_deleted)
		r->f.objtype_new = EOT_DOESNTEXIST;

	return;
}

int auditd_restart() {
	debug(1, "Running \""AUDIT_CONTROL_INITSCRIPT" restart\"");

	pid_t pid = fork();
	switch (pid) {
		case -1: 
			error("Cannot fork().");
			return -1;
		case  0:
			debug(5, "fork: execl(\""AUDIT_CONTROL_INITSCRIPT"\", \""AUDIT_CONTROL_INITSCRIPT"\", \"restart\", NULL);", pid);
			execl(AUDIT_CONTROL_INITSCRIPT, AUDIT_CONTROL_INITSCRIPT, "restart", NULL);
			error("fork: Cannot execute \""AUDIT_CONTROL_INITSCRIPT" restart\"");
			return -1;
	}

	debug(6, "Waiting for %u", pid);
	int status;
	if (waitpid(pid, &status, 0) != pid) {
		error("Cannot waitid().");
		return -1;
	}
	int exitcode = WEXITSTATUS(status);

	if (exitcode)
		error("Got error while running \""AUDIT_CONTROL_INITSCRIPT" restart\"");

	debug(4, "exitcode == %u", exitcode);
	return exitcode;
}

int bsm_config_backup(mondata_t *mondata) {
	char buf[sizeof(AUDIT_CONTROL_HEADER)];
	int fd = open(AUDIT_CONTROL_PATH, O_RDONLY);

	if (fd == -1) {
		debug(4, "Cannot open "AUDIT_CONTROL_PATH". No need for backup.");
		return 1;
	}

	int r = read(fd, buf, sizeof(AUDIT_CONTROL_HEADER)-1);
	close(fd);

	if (r == sizeof(AUDIT_CONTROL_HEADER)-1)
		if (!memcmp(buf, AUDIT_CONTROL_HEADER, sizeof(AUDIT_CONTROL_HEADER)-1)) {
			debug(4, "File "AUDIT_CONTROL_PATH" is already clsync-compatible.");
			return 0;
		}


	if (!access(AUDIT_CONTROL_PATH"-clsync_backup", R_OK)) {
		error("File \""AUDIT_CONTROL_PATH"-clsync_backup\" already exists. Cannot backup \""AUDIT_CONTROL_PATH"\".");
		return -1;
	}

	debug(3, "mv: "AUDIT_CONTROL_PATH" -> "AUDIT_CONTROL_PATH"-clsync_backup");
	rename(AUDIT_CONTROL_PATH, AUDIT_CONTROL_PATH"-clsync_backup");

	close(fd);

	return 1;
}

int bsm_config_setup(mondata_t *mondata) {
	debug(3, "");
	switch (bsm_config_backup(mondata)) {
		case 0:
			debug(4, "bsm_config_backup(): no reconfig required");
			return 0;
		case -1:
			debug(4, "bsm_config_backup(): error");
			return -1;
	}
	debug(3, "Writting a new audit_control file to \""AUDIT_CONTROL_PATH"\"");

	mondata->config_fd = open(AUDIT_CONTROL_PATH, O_RDONLY);
	flock(mondata->config_fd, LOCK_SH);

	int fd_w = open(AUDIT_CONTROL_PATH, O_WRONLY|O_CREAT);
	if (fd_w == -1) {
		error("Cannot open file \""AUDIT_CONTROL_PATH"\" for writing");
		return -1;
	}

	int w;
	if ((w=write(fd_w, AUDIT_CONTROL_HEADER AUDIT_CONTROL_CONTENT, sizeof(AUDIT_CONTROL_HEADER AUDIT_CONTROL_CONTENT)-1)) != sizeof(AUDIT_CONTROL_HEADER AUDIT_CONTROL_CONTENT)-1) {
		error("Cannot write to \""AUDIT_CONTROL_HEADER AUDIT_CONTROL_CONTENT"\" (%u != %u)", w, sizeof(AUDIT_CONTROL_HEADER AUDIT_CONTROL_CONTENT)-1);
		return -1;
	}

	close(fd_w);

	if (auditd_restart()) {
		error("Cannot restart auditd to apply a new "AUDIT_CONTROL_PATH);
		return -1;
	}

	return 0;
}

int bsm_config_revert(mondata_t *mondata) {
	int rc = 0;
	int fd = mondata->config_fd;

	flock(fd, LOCK_UN);

	if (flock(fd, LOCK_NB|LOCK_EX))
		return 0;

	debug(1, "I'm the last BSM clsync instance.");

	if (!access(AUDIT_CONTROL_PATH"-clsync_backup", R_OK)) {
		debug(1,"Reverting the audit config file (\""AUDIT_CONTROL_PATH"-clsync_backup\" -> \""AUDIT_CONTROL_PATH"\").");
		rc = rename(AUDIT_CONTROL_PATH"-clsync_backup", AUDIT_CONTROL_PATH);
	}
	flock(fd, LOCK_UN);

	if (rc) {
		error("Got error while rename(\""AUDIT_CONTROL_PATH"-clsync_backup\", \""AUDIT_CONTROL_PATH"\")");
		return -1;
	}
	return 0;
}


#define BSM_INIT_ERROR {\
	free(ctx_p->fsmondata);\
	ctx_p->fsmondata = NULL;\
	return -1;\
}

int bsm_init(ctx_t *ctx_p) {

	ctx_p->fsmondata = xcalloc(sizeof(mondata_t), 1);
	mondata_t *mondata = ctx_p->fsmondata;

	if (bsm_config_setup(mondata) == -1)
		BSM_INIT_ERROR;

	FILE *pipe = fopen(AUDITPIPE_PATH, "r");
	if (pipe == NULL) {
		error("Cannot open \""AUDITPIPE_PATH"\" for reading.");
		BSM_INIT_ERROR;
	}
	
	if (setvbuf(pipe, NULL, _IONBF, 0)) {
		error("Cannot set unbuffered mode for auditpipe");
		BSM_INIT_ERROR;
	}

	mondata->pipe = pipe;

	return 0;
}
int bsm_wait(struct ctx *ctx_p, struct indexes *indexes_p, struct timeval *timeout_p) {
	mondata_t *mondata = ctx_p->fsmondata;
	struct timeval timeout_abs, tv_abs;
	int dontwait = 0;
	u_char *au_buf;
	size_t  au_len;
	size_t  au_parsed;
	tokenstr_t tok;
	struct bsm_event *event_p = &mondata->event;

	if (timeout_p->tv_sec == 0 && timeout_p->tv_usec == 0)
		dontwait = 1;

	if (!dontwait) {
		gettimeofday(&tv_abs, NULL);
		timeradd(&tv_abs, timeout_p, &timeout_abs);
	}

	int pipe_fd = fileno(mondata->pipe);

	while (42) {
		int path_count;

		// Checking if there already a recond in mondata
		if (*event_p->path) {
			debug(2, "we have an event. return 1.");
			return 1;
		}

		// Getting a record
		{
			debug(3, "select() with timeout %li.%06li secs (dontwait == %u).", timeout_p->tv_sec, timeout_p->tv_usec, dontwait);
			fd_set rfds;
			FD_ZERO(&rfds);
			FD_SET(pipe_fd, &rfds);
			int rc = select(pipe_fd+1, &rfds, NULL, NULL, timeout_p);

			if (rc == 0 || rc == -1)
				return rc;

			au_len = au_read_rec(mondata->pipe, &au_buf);
			if (au_len == -1) {
				au_len = 0;
				return -1;
			}

			if (!dontwait) {
				debug(5, "old timeout_p->: tv_sec == %lu; tv_usec == %lu", timeout_p->tv_sec, timeout_p->tv_usec);
				gettimeofday(&tv_abs, NULL);
				if (timercmp(&timeout_abs, &tv_abs, <))
					timersub(&timeout_abs, &tv_abs, timeout_p);
				else
					memset(timeout_p, 0, sizeof(*timeout_p));
				debug(5, "new timeout_p->: tv_sec == %lu; tv_usec == %lu", timeout_p->tv_sec, timeout_p->tv_usec);
			}
		}

		// Parsing the record
		path_count = 0;
		debug(3, "parsing the event");
		while (au_parsed < au_len) {

			if (au_fetch_tok(&tok, &au_buf[au_parsed], au_len - au_parsed) == -1)
				return -1;
			au_parsed += tok.len;

			switch (tok.id) {
				case AUT_HEADER32:
				case AUT_HEADER32_EX:
				case AUT_HEADER64:
				case AUT_HEADER64_EX: {
					event_p->type = tok.tt.hdr32.e_type;
					path_count = 0;
					break;
				}
				case AUT_PATH: {
					char *ptr;
					int dir_wd, dir_iswatched;

					ptr = memrchr(tok.tt.path.path, '/', tok.tt.path.len);

#ifdef PARANOID
					if (ptr == NULL)
						critical("relative path received from au_fetch_tok(): \"%s\" (len: %u)", tok.tt.path.path, tok.tt.path.len);
#endif

					debug(6, "Event on \"%s\".", tok.tt.path.path);
					*ptr = 0;
					dir_wd = indexes_fpath2wd(indexes_p, tok.tt.path.path);
					dir_iswatched = (dir_wd != -1);
					debug(7, "Directory is \"%s\". dir_wd == %i; dir_iswatched == %u", tok.tt.path.path, dir_wd, dir_iswatched);
					*ptr = '/';

					if (dir_iswatched) {
						debug(5, "Event on \"%s\" is watched. Pushing. path_count == %u", tok.tt.path.path, path_count);
						switch (path_count) {
							case 0: 
								memcpy(event_p->path,    tok.tt.path.path, tok.tt.path.len+1);
								break;
							case 1: 
								memcpy(event_p->path_to, tok.tt.path.path, tok.tt.path.len+1);
								break;
#ifdef PARANOID
							default:
								warning("To many paths on BSM event: \"%s\" (already count: %u)", tok.tt.path.path, path_count);
								break;
#endif
						}
					}
					path_count++;
					break;
				}
				default:
					continue;
			}
		}

		// Cleanup
		debug(4, "clean up");
		free(au_buf);
		au_buf    = NULL;
		au_len    = 0;
		au_parsed = 0;
	}

	return -1;
}
int bsm_handle(struct ctx *ctx_p, struct indexes *indexes_p) {
	static struct timeval tv={0};
	mondata_t *mondata = ctx_p->fsmondata;
	int count;
	char   *path_rel	= NULL;
	size_t  path_rel_len	= 0;
	struct bsm_event *event_p = &mondata->event;

	count = 0;

#ifdef PARANOID
	g_hash_table_remove_all(indexes_p->fpath2ei_ht);
#endif

	do {
		struct  recognize_event_return r = {{0}};
		char *path_stat;
		struct stat st;
		mode_t st_mode;
		size_t st_size;

#ifdef PARANOID
		if (!*event_p->path && !*event_p->path_to) {
			warning("bsm_handle() but no events are parsed.");
			continue;
		}
#endif

		recognize_event(&r, event_p->type);

		if (r.t.objtype_new != EOT_UNKNOWN) 
			path_stat = event_p->path_to;
		else 
			path_stat = event_p->path;

		if (lstat(path_stat, &st)) {
			debug(2, "Cannot lstat64(\"%s\", st). Seems, that the object disappeared.", path_stat);
			if(r.f.objtype_old == EOT_DIR || r.f.objtype_new == EOT_DIR)
				st_mode = S_IFDIR;
			else
				st_mode = S_IFREG;
			st_size = 0;
		} else {
			st_mode = st.st_mode;
			st_size = st.st_size;
		}

		if (*event_p->path) {
			if (sync_prequeue_loadmark(1, ctx_p, indexes_p, event_p->path, NULL, r.f.objtype_old, r.f.objtype_new, event_p->type, event_p->w_id, st_mode, st_size, &path_rel, &path_rel_len, NULL)) {
				error("Got error while load_mark-ing into pre-queue \"%s\"", event_p->path);
				count = -1;
				*event_p->path = 0;
				break;
			}
			*event_p->path = 0;
			count++;
		}

		if ((r.t.objtype_new != EOT_UNKNOWN) && *event_p->path_to) {
			if (sync_prequeue_loadmark(1, ctx_p, indexes_p, event_p->path_to, NULL, r.t.objtype_old, r.t.objtype_new, event_p->type, event_p->w_id, st_mode, st_size, &path_rel, &path_rel_len, NULL)) {
				error("Got error while load_mark-ing into pre-queue \"%s\"", event_p->path_to);
				count = -1;
				*event_p->path_to = 0;
				break;
			}
			*event_p->path_to = 0;
			count++;
		}
	} while (bsm_wait(ctx_p, indexes_p, &tv) > 0);

	free(path_rel);
#ifdef VERYPARANOID
	path_rel     = NULL;
	path_rel_len = 0;
#endif

	// Globally queueing captured events:
	// Moving events from local queue to global ones
	sync_prequeue_unload(ctx_p, indexes_p);

	debug(4, "Result count: %i", count);
	if (count == -1)
		return -1;

	return count;
}
int bsm_add_watch_dir(struct ctx *ctx_p, struct indexes *indexes_p, const char *const accpath) {
	static int id = 1;
	if (id == -1)
		id = (int)((unsigned int)~0 >> 2);

	// TODO: optimize this line out:
	while (indexes_wd2fpath(indexes_p, id) != NULL)
		id++;

	return id++;
}
int bsm_deinit(ctx_t *ctx_p) {
	int rc = 0;
	mondata_t *mondata = ctx_p->fsmondata;

	rc |= fclose(mondata->pipe);

	rc |= bsm_config_revert(mondata);

	free(ctx_p->fsmondata);
	ctx_p->fsmondata = NULL;

	rc |= auditd_restart();

	return rc;
}

