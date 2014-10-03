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
#include <sys/ioctl.h>
#include <security/audit/audit_ioctl.h>

struct bsm_event {
	u_int16_t type;
	char path   [PATH_MAX];
	char path_to[PATH_MAX];
	int w_id;
};

struct mondata {
	FILE *pipe;
	int config_fd;
	size_t event_count;
	size_t event_count_wasinqueue;
	size_t event_alloc;
	struct bsm_event *event;
};
typedef struct mondata mondata_t;

enum event_bits {
	UEM_DIR		= 0x01,
	UEM_CREATED	= 0x02,
	UEM_DELETED	= 0x04,
};

enum bsm_handle_type {
	BSM_HANDLER_CALLWAIT,
	BSM_HANDLER_ITERATE,
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

pthread_t       prefetcher_thread;
pthread_mutex_t bsm_mutex_prefetcher = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t  bsm_cond_gotevent    = PTHREAD_COND_INITIALIZER;
pthread_cond_t  bsm_cond_queueend    = PTHREAD_COND_INITIALIZER;

int bsm_queue_len;

int (*bsm_wait)(struct ctx *ctx_p, struct indexes *indexes_p, struct timeval *timeout_p);
int (*bsm_handle)(struct ctx *ctx_p, struct indexes *indexes_p);

extern int bsm_prefetcher(struct ctx *ctx_p);
extern int bsm_wait_prefetched  (struct ctx *ctx_p, struct indexes *indexes_p, struct timeval *timeout_p);
extern int bsm_wait_noprefetch  (struct ctx *ctx_p, struct indexes *indexes_p, struct timeval *timeout_p);
extern int bsm_handle_prefetched(struct ctx *ctx_p, struct indexes *indexes_p);
extern int bsm_handle_noprefetch(struct ctx *ctx_p, struct indexes *indexes_p);

static inline void recognize_event(struct recognize_event_return *r, uint32_t event) {
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
	debug(1, "Running \""AUDIT_CONTROL_INITSCRIPT" onerestart\"");

	pid_t pid = fork();
	switch (pid) {
		case -1: 
			error("Cannot fork().");
			return -1;
		case  0:
			debug(5, "fork: execl(\""AUDIT_CONTROL_INITSCRIPT"\", \""AUDIT_CONTROL_INITSCRIPT"\", \"onerestart\", NULL);", pid);
			execl(AUDIT_CONTROL_INITSCRIPT, AUDIT_CONTROL_INITSCRIPT, "onerestart", NULL);
			error("fork: Cannot execute \""AUDIT_CONTROL_INITSCRIPT" onerestart\"");
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
		error("Got error while running \""AUDIT_CONTROL_INITSCRIPT" onerestart\"");

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
	debug(9, "");

	ctx_p->fsmondata = xcalloc(sizeof(mondata_t), 1);
	mondata_t *mondata = ctx_p->fsmondata;

	if (bsm_config_setup(mondata) == -1)
		BSM_INIT_ERROR;

	debug(5, "Openning \""AUDITPIPE_PATH"\"");
	FILE *pipe = fopen(AUDITPIPE_PATH, "r");
	if (pipe == NULL) {
		error("Cannot open \""AUDITPIPE_PATH"\" for reading.");
		BSM_INIT_ERROR;
	}

	{
		// Setting auditpipe queue length to be maximal

		int fd;
		u_int len;

		fd = fileno(pipe);

		if (ioctl(fd, AUDITPIPE_GET_QLIMIT_MAX, &len) < 0) {
			error("Cannot read QLIMIT_MAX from auditpipe");
			BSM_INIT_ERROR;
		}

		if (ioctl(fd, AUDITPIPE_SET_QLIMIT, &len) < 0) {
			error("Cannot set QLIMIT through auditpipe");
			BSM_INIT_ERROR;
		}

		if (ioctl(fd, AUDITPIPE_GET_QLIMIT, &len) < 0) {
			error("Cannot read QLIMIT from auditpipe");
			BSM_INIT_ERROR;
		}

		bsm_queue_len = len;

		debug(5, "auditpipe QLIMIT -> %i", (int)len);
	}
	
	if (setvbuf(pipe, NULL, _IONBF, 0)) {
		error("Cannot set unbuffered mode for auditpipe");
		BSM_INIT_ERROR;
	}

	mondata->pipe = pipe;

	switch (ctx_p->flags[MONITOR]) {
		case NE_BSM:
			bsm_wait   = bsm_wait_noprefetch;
			bsm_handle = bsm_handle_noprefetch;
			mondata->event = xcalloc(sizeof(*mondata->event), 1);
			break;
		case NE_BSM_PREFETCH:
			pthread_mutex_init(&bsm_mutex_prefetcher, NULL);
			pthread_cond_init (&bsm_cond_gotevent,    NULL);
			pthread_cond_init (&bsm_cond_queueend,    NULL);
			bsm_wait   = bsm_wait_prefetched;
			bsm_handle = bsm_handle_prefetched;

			critical_on (pthread_create(&prefetcher_thread, NULL, (void *(*)(void *))bsm_prefetcher, ctx_p));
			break;
		default:
			critical("Invalid ctx_p->flags[MONITOR]: %u", ctx_p->flags[MONITOR]);
	}

	return 0;
}

int select_rfd(int fd, struct timeval *timeout_p) {
	int rc;
	debug(9, "%i, {%li, %li}", fd, timeout_p == NULL ? -1 : timeout_p->tv_sec, timeout_p == NULL ? 0 : timeout_p->tv_usec);
	fd_set rfds;
	FD_ZERO(&rfds);
	FD_SET(fd, &rfds);
	rc = select(fd+1, &rfds, NULL, NULL, timeout_p);
	debug(9, "rc -> %i", rc);
	return rc;
}

int bsm_fetch(ctx_t *ctx_p, indexes_t *indexes_p, struct bsm_event *event_p, int pipe_fd, struct timeval *timeout_p, struct timeval *timeout_abs_p) {
	size_t  au_len;
	size_t  au_parsed;
	u_char *au_buf;
	tokenstr_t tok;
	int recalc_timeout;
	static int dont_wait = 0;
	struct timeval tv_abs;
	struct timeval timeout_zero = {0};
	mondata_t *mondata = ctx_p->fsmondata;

	recalc_timeout = 0;
	if (timeout_p != NULL)
		if (timeout_p->tv_sec != 0 || timeout_p->tv_usec != 0)
			recalc_timeout = 1;

	while (42) {
		int path_count;

		// Checking if there already a recond in mondata
		if (*event_p->path) {
			debug(2, "we have an event. return 1.");
			return 1;
		}

		// Getting a record
		{
			int rc;

			rc = 0;
			if (dont_wait) {
				debug(4, "select() without waiting");
				rc = select_rfd(pipe_fd, &timeout_zero);
				if (rc == 0) {
					dont_wait = 0;
					mondata->event_count_wasinqueue = 0;
					switch (ctx_p->flags[MONITOR]) {
						case NE_BSM_PREFETCH:
							pthread_cond_broadcast(&bsm_cond_queueend);
							break;
						default:
							break;
					}
				} else
				if (rc > 0) {
					mondata->event_count_wasinqueue++;
					if (mondata->event_count_wasinqueue+1 >= bsm_queue_len)
						critical_or_warning(ctx_p->flags[EXITONSYNCSKIP], "The was too many events in BSM queue (reached kernel BSM queue limit: %u).", bsm_queue_len);
				}
			}

			if (rc == 0) {
				if (recalc_timeout == 2) {
					debug(5, "old timeout_p->: tv_sec == %lu; tv_usec == %lu", timeout_p->tv_sec, timeout_p->tv_usec);
					gettimeofday(&tv_abs, NULL);
					if (timercmp(timeout_abs_p, &tv_abs, <))
						timersub(timeout_abs_p, &tv_abs, timeout_p);
					else
						memset(timeout_p, 0, sizeof(*timeout_p));
					debug(5, "new timeout_p->: tv_sec == %lu; tv_usec == %lu", timeout_p->tv_sec, timeout_p->tv_usec);
				}

				debug(3, "select() with timeout %li.%06li secs (recalc_timeout == %u).", 
					timeout_p == NULL ? -1 : timeout_p->tv_sec,
					timeout_p == NULL ?  0 : timeout_p->tv_usec,
					recalc_timeout);

				rc = select_rfd(pipe_fd, timeout_p);
				if (rc > 0)
					mondata->event_count_wasinqueue++;

				if (recalc_timeout == 1)
					recalc_timeout++;
			}

			critical_on ((rc == -1) && (errno != EINTR));
			if (rc == 0 || rc == -1) {
				debug(3, "rc == %i; errno == %i; return 0", rc, errno);
				return 0;
			}

			dont_wait = 1;

			au_len = au_read_rec(mondata->pipe, &au_buf);
			critical_on (au_len == -1);
		}

		// Parsing the record
		au_parsed  = 0;
		path_count = 0;
		debug(3, "parsing the event (au_parsed == %u; au_len == %u)", au_parsed, au_len);
		while (au_parsed < au_len) {
			critical_on (au_fetch_tok(&tok, &au_buf[au_parsed], au_len - au_parsed) == -1);

			au_parsed += tok.len;
			debug(4, "au_fetch_tok(): au_parsed -> %u", tok.len);

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
	}

	critical ("This code shouldn't be reached");
	return -1;
}
enum bsm_handletype {
	BSM_HANDLE_CALLWAIT,
	BSM_HANDLE_ITERATE,
};
typedef enum bsm_handletype bsm_handletype_t;
int bsm_handle_allevents(struct ctx *ctx_p, struct indexes *indexes_p, bsm_handletype_t how) {
	debug(4, "");
	static struct timeval tv={0};
	mondata_t *mondata = ctx_p->fsmondata;
	int count, event_num;
	char   *path_rel	 = NULL;
	size_t  path_rel_len	 = 0;
	int left_count;

	event_num = 0;
	count     = 0;

#ifdef PARANOID
	g_hash_table_remove_all(indexes_p->fpath2ei_ht);
#endif

	do {
		struct  recognize_event_return r = {{0}};
		char *path_stat;
		struct stat st, *st_p;
		mode_t st_mode;
		size_t st_size;
		struct bsm_event *event_p = &mondata->event[event_num];

#ifdef PARANOID
		if (!*event_p->path && !*event_p->path_to) {
			warning("no events are parsed (event_p == %p; mondata->event_count == %i).", event_p, mondata->event_count);
			continue;
		}
#endif

		recognize_event(&r, event_p->type);

		if (r.t.objtype_new != EOT_UNKNOWN) 
			path_stat = event_p->path_to;
		else 
			path_stat = event_p->path;

		if ((r.t.objtype_new == EOT_DOESNTEXIST) || (ctx_p->flags[CANCEL_SYSCALLS]&CSC_MON_STAT) || lstat(path_stat, &st)) {
			debug(2, "Cannot lstat64(\"%s\", st). Seems, that the object had been deleted (%i) or option \"--cancel-syscalls=mon_stat\" (%i) is set.", path_stat, r.t.objtype_new == EOT_DOESNTEXIST, ctx_p->flags[CANCEL_SYSCALLS]&CSC_MON_STAT);
			if (r.f.objtype_old == EOT_DIR || r.f.objtype_new == EOT_DIR)
				st_mode = S_IFDIR;
			else
				st_mode = S_IFREG;
			st_size = 0;

			st_p    = NULL;
		} else {
			st_mode = st.st_mode;
			st_size = st.st_size;

			st_p    = &st;
		}

		if (*event_p->path) {
			if (sync_prequeue_loadmark(1, ctx_p, indexes_p, event_p->path, NULL, st_p, r.f.objtype_old, r.f.objtype_new, event_p->type, event_p->w_id, st_mode, st_size, &path_rel, &path_rel_len, NULL)) {
				error("Got error while load_mark-ing into pre-queue \"%s\"", event_p->path);
				count = -1;
				*event_p->path = 0;
				break;
			}
			*event_p->path = 0;
			count++;
		}

		if ((r.t.objtype_new != EOT_UNKNOWN) && *event_p->path_to) {
			if (sync_prequeue_loadmark(1, ctx_p, indexes_p, event_p->path_to, NULL, st_p, r.t.objtype_old, r.t.objtype_new, event_p->type, event_p->w_id, st_mode, st_size, &path_rel, &path_rel_len, NULL)) {
				error("Got error while load_mark-ing into pre-queue \"%s\"", event_p->path_to);
				count = -1;
				*event_p->path_to = 0;
				break;
			}
			*event_p->path_to = 0;
			count++;
		}
		switch (how) {
			case BSM_HANDLE_CALLWAIT:
				debug(15, "BSM_HANDLE_CALLWAIT");
				left_count = bsm_wait(ctx_p, indexes_p, &tv);
				break;
			case BSM_HANDLE_ITERATE:
				debug(15, "BSM_HANDLE_ITERATE");
				event_num++;
				left_count = mondata->event_count - event_num;
				break;
		}
		debug(10, "left_count: %i; event_num: %i; mondata->event_count: %i", left_count, event_num, mondata->event_count);
	} while (left_count > 0);
	switch (how) {
		case BSM_HANDLE_ITERATE:
			if (event_num < mondata->event_count) {
				memmove(
					 mondata->event,
					&mondata->event[event_num],
					sizeof(*mondata->event)*(mondata->event_count - event_num)
				);
			}
			mondata->event_count -= event_num;
			break;
		default:
			break;
	}

	free(path_rel);
#ifdef VERYPARANOID
	path_rel     = NULL;
	path_rel_len = 0;
#endif

	// Globally queueing captured events:
	// Moving events from local queue to global ones
	sync_prequeue_unload(ctx_p, indexes_p);

	debug(4, "Result processed count: %i (left, mondata->event_count == %i)", count, mondata->event_count);
	if (count == -1)
		return -1;

	return count;
}

void bsm_prefetcher_sig_int(int signal) {
	debug(2, "signal -> %i. Sending pthread_cond_broadcast() to bsm_cond_gotevent and bsm_cond_queueend.", signal);
	pthread_cond_broadcast(&bsm_cond_gotevent);
	pthread_cond_broadcast(&bsm_cond_queueend);
	return;
}

static int bsm_prefetcher_running=2;
int bsm_prefetcher(struct ctx *ctx_p) {
	mondata_t *mondata   = ctx_p->fsmondata;
	indexes_t *indexes_p = ctx_p->indexes_p;
	struct bsm_event event, *event_p;

	register_blockthread();
	signal(SIGUSR_BLOPINT,  bsm_prefetcher_sig_int);

	int pipe_fd = fileno(mondata->pipe);
	mondata->event = xcalloc(sizeof(*mondata->event), ALLOC_PORTION);

	bsm_prefetcher_running = 1;
	while (bsm_prefetcher_running) {
		if (bsm_fetch(ctx_p, indexes_p, &event, pipe_fd, NULL, NULL) > 0) {
			// Pushing the event
			debug(5, "We have an event. Pushing.");
#ifdef PARANOID
			critical_on (mondata->event_count >= BSM_QUEUE_LENGTH_MAX);
#endif
			if (mondata->event_count >= mondata->event_alloc) {
				debug(2, "Increasing queue length: %u -> %u (limit is "XTOSTR(BSM_QUEUE_LENGTH_MAX)")", mondata->event_alloc, mondata->event_alloc+ALLOC_PORTION);
				mondata->event_alloc += ALLOC_PORTION;
				mondata->event = xrealloc(mondata->event, mondata->event_alloc*sizeof(*mondata->event));
				memset(&mondata->event[mondata->event_count], 0, sizeof(*mondata->event)*(mondata->event_alloc - mondata->event_count));
			}

			pthread_mutex_lock(&bsm_mutex_prefetcher);
			event_p = &mondata->event[mondata->event_count++];
			memcpy(event_p, &event, sizeof(*event_p));
			debug(2, "event_count -> %u (event_p == %p; event_p->path == \"%s\")", mondata->event_count, event_p, event_p->path);
			pthread_cond_broadcast(&bsm_cond_gotevent);
			pthread_mutex_unlock(&bsm_mutex_prefetcher);

			memset(&event, 0, sizeof(event));
		}
	}

	return 0;
}
int bsm_wait_prefetched(struct ctx *ctx_p, struct indexes *indexes_p, struct timeval *timeout_p) {
	debug(3, "(ctx_p, indexes_p, %p {%u, %u})", timeout_p, timeout_p == NULL?-1:timeout_p->tv_sec, timeout_p == NULL?0:timeout_p->tv_usec);
#ifdef PARANOID
	critical_on (timeout_p == NULL);
#endif
	mondata_t *mondata = ctx_p->fsmondata;
	struct timespec ts_abs;
	struct timeval tv_abs, timeout_abs;

#define INFINITETIME (3600 * 24 * 365 * 10) /* ~10 years */
	if (timeout_p->tv_sec > INFINITETIME)
		timeout_p->tv_sec = INFINITETIME;
#undef INFINITETIME

	gettimeofday(&tv_abs, NULL);
	timeradd(&tv_abs, timeout_p, &timeout_abs);

	ts_abs.tv_sec  = timeout_abs.tv_sec;
	ts_abs.tv_nsec = timeout_abs.tv_usec*1000;

	pthread_mutex_lock(&bsm_mutex_prefetcher);
	if (mondata->event_count) {
		debug(2, "Already have an event. mondata->event_count == %i", mondata->event_count);
		pthread_mutex_unlock(&bsm_mutex_prefetcher);
		return mondata->event_count;
	}

	if (timeout_p->tv_sec == 0 && timeout_p->tv_sec == 0) {
		debug(2, "Zero timeout. Waiting for the current queue to be processed.")
		pthread_cond_wait(&bsm_cond_queueend, &bsm_mutex_prefetcher);
		pthread_mutex_unlock(&bsm_mutex_prefetcher);
		debug(3, "return mondata->event_count == %i", mondata->event_count);
		return mondata->event_count;
	}

//l_pthread_cond_timedwait_restart:
	debug(10, "pthread_cond_timedwait(&bsm_cond_gotevent, &bsm_mutex_prefetcher, {%i, %i})", ts_abs.tv_sec, ts_abs.tv_nsec);
	if ((errno = pthread_cond_timedwait(&bsm_cond_gotevent, &bsm_mutex_prefetcher, &ts_abs))) {
		pthread_mutex_unlock(&bsm_mutex_prefetcher);
		switch (errno) {
			case ETIMEDOUT:
#ifdef PARANOID
				critical_on (mondata->event_count);
#endif
				debug(2, "Timed out -> no events (mondata->event_count == %i)", mondata->event_count);
				return 0;
/*			case EINTR:
				debug(3, "pthread_cond_timedwait() -> EINTR. Restarting.");
				goto l_pthread_cond_timedwait_restart;*/
			default:
				critical("Got unhandled error on pthread_cond_timedwait()");
		}
	}

	pthread_mutex_unlock(&bsm_mutex_prefetcher);
/*#ifdef PARANOID
	critical_on (!mondata->event_count);
#endif*/

	debug(2, "%s. mondata->event_count == %i", mondata->event_count?"Got an event":"Got signal SIGUSR_BLOPINT", mondata->event_count);
	return mondata->event_count;
}
int bsm_handle_prefetched(struct ctx *ctx_p, struct indexes *indexes_p) {
	int count;
	debug(8, "");

	pthread_mutex_lock(&bsm_mutex_prefetcher);
	count = bsm_handle_allevents(ctx_p, indexes_p, BSM_HANDLE_ITERATE);
	pthread_mutex_unlock(&bsm_mutex_prefetcher);

	return count;
}
int bsm_wait_noprefetch(struct ctx *ctx_p, struct indexes *indexes_p, struct timeval *timeout_p) {
	debug(3, "(ctx_p, indexes_p, %p {%u, %u})", timeout_p, timeout_p == NULL?-1:timeout_p->tv_sec, timeout_p == NULL?0:timeout_p->tv_usec);
	mondata_t *mondata = ctx_p->fsmondata;
	struct timeval timeout_abs, tv_abs;
	struct bsm_event *event_p = mondata->event;

	if (timeout_p->tv_sec != 0 || timeout_p->tv_usec != 0) {
		gettimeofday(&tv_abs, NULL);
		timeradd(&tv_abs, timeout_p, &timeout_abs);
	}

	int pipe_fd = fileno(mondata->pipe);

	if (*event_p->path) {
		debug(2, "We already have an event. Return 1.");
		return 1;
	}

	if (bsm_fetch(ctx_p, indexes_p, mondata->event, pipe_fd, timeout_p, &timeout_abs) == 0) {
		debug(2, "No events. Return 0");
		return 0;
	}

	if (*event_p->path) {
		debug(2, "We have an event. Return 1.");
		return 1;
	}

	critical ("This code shouldn't be reached");
	return -1;
}
int bsm_handle_noprefetch(struct ctx *ctx_p, struct indexes *indexes_p) {
	debug(3, "");
	return bsm_handle_allevents(ctx_p, indexes_p, BSM_HANDLE_CALLWAIT);
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
	void *ret;
	int rc = 0;
	mondata_t *mondata = ctx_p->fsmondata;

	bsm_prefetcher_running = 0;
	pthread_kill(prefetcher_thread, SIGUSR_BLOPINT);
	pthread_cond_destroy (&bsm_cond_gotevent);
	pthread_mutex_destroy(&bsm_mutex_prefetcher);
	pthread_join(prefetcher_thread, &ret);

	rc |= fclose(mondata->pipe);

	rc |= bsm_config_revert(mondata);

	free(ctx_p->fsmondata);
	ctx_p->fsmondata = NULL;

	rc |= auditd_restart();

	return rc;
}

