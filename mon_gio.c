/*
    clsync - file tree sync utility based on inotify/kqueue/bsm/gio
    
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

// The "queue" is actually "stack" in this code. It's a lack of design of this code.

#include "common.h"
#include "error.h"
#include "sync.h"
#include "indexes.h"
#include "privileged.h"

#include <pthread.h>
#include <gio/gio.h>

#include "mon_gio.h"

struct filemondata {
	ctx_t		*ctx_p;
	GFile		*file;
	GFileMonitor	*filemon;
	gulong		 handle_id;
};
typedef struct filemondata filemondata_t;

struct event {
	char *path;
	gulong            handle_id;
	GFileMonitorEvent event_id;
	eventobjtype_t    objtype_event;
	eventobjtype_t    objtype_old;
	eventobjtype_t    objtype_new;
};
typedef struct event event_t;

GHashTable *mondirs_ht;
pthread_spinlock_t queue_lock;
pthread_mutex_t    gio_mutex_prefetcher = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t     gio_cond_gotevent    = PTHREAD_COND_INITIALIZER;
event_t *queue = NULL;
int queue_length;
int queue_alloc;

static inline void event_free(event_t *ev) {
	free(ev->path);
	return;
}

static inline int event_push(char *path, gulong handle_id, GFileMonitorEvent event, eventobjtype_t objtype_event, eventobjtype_t objtype_old, eventobjtype_t objtype_new) {
	event_t *ev;

	debug(30, "pthread_spin_lock(&queue_lock);");
	pthread_spin_lock(&queue_lock);

	if (queue_length >= queue_alloc) {
		queue_alloc += ALLOC_PORTION;
		critical_on (queue_alloc >= GIO_QUEUE_LENGTH_MAX);
		queue = xrealloc(queue, queue_alloc*sizeof(*queue));
	}

	ev = &queue[queue_length++];

	ev->path          = path;
	ev->event_id      = event;
	ev->handle_id     = handle_id;
	ev->objtype_event = objtype_event;
	ev->objtype_old   = objtype_old;
	ev->objtype_new   = objtype_new;

	debug(30, "pthread_spin_unlock(&queue_lock);");
	pthread_spin_unlock(&queue_lock);
	return 0;
}

static inline event_t *event_pop() {
	static event_t ev;

	debug(30, "pthread_spin_lock(&queue_lock);");
	pthread_spin_lock(&queue_lock);
	critical_on (!queue_length);
	memcpy(&ev, &queue[--queue_length], sizeof(ev));
	debug(30, "pthread_spin_unlock(&queue_lock);");
	pthread_spin_unlock(&queue_lock);

	return &ev;
}

static void dir_gotevent(
		GFileMonitor		*filemon,
		GFile			*file,
		GFile			*file_other,
		GFileMonitorEvent	 event,
		gpointer		 arg
) {
	eventobjtype_t objtype_old, objtype_new, objtype;
	filemondata_t *fmdat    = arg;
	ctx_t         *ctx_p    = fmdat->ctx_p;
	GFileType      filetype = g_file_query_file_type(file, G_FILE_QUERY_INFO_NOFOLLOW_SYMLINKS, NULL);
	debug(10, "%p %p %p %i %p %i", filemon, file, file_other, event, arg, filetype);

	char *path_full, *path_rel = NULL;
	switch (event) {
		case G_FILE_MONITOR_EVENT_DELETED:
		case G_FILE_MONITOR_EVENT_CREATED:
		case G_FILE_MONITOR_EVENT_CHANGED:
		case G_FILE_MONITOR_EVENT_ATTRIBUTE_CHANGED:
			path_full = g_file_get_path(file);
			path_rel  = strdup(&path_full[ctx_p->watchdirlen+1]);
			g_free(path_full);
			debug(9, "Got event %i for \"%s\" (%i)", event, path_rel, filetype);
			break;
		default:
			break;
	}

	switch (filetype) {
		case G_FILE_TYPE_DIRECTORY:
			objtype = EOT_DIR;
			break;
		default:
			objtype = EOT_FILE;
			break;
	}

	switch (event) {
		case G_FILE_MONITOR_EVENT_DELETED:
			objtype_old = objtype;
			objtype_new = EOT_DOESNTEXIST;
			break;
		case G_FILE_MONITOR_EVENT_CREATED:
			objtype_old = EOT_DOESNTEXIST;
			objtype_new = objtype;
			break;
		default:
			objtype_old = objtype;
			objtype_new = objtype;
			break;
	}

	switch (event) {
		case G_FILE_MONITOR_EVENT_DELETED:
			debug(20, "g_hash_table_remove(mondirs_ht, \"%s\")", path_rel);
			g_hash_table_remove(mondirs_ht, path_rel);
		case G_FILE_MONITOR_EVENT_CREATED:
		case G_FILE_MONITOR_EVENT_CHANGED:
		case G_FILE_MONITOR_EVENT_ATTRIBUTE_CHANGED:
#ifdef PARANOID
			critical_on (path_rel == NULL);
#endif

			debug(20, "event_push(\"%s\", %i, %i, %i, %i, %i)", path_rel, fmdat->handle_id, event, objtype, objtype_old, objtype_new);
			critical_on (event_push(path_rel, fmdat->handle_id, event, objtype, objtype_old, objtype_new));
			break;
		default:
			break;
	}

	return;
}

int gio_add_watch_dir(ctx_t *ctx_p, indexes_t *indexes_p, const char *const accpath) {
	(void) indexes_p;

	filemondata_t *fmdat;
	GError        *error = NULL;
	debug(3, "\"%s\"", accpath);

#ifdef PARANOID
	fmdat = g_hash_table_lookup(mondirs_ht, accpath);
	if (fmdat != NULL) {
		errno = EADDRINUSE;
		warning("Directory \"%s\" is already monitored.", accpath);
		return -1;
	}
#endif

	fmdat = xmalloc(sizeof(*fmdat));

	fmdat->ctx_p     = ctx_p;
	fmdat->file      = g_file_new_for_path(accpath);
	fmdat->filemon   = g_file_monitor_directory(fmdat->file, 0, NULL, &error);

	fmdat->handle_id = g_signal_connect (fmdat->filemon, "changed", G_CALLBACK(dir_gotevent), fmdat);

	g_hash_table_replace(mondirs_ht, strdup(accpath), fmdat);

	return fmdat->handle_id;
}

int cancel_g_iteration_stop;
pthread_t thread_g_iteration_stop;
void *g_iteration_stop(void *_timeout_p) {
	struct timeval *timeout_p = _timeout_p;
	struct timeval tv_abs, timeout_abs;
	struct timespec ts_abs;
	debug(10, "{%u, %u}", timeout_p->tv_sec, timeout_p->tv_usec);
	critical_on (pthread_mutex_lock(&gio_mutex_prefetcher));
	if (cancel_g_iteration_stop) {
		critical_on (pthread_mutex_unlock(&gio_mutex_prefetcher));
		return NULL;
	}

#define INFINITETIME (3600 * 24 * 365 * 10) /* ~10 years */
	if (timeout_p->tv_sec > INFINITETIME)
		timeout_p->tv_sec = INFINITETIME;
#undef INFINITETIME

	gettimeofday(&tv_abs, NULL);
	timeradd(&tv_abs, timeout_p, &timeout_abs);

	ts_abs.tv_sec  = timeout_abs.tv_sec;
	ts_abs.tv_nsec = timeout_abs.tv_usec*1000;
	debug(10, "{%u, %u}", ts_abs.tv_sec, ts_abs.tv_nsec);
	
	switch ((errno = pthread_cond_timedwait(&gio_cond_gotevent, &gio_mutex_prefetcher, &ts_abs))) {
		case 0:
		case ETIMEDOUT:
			break;
		default:
			critical ("Got error while pthread_cond_timedwait(&gio_cond_gotevent, &gio_mutex_prefetcher, &ts_abs)");
	}
	g_main_context_wakeup(NULL);
	pthread_mutex_unlock(&gio_mutex_prefetcher);

	debug(10, "return");
	return NULL;
}

static inline int gio_wait_now(ctx_t *ctx_p, struct indexes *indexes_p, struct timeval *tv_p) {
	(void) ctx_p; (void) indexes_p;

	void *ret;
	int result;
	debug(3, "(ctx_p, indexes_p, %p {%u, %u})", tv_p, tv_p == NULL?-1:tv_p->tv_sec, tv_p == NULL?0:tv_p->tv_usec);
#ifdef PARANOID
	critical_on (tv_p == NULL);
#endif

	if (queue_length) {
		debug(9, "already: queue_length == %i", queue_length);
		return queue_length;
	}

	if (tv_p->tv_sec == 0 && tv_p->tv_usec == 0) {
		g_main_context_iteration(NULL, FALSE);
		debug(9, "nowait: queue_length == %i", queue_length);
		return queue_length;
	}

	cancel_g_iteration_stop = 0;
	pthread_create(&thread_g_iteration_stop, NULL, g_iteration_stop, tv_p);
/*
	debug(30, "pthread_spin_unlock(&queue_lock);");
	pthread_spin_unlock(&queue_lock);
	debug(30 , "g_main_context_iteration(NULL, FALSE);");
	result  = g_main_context_iteration(NULL, FALSE);
	debug(30, "pthread_spin_lock(&queue_lock);");
	pthread_spin_lock(&queue_lock);

	if (queue_length) {
		debug(9, "already2: queue_length == %i", queue_length);
		return queue_length;
	}
*/
	debug_call  (40, pthread_spin_unlock(&queue_lock));
	debug(20 , "g_main_context_iteration(NULL, TRUE); queue_length == %i", queue_length);
	result  = g_main_context_iteration(NULL, TRUE);
	debug(10, "g_main_context_iteration() -> %i", result);
	debug_call  (40, pthread_spin_lock(&queue_lock));
	critical_on (pthread_mutex_lock(&gio_mutex_prefetcher));
	cancel_g_iteration_stop = 1;
	critical_on (pthread_mutex_unlock(&gio_mutex_prefetcher));
	critical_on (pthread_cond_broadcast(&gio_cond_gotevent));
	critical_on (pthread_join(thread_g_iteration_stop, &ret));

	debug(9, "queue_length == %i", queue_length);
	return queue_length;
}
int gio_wait(ctx_t *ctx_p, struct indexes *indexes_p, struct timeval *tv_p) {
	(void) ctx_p;

	int ret;

	debug(30, "pthread_spin_lock(&queue_lock);");
	debug_call (40, pthread_spin_lock(&queue_lock));
	ret = gio_wait_now(ctx_p, indexes_p, tv_p);
	debug(30, "pthread_spin_unlock(&queue_lock);");
	debug_call (40, pthread_spin_unlock(&queue_lock));

	return ret;
}

int gio_handle(ctx_t *ctx_p, indexes_t *indexes_p) {
	static struct timeval tv={0};
	int count;

	char   *path_full	 = NULL;
	size_t  path_full_len	 = 0;

	count = 0;
	while (gio_wait(ctx_p, indexes_p, &tv)) {
		event_t *ev = event_pop();
		stat64_t lstat, *lstat_p;
		mode_t st_mode;
		size_t st_size;
		if ((ev->objtype_new == EOT_DOESNTEXIST) || (ctx_p->flags[CANCEL_SYSCALLS]&CSC_MON_STAT) || lstat64(ev->path, &lstat)) {
			debug(2, "Cannot lstat64(\"%s\", lstat). Seems, that the object had been deleted (%i) or option \"--cancel-syscalls mon_stat\" (%i) is set.", ev->path, ev->objtype_new == EOT_DOESNTEXIST, ctx_p->flags[CANCEL_SYSCALLS]&CSC_MON_STAT);
			st_mode = (ev->objtype_event == EOT_DIR ? S_IFDIR : S_IFREG);
			st_size = 0;
			lstat_p = NULL;
		} else {
			st_mode = lstat.st_mode;
			st_size = lstat.st_size;
			lstat_p = &lstat;
		}

		if (sync_prequeue_loadmark(1, ctx_p, indexes_p, NULL, ev->path, lstat_p, ev->objtype_old, ev->objtype_new, ev->event_id, ev->handle_id, st_mode, st_size, &path_full, &path_full_len, NULL)) {
			event_free(ev);
			count = -1;
			break;
		}
		event_free(ev);
		count++;
	}
	// Globally queueing captured events:
	// Moving events from local queue to global ones
	sync_prequeue_unload(ctx_p, indexes_p);

	free(path_full);
#ifdef VERYPARANOID
	path_full     = NULL;
	path_full_len = 0;
#endif

	return count;
}

void free_filemondat(void *_fmdat) {
	filemondata_t *fmdat = _fmdat;

	g_signal_handler_disconnect(fmdat->file, fmdat->handle_id);

	free(fmdat->file);
	free(fmdat->filemon);

	free(fmdat);
	return;
}

GMainLoop *gio_loop = NULL;
int gio_init(ctx_t *ctx_p) {
	(void) ctx_p;

	queue_length = 0;
	queue_alloc  = 0;
	pthread_mutex_init (&gio_mutex_prefetcher, NULL);
	pthread_cond_init  (&gio_cond_gotevent,    NULL);
	pthread_spin_init  (&queue_lock,           PTHREAD_PROCESS_SHARED);
	mondirs_ht = g_hash_table_new_full(g_str_hash, g_str_equal, free, free_filemondat);
	gio_loop   = g_main_loop_new(NULL, TRUE);

	g_main_context_iteration(NULL, FALSE);
	return 0;
}

int gio_deinit(ctx_t *ctx_p) {
	(void) ctx_p;

/*
	g_main_loop_quit(gio_loop);
	g_hash_table_destroy  (mondirs_ht);
	pthread_spin_destroy  (&queue_lock);
	pthread_cond_destroy  (&gio_cond_gotevent);
	pthread_mutex_destroy (&gio_mutex_prefetcher);
*/
	return 0;
}

