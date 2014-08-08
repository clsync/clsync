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

#include "port-hacks.h"

#if KQUEUE_SUPPORT
#	include "mon_kqueue.h"
#endif
#if INOTIFY_SUPPORT
#	include "mon_inotify.h"
#endif
#if FANOTIFY_SUPPORT
#	include "mon_fanotify.h"
#endif
#if BSM_SUPPORT
#	include "mon_bsm.h"
#	include <bsm/audit_kevents.h>
#endif

#include "main.h"
#include "error.h"
#include "fileutils.h"
#include "malloc.h"
#include "cluster.h"
#include "sync.h"
#include "glibex.h"
#include "control.h"
#include "indexes.h"
#include "privileged.h"
#include "rules.h"

#include <stdio.h>
#include <dlfcn.h>


pthread_t pthread_sighandler;

// seqid - is a counter of main loop. But it may overflow and it's required to compare
// seqid-values anyway.
// So if (a-b) is too big, let's assume, that "b<a".
#define SEQID_WINDOW (((unsigned int)~0)>>1)
#define SEQID_EQ(a, b) ((a)==(b))
#define SEQID_GE(a, b) ((a)-(b) < SEQID_WINDOW)
#define SEQID_LE(a, b) ((b)-(a) < SEQID_WINDOW)
#define SEQID_GT(a, b) ((!SEQID_EQ(a, b)) && (SEQID_GE(a, b)))
#define SEQID_LT(a, b) ((!SEQID_EQ(a, b)) && (SEQID_LE(a, b)))
static unsigned int _sync_seqid_value=0;
static inline unsigned int sync_seqid() {
	return _sync_seqid_value++;
}


gpointer eidup(gpointer ei_gp) {
	eventinfo_t *ei = (eventinfo_t *)ei_gp;

	eventinfo_t *ei_dup = (eventinfo_t *)xmalloc(sizeof(*ei));
	memcpy(ei_dup, ei, sizeof(*ei));

	return (gpointer)ei_dup;
}

static inline void evinfo_merge(ctx_t *ctx_p, eventinfo_t *evinfo_dst, eventinfo_t *evinfo_src) {
	debug(3, "evinfo_dst: seqid_min == %u; seqid_max == %u; objtype_old == %i; objtype_new == %i; \t"
			"evinfo_src: seqid_min == %u; seqid_max == %u; objtype_old == %i; objtype_new == %i",
			evinfo_dst->seqid_min, evinfo_dst->seqid_max, evinfo_dst->objtype_old, evinfo_dst->objtype_new,
			evinfo_src->seqid_min, evinfo_src->seqid_max, evinfo_src->objtype_old, evinfo_src->objtype_new
		);

#if KQUEUE_SUPPORT | INOTIFY_SUPPORT
	switch(ctx_p->flags[MONITOR]) {
#ifdef KQUEUE_SUPPORT
		case NE_KQUEUE:
#endif
#ifdef INOTIFY_SUPPORT
		case NE_INOTIFY:
#endif
			evinfo_dst->evmask |= evinfo_src->evmask;
			break;
	}
#endif

	evinfo_dst->flags  |= evinfo_src->flags;

	if(SEQID_LE(evinfo_src->seqid_min, evinfo_dst->seqid_min)) {
		evinfo_dst->objtype_old = evinfo_src->objtype_old;
		evinfo_dst->seqid_min   = evinfo_src->seqid_min;
	}

	if(SEQID_GE(evinfo_src->seqid_max,  evinfo_dst->seqid_max))  {
		evinfo_dst->objtype_new = evinfo_src->objtype_new;
		evinfo_dst->seqid_max   = evinfo_src->seqid_max;
#ifdef BSM_SUPPORT
		switch(ctx_p->flags[MONITOR]) {
			case NE_BSM:
				evinfo_dst->evmask = evinfo_src->evmask;
				break;
		}
#endif
	}

	return;
}

static inline int _exitcode_process(ctx_t *ctx_p, int exitcode) {
	if (ctx_p->isignoredexitcode[(unsigned char)exitcode])
		return 0;

	if (exitcode && !((ctx_p->flags[MODE]==MODE_RSYNCDIRECT) && (exitcode == 24))) {
		error("Got non-zero exitcode %i from __sync_exec().", exitcode);
		return exitcode;
	}

	return 0;
}

int exitcode_process(ctx_t *ctx_p, int exitcode) {
	int err = _exitcode_process(ctx_p, exitcode);

	if(err) error("Got error-report from exitcode_process().\nExitcode is %i, strerror(%i) returns \"%s\". However strerror() is not ensures compliance "
			"between exitcode and error description for every utility. So, e.g if you're using rsync, you should look for the error description "
			"into rsync's manpage (\"man 1 rsync\"). Also some advices about diagnostics can be found in clsync's manpage (\"man 1 clsync\", see DIAGNOSTICS)", 
			exitcode, exitcode, strerror(exitcode));

	return err;
}


threadsinfo_t *thread_info() {	// TODO: optimize this
	static threadsinfo_t threadsinfo={{{{0}}},{{{0}}},0};
	if (!threadsinfo.mutex_init) {
		int i=0;
		while (i < PTHREAD_MUTEX_MAX) {
			if (pthread_mutex_init(&threadsinfo.mutex[i], NULL)) {
				error("Cannot pthread_mutex_init().");
				return NULL;
			}
			if (pthread_cond_init (&threadsinfo.cond [i], NULL)) {
				error("Cannot pthread_cond_init().");
				return NULL;
			}
			i++;
		}
		threadsinfo.mutex_init++;
	}

	return &threadsinfo;
}

#define thread_info_lock() _thread_info_lock(__FUNCTION__)
static inline threadsinfo_t *_thread_info_lock(const char *const function_name) {
	threadsinfo_t *threadsinfo_p = thread_info();

	debug(4, "used by %s()", function_name);
	pthread_mutex_lock  (&threadsinfo_p->mutex[PTHREAD_MUTEX_THREADSINFO]);

	return threadsinfo_p;
}

#define thread_info_unlock(...) _thread_info_unlock(__FUNCTION__, __VA_ARGS__)
static inline int _thread_info_unlock(const char *const function_name, int rc) {
	threadsinfo_t *threadsinfo_p = thread_info();

	debug(4, "used by %s()", function_name);
	pthread_mutex_unlock(&threadsinfo_p->mutex[PTHREAD_MUTEX_THREADSINFO]);

	return rc;
}

int threads_foreach(int (*funct)(threadinfo_t *, void *), state_t state, void *arg) {
	int i, rc;
	threadsinfo_t *threadsinfo_p = thread_info_lock();
#ifdef PARANOID
	if(threadsinfo_p == NULL)
		return thread_info_unlock(EINVAL);
#endif

	rc = 0;
	i  = 0;
	while (i < threadsinfo_p->used) {
		threadinfo_t *threadinfo_p = &threadsinfo_p->threads[i++];
		if ((state == STATE_UNKNOWN) || (threadinfo_p->state == state)) {
			if((rc=funct(threadinfo_p, arg)))
				break;
		}
	}

	return thread_info_unlock(rc);
}

time_t thread_nextexpiretime() {
	time_t nextexpiretime = 0;
	threadsinfo_t *threadsinfo_p = thread_info_lock();
#ifdef PARANOID
	if(threadsinfo_p == NULL)
		return thread_info_unlock(0);
#endif

	int thread_num = threadsinfo_p->used;

	while(thread_num--) {
		threadinfo_t *threadinfo_p = &threadsinfo_p->threads[thread_num];
		debug(3, "threadsinfo_p->threads[%i].state == %i;\tthreadsinfo_p->threads[%i].pthread == %p;\tthreadsinfo_p->threads[%i].expiretime == %i", 
			thread_num, threadinfo_p->state,thread_num, threadinfo_p->pthread, thread_num, threadinfo_p->expiretime);

		if(threadinfo_p->state == STATE_EXIT)
			continue;

		if(threadinfo_p->expiretime) {
			if(nextexpiretime)
				nextexpiretime = MIN(nextexpiretime, threadinfo_p->expiretime);
			else
				nextexpiretime = threadinfo_p->expiretime;
		}
	}

	thread_info_unlock(0);
	debug(3, "nextexpiretime == %i", nextexpiretime);
	return nextexpiretime;
}

threadinfo_t *thread_new() {
	threadsinfo_t *threadsinfo_p = thread_info_lock();
#ifdef PARANOID
	if(threadsinfo_p == NULL) {
		thread_info_unlock(0);
		return NULL;
	}
#endif

	int thread_num;
	threadinfo_t *threadinfo_p;

	if(threadsinfo_p->stacklen) {
		threadinfo_p = threadsinfo_p->threadsstack[--threadsinfo_p->stacklen];
		thread_num   =  threadinfo_p->thread_num;
	} else {
		if(threadsinfo_p->used >= threadsinfo_p->allocated) {
			threadsinfo_p->allocated += ALLOC_PORTION;
			debug(2, "Reallocated memory for threadsinfo -> %i.", threadsinfo_p->allocated);
			threadsinfo_p->threads      = (threadinfo_t *) xrealloc((char *)threadsinfo_p->threads, 
											sizeof(*threadsinfo_p->threads)     *(threadsinfo_p->allocated+2));
			threadsinfo_p->threadsstack = (threadinfo_t **)xrealloc((char *)threadsinfo_p->threadsstack,
											sizeof(*threadsinfo_p->threadsstack)*(threadsinfo_p->allocated+2));
		}

		thread_num = threadsinfo_p->used++;
		threadinfo_p = &threadsinfo_p->threads[thread_num];
	}

#ifdef PARANOID
	memset(threadinfo_p, 0, sizeof(*threadinfo_p));
#else
	threadinfo_p->expiretime = 0;
	threadinfo_p->errcode    = 0;
	threadinfo_p->exitcode   = 0;
#endif
	threadinfo_p->thread_num = thread_num;
	threadinfo_p->state	 = STATE_RUNNING;


	debug(2, "thread_new -> thread_num: %i; used: %i", thread_num, threadsinfo_p->used);
	thread_info_unlock(0);
	return threadinfo_p;
}

int thread_del_bynum(int thread_num) {
	debug(2, "thread_del_bynum(%i)", thread_num);
	threadsinfo_t *threadsinfo_p = thread_info_lock();
#ifdef PARANOID
	if(threadsinfo_p == NULL)
		return thread_info_unlock(errno);
#endif

	if(thread_num >= threadsinfo_p->used)
		return thread_info_unlock(EINVAL);

	threadinfo_t *threadinfo_p = &threadsinfo_p->threads[thread_num];
	threadinfo_p->state = STATE_EXIT;

	char **ptr = threadinfo_p->argv;
	if(ptr != NULL) {
		while(*ptr)
			free(*(ptr++));
		free(threadinfo_p->argv);
	}

	if(thread_num == (threadsinfo_p->used-1)) {
		threadsinfo_p->used--;
		debug(3, "thread_del_bynum(%i): there're %i threads left (#0).", thread_num, threadsinfo_p->used - threadsinfo_p->stacklen);
		return thread_info_unlock(0);
	}
	
	threadinfo_t *t = &threadsinfo_p->threads[threadsinfo_p->used-1];
	if(t->state == STATE_EXIT) {
		threadsinfo_p->used--;
		debug(3, "%i [%p] -> %i [%p]; left: %i", 
			threadsinfo_p->used, t->pthread, thread_num, threadinfo_p->pthread, threadsinfo_p->used - threadsinfo_p->stacklen);
		memcpy(threadinfo_p, t, sizeof(*threadinfo_p));
	} else {
#ifdef PARANOID
		if(threadsinfo_p->stacklen >= threadsinfo_p->allocated) {
			error("Threads metadata structures pointers stack overflowed!");
			return thread_info_unlock(EINVAL);
		}
#endif
		threadsinfo_p->threadsstack[threadsinfo_p->stacklen++] = threadinfo_p;
	}

	debug(3, "thread_del_bynum(%i): there're %i threads left (#1).", thread_num, threadsinfo_p->used - threadsinfo_p->stacklen);
	return thread_info_unlock(0);
}

int thread_gc(ctx_t *ctx_p) {
	int thread_num;
	time_t tm = time(NULL);
	debug(3, "tm == %i; thread %p", tm, pthread_self());
	if(!ctx_p->flags[THREADING])
		return 0;

	threadsinfo_t *threadsinfo_p = thread_info_lock();
#ifdef PARANOID
	if(threadsinfo_p == NULL)
		return thread_info_unlock(errno);
#endif

	debug(2, "There're %i threads.", threadsinfo_p->used);
	thread_num=-1;
	while(++thread_num < threadsinfo_p->used) {
		int err;
		threadinfo_t *threadinfo_p = &threadsinfo_p->threads[thread_num];

		debug(3, "Trying thread #%i (==%i) (state: %i; expire at: %i, now: %i, exitcode: %i, errcode: %i; i_p: %p; p: %p).", 
			thread_num, threadinfo_p->thread_num, threadinfo_p->state, threadinfo_p->expiretime, tm, threadinfo_p->exitcode, 
			threadinfo_p->errcode, threadinfo_p, threadinfo_p->pthread);

		if(threadinfo_p->state == STATE_EXIT)
			continue;

		if(threadinfo_p->expiretime && (threadinfo_p->expiretime <= tm)) {
			if(pthread_tryjoin_np(threadinfo_p->pthread, NULL)) {	// TODO: check this pthread_tryjoin_np() on error returnings
				error("Debug3: thread_gc(): Thread #%i is alive too long: %lu <= %lu (started at %lu)", thread_num, threadinfo_p->expiretime, tm, threadinfo_p->starttime);
				return thread_info_unlock(ETIME);
			}
		}

#ifndef VERYPARANOID
		if(threadinfo_p->state != STATE_TERM) {
			debug(3, "Thread #%i is busy, skipping (#0).", thread_num);
			continue;
		}
#endif


		debug(3, "Trying to join thread #%i: %p", thread_num, threadinfo_p->pthread);

#ifndef VERYPARANOID
		switch((err=pthread_join(threadinfo_p->pthread, NULL))) {
#else
		switch((err=pthread_tryjoin_np(threadinfo_p->pthread, NULL))) {
			case EBUSY:
				debug(3, "Thread #%i is busy, skipping (#1).", thread_num);
				continue;
#endif
			case EDEADLK:
			case EINVAL:
			case 0:
				debug(3, "Thread #%i is finished with exitcode %i (errcode %i), deleting. threadinfo_p == %p",
					thread_num, threadinfo_p->exitcode, threadinfo_p->errcode, threadinfo_p);
				break;
			default:
				error("Got error while pthread_join() or pthread_tryjoin_np().", strerror(err), err);
				return thread_info_unlock(errno);

		}

		if(threadinfo_p->errcode) {
			error("Got error from thread #%i: errcode %i.", thread_num, threadinfo_p->errcode);
			thread_del_bynum(thread_num);
			return thread_info_unlock(threadinfo_p->errcode);
		}

		thread_info_unlock(0);
		if(thread_del_bynum(thread_num))
			return errno;
		thread_info_lock();
	}

	debug(3, "There're %i threads left.", threadsinfo_p->used - threadsinfo_p->stacklen);
	return thread_info_unlock(0);
}

int thread_cleanup(ctx_t *ctx_p) {
	debug(3, "");
	threadsinfo_t *threadsinfo_p = thread_info_lock();

#ifdef PARANOID
	if(threadsinfo_p == NULL)
		return thread_info_unlock(errno);
#endif

	// Waiting for threads:
	debug(1, "There're %i opened threads. Waiting.", threadsinfo_p->used);
	while(threadsinfo_p->used) {
//		int err;
		threadinfo_t *threadinfo_p = &threadsinfo_p->threads[--threadsinfo_p->used];
		if(threadinfo_p->state == STATE_EXIT)
			continue;
		//pthread_kill(threadinfo_p->pthread, SIGTERM);
		debug(1, "killing pid %i with SIGTERM", threadinfo_p->child_pid);
		kill(threadinfo_p->child_pid, SIGTERM);
		pthread_join(threadinfo_p->pthread, NULL);
		debug(2, "thread #%i exitcode: %i", threadsinfo_p->used, threadinfo_p->exitcode);
/*
		if(threadinfo_p->callback)
			if((err=threadinfo_p->callback(ctx_p, threadinfo_p->argv)))
				warning("Got error from callback function.", strerror(err), err);
*/
		char **ptr = threadinfo_p->argv;
		while(*ptr)
			free(*(ptr++));
		free(threadinfo_p->argv);
	}
	debug(3, "All threads are closed.");

	// Freeing
	if(threadsinfo_p->allocated) {
		free(threadsinfo_p->threads);
		free(threadsinfo_p->threadsstack);
	}

	if(threadsinfo_p->mutex_init) {
		int i=0;
		while(i < PTHREAD_MUTEX_MAX) {
			pthread_mutex_destroy(&threadsinfo_p->mutex[i]);
			pthread_cond_destroy (&threadsinfo_p->cond [i]);
			i++;
		}
	}

#ifdef PARANOID
	// Reseting
	memset(threadsinfo_p, 0, sizeof(*threadsinfo_p));	// Just in case;
#endif

	debug(3, "done.");
	return thread_info_unlock(0);
}

state_t *state_p = NULL;
int exitcode = 0;
#define SHOULD_THREAD(ctx_p) ((ctx_p->flags[THREADING] != PM_OFF) && (ctx_p->flags[THREADING] != PM_SAFE || ctx_p->iteration_num))

int exec_argv(char **argv, int *child_pid) {
	debug(3, "Thread %p.", pthread_self());
	pid_t pid;
	int status;

	// Forking
	pid = privileged_fork_execvp(argv[0], (char *const *)argv);
//	debug(3, "After fork thread %p"")".", pthread_self() );
	debug(3, "Child pid is %u", pid);

	// Setting *child_pid value
	if (child_pid)
		*child_pid = pid;

	// Waiting for process end
#ifdef VERYPARANOID
	sigset_t sigset_exec, sigset_old;
	sigemptyset(&sigset_exec);
	sigaddset(&sigset_exec, SIGUSR_BLOPINT);
	pthread_sigmask(SIG_BLOCK, &sigset_exec, &sigset_old);
#endif

//	debug(3, "Pre-wait thread %p"")".", pthread_self() );
	if (waitpid(pid, &status, 0) != pid) {
		switch (errno) {
			case ECHILD:
				debug(2, "Child %u is already dead.", pid);
				break;
			default:
				error("Cannot waitid().");
				return errno;
		}
	}
//	debug(3, "After-wait thread %p"")".", pthread_self() );

#ifdef VERYPARANOID
	pthread_sigmask(SIG_SETMASK, &sigset_old, NULL);
#endif

	// Return
	int exitcode = WEXITSTATUS(status);
	debug(3, "execution completed with exitcode %i", exitcode);

	return exitcode;
}

static inline int thread_exit(threadinfo_t *threadinfo_p, int exitcode ) {
	int err=0;
	threadinfo_p->exitcode = exitcode;

#if _DEBUG_FORCE | VERYPARANOID
	if (threadinfo_p->pthread != pthread_self()) {
		error("pthread id mismatch! (i_p->p) %p != (p) %p""", threadinfo_p->pthread, pthread_self() );
		return EINVAL;
	}
#endif

	if (threadinfo_p->callback) {
		if (threadinfo_p->ctx_p->flags[DEBUG]>2) {
			debug(3, "thread %p, argv: ", threadinfo_p->pthread);
			char **argv = threadinfo_p->argv;
			while(*argv) {
				debug(3, "\t%p == %s", *argv, *argv);
				argv++;
			}
		}
		if ((err=threadinfo_p->callback(threadinfo_p->ctx_p, threadinfo_p->callback_arg))) {
			error("Got error from callback function.", strerror(err), err);
			threadinfo_p->errcode = err;
		}
	}

	// Notifying the parent-thread, that it's time to collect garbage threads
	threadinfo_p->state    = STATE_TERM;
	debug(3, "thread %p is sending signal to sighandler to call GC", threadinfo_p->pthread);
	return pthread_kill(pthread_sighandler, SIGUSR_THREAD_GC);
}

static inline void so_call_sync_finished(int n, api_eventinfo_t *ei) {
	int i = 0;
	api_eventinfo_t *ei_i = ei;
	while (i < n) {
#ifdef PARANOID
		if (ei_i->path == NULL) {
			warning("ei_i->path == NULL");
			i++;
			continue;
		}
#endif
		free((char *)ei_i->path);
		ei_i++;
		i++;
	}
	if (ei != NULL)
		free(ei);

	return;
}

int so_call_sync_thread(threadinfo_t *threadinfo_p) {
	debug(3, "thread_num == %i; threadinfo_p == %p; i_p->pthread %p; thread %p", 
			threadinfo_p->thread_num, threadinfo_p, threadinfo_p->pthread, pthread_self());

	ctx_t *ctx_p	= threadinfo_p->ctx_p;
	int n			= threadinfo_p->n;
	api_eventinfo_t *ei	= threadinfo_p->ei;

	int err=0, rc=0, try_again = 0;
	do {
		try_again = 0;
		threadinfo_p->try_n++;

		rc = ctx_p->handler_funct.sync(n, ei);

		if ((err=exitcode_process(threadinfo_p->ctx_p, rc))) {
			try_again = ((!ctx_p->retries) || (threadinfo_p->try_n < ctx_p->retries)) && (ctx_p->state != STATE_TERM) && (ctx_p->state != STATE_EXIT);
			warning("Bad exitcode %i (errcode %i). %s.", rc, err, try_again?"Retrying":"Give up");
			if (try_again) {
				debug(2, "Sleeping for %u seconds before the retry.", ctx_p->syncdelay);
				sleep(ctx_p->syncdelay);
			}
		}

	} while (err && ((!ctx_p->retries) || (threadinfo_p->try_n < ctx_p->retries)) && (ctx_p->state != STATE_TERM) && (ctx_p->state != STATE_EXIT));

	if (err && !ctx_p->flags[IGNOREFAILURES]) {
		error("Bad exitcode %i (errcode %i)", rc, err);
		threadinfo_p->errcode = err;
	}

	so_call_sync_finished(n, ei);

	if ((err=thread_exit(threadinfo_p, rc))) {
		exitcode = err;	// This's global variable "exitcode"
		pthread_kill(pthread_sighandler, SIGTERM);
	}

	return rc;
}

static inline int so_call_sync(ctx_t *ctx_p, indexes_t *indexes_p, int n, api_eventinfo_t *ei) {
	debug(2, "n == %i", n);

	if (!SHOULD_THREAD(ctx_p)) {
		int rc=0, ret=0, err=0;
		int try_n=0, try_again;
		state_t status = STATE_UNKNOWN;

//		indexes_p->nonthreaded_syncing_fpath2ei_ht = g_hash_table_dup(indexes_p->fpath2ei_ht, g_str_hash, g_str_equal, free, free, (gpointer(*)(gpointer))strdup, eidup);
		indexes_p->nonthreaded_syncing_fpath2ei_ht = indexes_p->fpath2ei_ht;

		do {
			try_again = 0;
			try_n++;

			alarm(ctx_p->synctimeout);
			rc = ctx_p->handler_funct.sync(n, ei);
			alarm(0);

			if ((err=exitcode_process(ctx_p, rc))) {
				if ((try_n == 1) && (ctx_p->state != STATE_TERM) && (ctx_p->state != STATE_EXIT)) {
					status = ctx_p->state;
					ctx_p->state = STATE_SYNCHANDLER_ERR;
					main_status_update(ctx_p);
				}

				try_again = ((!ctx_p->retries) || (try_n < ctx_p->retries)) && (ctx_p->state != STATE_TERM) && (ctx_p->state != STATE_EXIT);
				warning("Bad exitcode %i (errcode %i). %s.", rc, err, try_again?"Retrying":"Give up");
				if (try_again) {
					debug(2, "Sleeping for %u seconds before the retry.", ctx_p->syncdelay);
					sleep(ctx_p->syncdelay);
				}
			}
		} while (err && ((!ctx_p->retries) || (try_n < ctx_p->retries)) && (ctx_p->state != STATE_TERM) && (ctx_p->state != STATE_EXIT));
		if (err && !ctx_p->flags[IGNOREFAILURES]) {
			error("Bad exitcode %i (errcode %i)", rc, err);
			ret = err;
		} else
		if (status != STATE_UNKNOWN) {
			ctx_p->state = status;
			main_status_update(ctx_p);
		}

//		g_hash_table_destroy(indexes_p->nonthreaded_syncing_fpath2ei_ht);
		indexes_p->nonthreaded_syncing_fpath2ei_ht = NULL;

		so_call_sync_finished(n, ei);
		return ret;
	}

	threadinfo_t *threadinfo_p = thread_new();
	if (threadinfo_p == NULL)
		return errno;

	threadinfo_p->try_n       = 0;
	threadinfo_p->callback    = NULL;
	threadinfo_p->argv        = NULL;
	threadinfo_p->ctx_p       = ctx_p;
	threadinfo_p->starttime	  = time(NULL);
	threadinfo_p->fpath2ei_ht = g_hash_table_dup(indexes_p->fpath2ei_ht, g_str_hash, g_str_equal, free, free, (gpointer(*)(gpointer))strdup, eidup);
	threadinfo_p->n           = n;
	threadinfo_p->ei          = ei;
	threadinfo_p->iteration   = ctx_p->iteration_num;

	if (ctx_p->synctimeout)
		threadinfo_p->expiretime = threadinfo_p->starttime + ctx_p->synctimeout;

	if (pthread_create(&threadinfo_p->pthread, NULL, (void *(*)(void *))so_call_sync_thread, threadinfo_p)) {
		error("Cannot pthread_create().");
		return errno;
	}
	debug(3, "thread %p", threadinfo_p->pthread);
	return 0;

}

static inline int so_call_rsync_finished(ctx_t *ctx_p, const char *inclistfile, const char *exclistfile) {
	int ret0, ret1;
	debug(5, "");
	if (ctx_p->flags[DONTUNLINK]) 
		return 0;

	if (inclistfile == NULL) {
		error("inclistfile == NULL.");
		return EINVAL;
	}

	debug(3, "unlink()-ing \"%s\"", inclistfile);
	ret0 = unlink(inclistfile);

	if (ctx_p->flags[RSYNCPREFERINCLUDE])
		return ret0;

	if (exclistfile == NULL) {
		error("exclistfile == NULL.");
		return EINVAL;
	}

	debug(3, "unlink()-ing \"%s\"", exclistfile);
	ret1 = unlink(exclistfile);

	return ret0 == 0 ? ret1 : ret0;
}

int so_call_rsync_thread(threadinfo_t *threadinfo_p) {
	debug(3, "thread_num == %i; threadinfo_p == %p; i_p->pthread %p; thread %p", 
			threadinfo_p->thread_num, threadinfo_p, threadinfo_p->pthread, pthread_self());

	ctx_t *ctx_p	= threadinfo_p->ctx_p;
	char **argv		= threadinfo_p->argv;

	int err=0, rc=0, try_again;
	do {
		try_again=0;
		threadinfo_p->try_n++;

		rc = ctx_p->handler_funct.rsync(argv[0], argv[1]);
		if ((err=exitcode_process(threadinfo_p->ctx_p, rc))) {
			try_again = ((!ctx_p->retries) || (threadinfo_p->try_n < ctx_p->retries)) && (ctx_p->state != STATE_TERM) && (ctx_p->state != STATE_EXIT);
			warning("Bad exitcode %i (errcode %i). %s.", rc, err, try_again?"Retrying":"Give up");
			if (try_again) {
				debug(2, "Sleeping for %u seconds before the retry.", ctx_p->syncdelay);
				sleep(ctx_p->syncdelay);
			}
		}
	} while (try_again);

	if (err && !ctx_p->flags[IGNOREFAILURES]) {
		error("Bad exitcode %i (errcode %i)", rc, err);
		threadinfo_p->errcode = err;
	}

	if ((err=so_call_rsync_finished(ctx_p, argv[0], argv[1]))) {
		exitcode = err;	// This's global variable "exitcode"
		pthread_kill(pthread_sighandler, SIGTERM);
	}

	free(argv[0]);
	free(argv[1]);
	free(argv);

	if ((err=thread_exit(threadinfo_p, rc))) {
		exitcode = err;	// This's global variable "exitcode"
		pthread_kill(pthread_sighandler, SIGTERM);
	}

	return rc;
}

static inline int so_call_rsync(ctx_t *ctx_p, indexes_t *indexes_p, const char *inclistfile, const char *exclistfile) {
	debug(2, "inclistfile == \"%s\"; exclistfile == \"%s\"", inclistfile, exclistfile);

	if (!SHOULD_THREAD(ctx_p)) {
		debug(3, "ctx_p->handler_funct.rsync == %p", ctx_p->handler_funct.rsync);

//		indexes_p->nonthreaded_syncing_fpath2ei_ht = g_hash_table_dup(indexes_p->fpath2ei_ht, g_str_hash, g_str_equal, free, free, (gpointer(*)(gpointer))strdup, eidup);
		indexes_p->nonthreaded_syncing_fpath2ei_ht = indexes_p->fpath2ei_ht;

		int rc=0, err=0;
		int try_n=0, try_again;
		state_t status = STATE_UNKNOWN;
		do {
			try_again = 0;
			try_n++;

			alarm(ctx_p->synctimeout);
			rc = ctx_p->handler_funct.rsync(inclistfile, exclistfile);
			alarm(0);

			if ((err=exitcode_process(ctx_p, rc))) {
				if ((try_n == 1) && (ctx_p->state != STATE_TERM) && (ctx_p->state != STATE_EXIT)) {
					status = ctx_p->state;
					ctx_p->state = STATE_SYNCHANDLER_ERR;
					main_status_update(ctx_p);
				}
				try_again = ((!ctx_p->retries) || (try_n < ctx_p->retries)) && (ctx_p->state != STATE_TERM) && (ctx_p->state != STATE_EXIT);
				warning("Bad exitcode %i (errcode %i). %s.", rc, err, try_again?"Retrying":"Give up");
				if (try_again) {
					debug(2, "Sleeping for %u seconds before the retry.", ctx_p->syncdelay);
					sleep(ctx_p->syncdelay);
				}
			}
		} while (try_again);
		if (err && !ctx_p->flags[IGNOREFAILURES]) {
			error("Bad exitcode %i (errcode %i)", rc, err);
			rc = err;
		} else
		if (status != STATE_UNKNOWN) {
			ctx_p->state = status;
			main_status_update(ctx_p);
		}

//		g_hash_table_destroy(indexes_p->nonthreaded_syncing_fpath2ei_ht);
		indexes_p->nonthreaded_syncing_fpath2ei_ht = NULL;

		int ret_cleanup;
		if ((ret_cleanup=so_call_rsync_finished(ctx_p, inclistfile, exclistfile)))
			return rc ? rc : ret_cleanup;
		return rc;
	}

	threadinfo_t *threadinfo_p = thread_new();
	if(threadinfo_p == NULL)
		return errno;

	threadinfo_p->try_n       = 0;
	threadinfo_p->callback    = NULL;
	threadinfo_p->argv        = xmalloc(sizeof(char *) * 3);
	threadinfo_p->ctx_p       = ctx_p;
	threadinfo_p->starttime	  = time(NULL);
	threadinfo_p->fpath2ei_ht = g_hash_table_dup(indexes_p->fpath2ei_ht, g_str_hash, g_str_equal, free, free, (gpointer(*)(gpointer))strdup, eidup);
	threadinfo_p->iteration   = ctx_p->iteration_num;

	threadinfo_p->argv[0]	  = strdup(inclistfile);
	threadinfo_p->argv[1]	  = strdup(exclistfile);

	if(ctx_p->synctimeout)
		threadinfo_p->expiretime = threadinfo_p->starttime + ctx_p->synctimeout;

	if(pthread_create(&threadinfo_p->pthread, NULL, (void *(*)(void *))so_call_rsync_thread, threadinfo_p)) {
		error("Cannot pthread_create().");
		return errno;
	}
	debug(3, "thread %p", threadinfo_p->pthread);
	return 0;

}

// === SYNC_EXEC() === {

#define SYNC_EXEC(...)      (SHOULD_THREAD(ctx_p) ? sync_exec_thread      : sync_exec     )(__VA_ARGS__)
#define SYNC_EXEC_ARGV(...) (SHOULD_THREAD(ctx_p) ? sync_exec_argv_thread : sync_exec_argv)(__VA_ARGS__)

#define debug_argv_dump(level, argv)\
	if (unlikely(ctx_p->flags[DEBUG] >= level))\
		argv_dump(level, argv)

static inline void argv_dump(int debug_level, char **argv) {
#ifdef _DEBUG_FORCE
	debug(19, "(%u, %p)", debug_level, argv);
#endif
	char **argv_p = argv;
	while (*argv_p != NULL) {
		debug(debug_level, "%p: \"%s\"", *argv_p, *argv_p);
		argv_p++;
	}

	return;
}

#define _sync_exec_getargv(argv, firstarg, COPYARG) {\
	va_list arglist;\
	va_start(arglist, firstarg);\
\
	int i = 0;\
	do {\
		char *arg;\
		if(i >= MAXARGUMENTS) {\
			error("Too many arguments (%i >= %i).", i, MAXARGUMENTS);\
			return ENOMEM;\
		}\
		arg = (char *)va_arg(arglist, const char *const);\
		argv[i] = arg!=NULL ? COPYARG : NULL;\
	} while(argv[i++] != NULL);\
	va_end(arglist);\
}

char *sync_path_rel2abs(ctx_t *ctx_p, const char *path_rel, size_t path_rel_len, size_t *path_abs_len_p, char *path_abs_oldptr) {
	if (path_rel == NULL)
		return NULL;

	if (path_rel_len == -1)
		path_rel_len = strlen(path_rel);

	char  *path_abs;
	size_t watchdirlen = 
		(ctx_p->watchdir == ctx_p->watchdirwslash) ? 0 : ctx_p->watchdirlen;
		// if [watchdir == "/"] ? 0 : watchdir.length()

	size_t path_abs_len = path_rel_len + watchdirlen + 1;

	path_abs = (path_abs_len_p == NULL || path_abs_len >= *path_abs_len_p) ?
			xrealloc(path_abs_oldptr, path_abs_len+1) :
			path_abs_oldptr;

	if (path_abs_oldptr == NULL) {
		memcpy(path_abs, ctx_p->watchdir, watchdirlen);
		path_abs[watchdirlen] = '/';
	}
	memcpy(&path_abs[watchdirlen+1], path_rel, path_rel_len+1);

	if (path_abs_len_p != NULL)
		*path_abs_len_p = path_abs_len;

	return path_abs;
}

char *sync_path_abs2rel(ctx_t *ctx_p, const char *path_abs, size_t path_abs_len, size_t *path_rel_len_p, char *path_rel_oldptr) {
	if (path_abs == NULL)
		return NULL;

	if (path_abs_len == -1)
		path_abs_len = strlen(path_abs);

	size_t path_rel_len;
	char  *path_rel;
	size_t watchdirlen = 
		(ctx_p->watchdir == ctx_p->watchdirwslash) ? 0 : ctx_p->watchdirlen;

	signed long path_rel_len_signed = path_abs_len - (watchdirlen+1);

	path_rel_len = (path_rel_len_signed > 0) ? path_rel_len_signed : 0;

	path_rel = (path_rel_len_p == NULL || path_rel_len >= *path_rel_len_p) ? 
			xrealloc(path_rel_oldptr, path_rel_len+1) : 
			path_rel_oldptr;

	if (!path_rel_len) {
		path_rel[0] = 0;
		return path_rel;
	}

	memcpy(path_rel, &path_abs[watchdirlen+1], path_rel_len+1);

#ifdef VERYPARANOID
	// Removing "/" on the end
	debug(3, "\"%s\" (len: %i) --%i--> \"%s\" (len: %i) + ", 
		path_abs, path_abs_len, path_rel[path_rel_len - 1] == '/',
		ctx_p->watchdirwslash, watchdirlen+1);
	if(path_rel[path_rel_len - 1] == '/')
		path_rel[--path_rel_len] = 0x00;
	debug(3, "\"%s\" (len: %i)", path_rel, path_rel_len);
#endif

	if(path_rel_len_p != NULL)
		*path_rel_len_p = path_rel_len;

	return path_rel;
}

pid_t clsyncapi_fork(ctx_t *ctx_p) {
//	if(ctx_p->flags[THREADING])
//		return fork();

	// Cleaning stale pids. TODO: Optimize this. Remove this GC.
	int i=0;
	while(i < ctx_p->children) {
		if(waitpid(ctx_p->child_pid[i], NULL, WNOHANG)<0)
			if(errno==ECHILD)
				ctx_p->child_pid[i] = ctx_p->child_pid[--ctx_p->children];
		i++;
	}

	// Too many children
	if(ctx_p->children >= MAXCHILDREN) {
		errno = ECANCELED;
		return -1;
	}

	// Forking
	pid_t pid = fork();
	ctx_p->child_pid[ctx_p->children++] = pid;
	return pid;
}

int sync_exec_argv(ctx_t *ctx_p, indexes_t *indexes_p, thread_callbackfunct_t callback, thread_callbackfunct_arg_t *callback_arg_p, char **argv) {
	debug(2, "");

	debug_argv_dump(2, argv);

//	indexes_p->nonthreaded_syncing_fpath2ei_ht = g_hash_table_dup(indexes_p->fpath2ei_ht, g_str_hash, g_str_equal, free, free, (gpointer(*)(gpointer))strdup, eidup);
	indexes_p->nonthreaded_syncing_fpath2ei_ht = indexes_p->fpath2ei_ht;

	int exitcode=0, ret=0, err=0;
	int try_n=0, try_again;
	state_t status = STATE_UNKNOWN;
	do {
		try_again = 0;
		try_n++;
		debug(2, "try_n == %u (retries == %u)", try_n, ctx_p->retries);

		alarm(ctx_p->synctimeout);
		ctx_p->children = 1;
		exitcode = exec_argv(argv, ctx_p->child_pid );
		ctx_p->children = 0;
		alarm(0);

		if ((err=exitcode_process(ctx_p, exitcode))) {
			if ((try_n == 1) && (ctx_p->state != STATE_TERM) && (ctx_p->state != STATE_EXIT)) {
				status = ctx_p->state;
				ctx_p->state = STATE_SYNCHANDLER_ERR;
				main_status_update(ctx_p);
			}
			try_again = ((!ctx_p->retries) || (try_n < ctx_p->retries)) && (ctx_p->state != STATE_TERM) && (ctx_p->state != STATE_EXIT);
			warning("Bad exitcode %i (errcode %i). %s.", exitcode, err, try_again?"Retrying":"Give up");
			if (try_again) {
				debug(2, "Sleeping for %u seconds before the retry.", ctx_p->syncdelay);
				sleep(ctx_p->syncdelay);
			}
		}
	} while(try_again);

	if (err && !ctx_p->flags[IGNOREFAILURES]) {
		error("Bad exitcode %i (errcode %i)", exitcode, err);
		ret = err;
	} else
	if (status != STATE_UNKNOWN) {
		ctx_p->state = status;
		main_status_update(ctx_p);
	}

	if (callback != NULL) {
		int nret = callback(ctx_p, callback_arg_p);
		if (nret) {
			error("Got error while callback().");
			if (!ret) ret=nret;
		}
	}

//	g_hash_table_destroy(indexes_p->nonthreaded_syncing_fpath2ei_ht);
	indexes_p->nonthreaded_syncing_fpath2ei_ht = NULL;
	return ret;
}

static inline int sync_exec(ctx_t *ctx_p, indexes_t *indexes_p, thread_callbackfunct_t callback, thread_callbackfunct_arg_t *callback_arg_p, ...) {
	int rc;
	debug(2, "");

	char **argv = (char **)xcalloc(sizeof(char *), MAXARGUMENTS);
	memset(argv, 0, sizeof(char *)*MAXARGUMENTS);

	_sync_exec_getargv(argv, callback_arg_p, arg);

	rc = sync_exec_argv(ctx_p, indexes_p, callback, callback_arg_p, argv);
	free(argv);
	return rc;
}

int __sync_exec_thread(threadinfo_t *threadinfo_p) {
	char **argv		= threadinfo_p->argv;
	ctx_t *ctx_p		= threadinfo_p->ctx_p;

	debug(3, "thread_num == %i; threadinfo_p == %p; i_p->pthread %p; thread %p""", 
			threadinfo_p->thread_num, threadinfo_p, threadinfo_p->pthread, pthread_self() );

	int err=0, exec_exitcode=0, try_again;
	do {
		try_again = 0;
		threadinfo_p->try_n++;

		exec_exitcode = exec_argv(argv, &threadinfo_p->child_pid );

		if ((err=exitcode_process(threadinfo_p->ctx_p, exec_exitcode))) {
			try_again = ((!ctx_p->retries) || (threadinfo_p->try_n < ctx_p->retries)) && (ctx_p->state != STATE_TERM) && (ctx_p->state != STATE_EXIT);
			warning("__sync_exec_thread(): Bad exitcode %i (errcode %i). %s.", exec_exitcode, err, try_again?"Retrying":"Give up");
			if (try_again) {
				debug(2, "Sleeping for %u seconds before the retry.", ctx_p->syncdelay);
				sleep(ctx_p->syncdelay);
			}
		}

	} while (try_again);

	if (err && !ctx_p->flags[IGNOREFAILURES]) {
		error("Bad exitcode %i (errcode %i)", exec_exitcode, err);
		threadinfo_p->errcode = err;
	}

	g_hash_table_destroy(threadinfo_p->fpath2ei_ht);

	if ((err=thread_exit(threadinfo_p, exec_exitcode))) {
		exitcode = err;	// This's global variable "exitcode"
		pthread_kill(pthread_sighandler, SIGTERM);
	}

	debug(3, "thread_num == %i; threadinfo_p == %p; i_p->pthread %p; thread %p""; errcode %i", 
			threadinfo_p->thread_num, threadinfo_p, threadinfo_p->pthread, pthread_self(),  threadinfo_p->errcode);
	return exec_exitcode;
}

static inline int sync_exec_argv_thread(ctx_t *ctx_p, indexes_t *indexes_p, thread_callbackfunct_t callback, thread_callbackfunct_arg_t *callback_arg_p, char **argv) {
	debug(2, "");

	debug_argv_dump(2, argv);

	threadinfo_t *threadinfo_p = thread_new();
	if (threadinfo_p == NULL)
		return errno;

	threadinfo_p->try_n        = 0;
	threadinfo_p->callback     = callback;
	threadinfo_p->callback_arg = callback_arg_p;
	threadinfo_p->argv         = argv;
	threadinfo_p->ctx_p        = ctx_p;
	threadinfo_p->starttime	   = time(NULL);
	threadinfo_p->fpath2ei_ht  = g_hash_table_dup(indexes_p->fpath2ei_ht, g_str_hash, g_str_equal, free, free, (gpointer(*)(gpointer))strdup, eidup);
	threadinfo_p->iteration    = ctx_p->iteration_num;

	if (ctx_p->synctimeout)
		threadinfo_p->expiretime = threadinfo_p->starttime + ctx_p->synctimeout;

	if (pthread_create(&threadinfo_p->pthread, NULL, (void *(*)(void *))__sync_exec_thread, threadinfo_p)) {
		error("Cannot pthread_create().");
		return errno;
	}
	debug(3, "thread %p", threadinfo_p->pthread);
	return 0;
}

static inline int sync_exec_thread(ctx_t *ctx_p, indexes_t *indexes_p, thread_callbackfunct_t callback, thread_callbackfunct_arg_t *callback_arg_p, ...) {
	debug(2, "");

	char **argv = (char **)xcalloc(sizeof(char *), MAXARGUMENTS);
	memset(argv, 0, sizeof(char *)*MAXARGUMENTS);

	_sync_exec_getargv(argv, callback_arg_p, strdup(arg));

	return sync_exec_argv_thread(ctx_p, indexes_p, callback, callback_arg_p, argv);
}

// } === SYNC_EXEC() ===

static int sync_queuesync(const char *fpath_rel, eventinfo_t *evinfo, ctx_t *ctx_p, indexes_t *indexes_p, queue_id_t queue_id) {

	debug(3, "sync_queuesync(\"%s\", ...): fsize == %lu; tres == %lu, queue_id == %u", fpath_rel, evinfo->fsize, ctx_p->bfilethreshold, queue_id);
	if(queue_id == QUEUE_AUTO)
		queue_id = (evinfo->fsize > ctx_p->bfilethreshold) ? QUEUE_BIGFILE : QUEUE_NORMAL;

	queueinfo_t *queueinfo = &ctx_p->_queues[queue_id];

	if(!queueinfo->stime)
		queueinfo->stime = time(NULL);

//	char *fpath_rel = sync_path_abs2rel(ctx_p, fpath, -1, NULL, NULL);

	// Filename can contain "" character that conflicts with event-row separator of list-files.
	if(strchr(fpath_rel, '\n')) {
		// At the moment, we will just ignore events of such files :(
		debug(3, "There's \"\\n\" character in path \"%s\". Ignoring it :(. Feedback to: https://github.com/xaionaro/clsync/issues/12", fpath_rel);
		return 0;
	}

#ifdef CLUSTER_SUPPORT
	if(ctx_p->cluster_iface)
		cluster_capture(fpath_rel);
#endif

	eventinfo_t *evinfo_q   = indexes_lookupinqueue(indexes_p, fpath_rel, queue_id);
	if(evinfo_q == NULL) {
		eventinfo_t *evinfo_dup = (eventinfo_t *)xmalloc(sizeof(*evinfo_dup));
		memcpy(evinfo_dup, evinfo, sizeof(*evinfo_dup));
		return indexes_queueevent(indexes_p, strdup(fpath_rel), evinfo_dup, queue_id);
	} else {
		evinfo_merge(ctx_p, evinfo_q, evinfo);
	}

	return 0;
}

static inline void evinfo_initialevmask(ctx_t *ctx_p, eventinfo_t *evinfo_p, int isdir) {
	switch(ctx_p->flags[MONITOR]) {
#ifdef FANOTIFY_SUPPORT
		case NE_FANOTIFY:
			critical("fanotify is not supported");
			break;
#endif
#if INOTIFY_SUPPORT | KQUEUE_SUPPORT
#ifdef INOTIFY_SUPPORT
		case NE_INOTIFY:
#endif
#ifdef KQUEUE_SUPPORT
		case NE_KQUEUE:
#endif
			evinfo_p->evmask = IN_CREATE_SELF;
			if (isdir)
				evinfo_p->evmask |= IN_ISDIR;
			break;
#endif
#ifdef BSM_SUPPORT
		case NE_BSM:
			evinfo_p->evmask = (isdir ? AUE_MKDIR : AUE_OPEN_RWC);
			break;
#endif
#ifdef VERYPARANOID
		default:
			critical("Unknown monitor subsystem: %u", ctx_p->flags[MONITOR]);
#endif
	}
	return;
}

static inline void api_evinfo_initialevmask(ctx_t *ctx_p, api_eventinfo_t *evinfo_p, int isdir) {
	eventinfo_t evinfo = {0};
	evinfo_initialevmask(ctx_p, &evinfo, isdir);
	evinfo_p->evmask = evinfo.evmask;
	return;
}

int sync_dosync(const char *fpath, uint32_t evmask, ctx_t *ctx_p, indexes_t *indexes_p);
int sync_initialsync_walk(ctx_t *ctx_p, const char *dirpath, indexes_t *indexes_p, queue_id_t queue_id, initsync_t initsync) {
	int ret = 0;
	const char *rootpaths[] = {dirpath, NULL};
	eventinfo_t evinfo;
	FTS *tree;
	rule_t *rules_p = ctx_p->rules;
	debug(2, "(ctx_p, \"%s\", indexes_p, %i, %i).", dirpath, queue_id, initsync);

	char skip_rules = (initsync==INITSYNC_FULL) && ctx_p->flags[INITFULL];

	char rsync_and_prefer_excludes =
			(
				(ctx_p->flags[MODE]==MODE_RSYNCDIRECT) ||
				(ctx_p->flags[MODE]==MODE_RSYNCSHELL)  ||
				(ctx_p->flags[MODE]==MODE_RSYNCSO)
			) && 
			!ctx_p->flags[RSYNCPREFERINCLUDE];

	if ((!ctx_p->flags[RSYNCPREFERINCLUDE]) && skip_rules)
		return 0;

	skip_rules |= (ctx_p->rules_count == 0);

	char fts_no_stat = (initsync==INITSYNC_FULL) && !(ctx_p->flags[EXCLUDEMOUNTPOINTS]);

	int fts_opts =  FTS_NOCHDIR | FTS_PHYSICAL | 
			(fts_no_stat			? FTS_NOSTAT	: 0) | 
			(ctx_p->flags[ONEFILESYSTEM] 	? FTS_XDEV	: 0); 

        debug(3, "fts_opts == %p", (void *)(long)fts_opts);

	tree = privileged_fts_open((char *const *)&rootpaths, fts_opts, NULL, PC_SYNC_INIIALSYNC_WALK_FTS_OPEN);

	if (tree == NULL) {
		error("Cannot privileged_fts_open() on \"%s\".", dirpath);
		return errno;
	}

	memset(&evinfo, 0, sizeof(evinfo));

	FTSENT *node;
	char  *path_rel		= NULL;
	size_t path_rel_len	= 0;

	while ((node = privileged_fts_read(tree, PC_SYNC_INIIALSYNC_WALK_FTS_READ))) {
		switch (node->fts_info) {
			// Duplicates:
			case FTS_DP:
				continue;
			// To sync:
			case FTS_DEFAULT:
			case FTS_SL:
			case FTS_SLNONE:
			case FTS_F:
			case FTS_D:
			case FTS_DOT:
                        case FTS_DC:    // TODO: think about case of FTS_DC
                        case FTS_NSOK:
				break;
			// Error cases:
			case FTS_ERR:
			case FTS_NS:
			case FTS_DNR: {
				int fts_errno = node->fts_errno;

				if (fts_errno == ENOENT) {
					debug(1, "Got error while privileged_fts_read(): %s (errno: %i; fts_info: %i).", strerror(fts_errno), fts_errno, node->fts_info);
					continue;
				} else {
					error("Got error while privileged_fts_read(): %s (errno: %i; fts_info: %i).", strerror(fts_errno), fts_errno, node->fts_info);
					ret = node->fts_errno;
					goto l_sync_initialsync_walk_end;
				}
			}
			default:

				error("Got unknown fts_info vlaue while privileged_fts_read(): %i.", node->fts_info);
				ret = EINVAL;
				goto l_sync_initialsync_walk_end;
		}
		path_rel = sync_path_abs2rel(ctx_p, node->fts_path, -1, &path_rel_len, path_rel);

		debug(3, "Pointing to \"%s\" (node->fts_info == %i)", path_rel, node->fts_info);

		if (ctx_p->flags[EXCLUDEMOUNTPOINTS] && node->fts_info==FTS_D) {
			if (rsync_and_prefer_excludes) {
				if (node->fts_statp->st_dev != ctx_p->st_dev) {
					if (queue_id == QUEUE_AUTO) {
						int i=0;
						while (i<QUEUE_MAX)
							indexes_addexclude(indexes_p, strdup(path_rel), EVIF_CONTENTRECURSIVELY, i++);
					} else
						indexes_addexclude(indexes_p, strdup(path_rel), EVIF_CONTENTRECURSIVELY, queue_id);
				}
			} else
			if (!ctx_p->flags[RSYNCPREFERINCLUDE])
				error("Excluding mount points is not implentemted for non \"rsync*\" modes.");
		}

		mode_t st_mode = fts_no_stat ? (node->fts_info==FTS_D ? S_IFDIR : S_IFREG) : node->fts_statp->st_mode;

		if (!skip_rules) {
			ruleaction_t perm = rules_getperm(path_rel, st_mode, rules_p, RA_WALK|RA_MONITOR);

			if (!(perm&RA_WALK)) {
				debug(3, "Rejecting to walk into \"%s\".", path_rel);
				fts_set(tree, node, FTS_SKIP);
			} else

			if (!(perm&RA_MONITOR)) {
				debug(3, "Excluding \"%s\".", path_rel);
				if (rsync_and_prefer_excludes) {
					if (queue_id == QUEUE_AUTO) {
						int i=0;
						while (i<QUEUE_MAX)
							indexes_addexclude(indexes_p, strdup(path_rel), EVIF_NONE, i++);
					} else
						indexes_addexclude(indexes_p, strdup(path_rel), EVIF_NONE, queue_id);
				}
				continue;
			}
		}

		if (!rsync_and_prefer_excludes) {
			evinfo_initialevmask(ctx_p, &evinfo, node->fts_info==FTS_D);

			switch (ctx_p->flags[MODE]) {
				case MODE_SIMPLE:
					sync_dosync(node->fts_path, evinfo.evmask, ctx_p, indexes_p);
					continue;
				default:
					break;
			}

			evinfo.seqid_min    = sync_seqid();
			evinfo.seqid_max    = evinfo.seqid_min;
			evinfo.objtype_old  = EOT_DOESNTEXIST;
			evinfo.objtype_new  = node->fts_info==FTS_D ? EOT_DIR : EOT_FILE;
			evinfo.fsize        = fts_no_stat ? 0 : node->fts_statp->st_size;
			debug(3, "queueing \"%s\" (depth: %i) with int-flags %p", node->fts_path, node->fts_level, (void *)(unsigned long)evinfo.flags);
			int _ret = sync_queuesync(path_rel, &evinfo, ctx_p, indexes_p, queue_id);

			if (_ret) {
				error("Got error while queueing \"%s\".", node->fts_path);
				ret = errno;
				goto l_sync_initialsync_walk_end;
			}
			continue;
		}

		/* "FTS optimization" */
		if (
			skip_rules					&&
			node->fts_info == FTS_D				&&
			!ctx_p->flags[EXCLUDEMOUNTPOINTS]
		) {
			debug(4, "\"FTS optimizator\"");
			fts_set(tree, node, FTS_SKIP);
		}
	}
	if (errno) {
		error("Got error while privileged_fts_read() and related routines.");
		ret = errno;
		goto l_sync_initialsync_walk_end;
	}

	if (privileged_fts_close(tree, PC_SYNC_INIIALSYNC_WALK_FTS_CLOSE)) {
		error("Got error while privileged_fts_close().");
		ret = errno;
		goto l_sync_initialsync_walk_end;
	}

l_sync_initialsync_walk_end:
	if (path_rel != NULL)
		free(path_rel);
	return ret;
}

const char *sync_parameter_get(const char *variable_name, void *_dosync_arg_p) {
	struct dosync_arg *dosync_arg_p = _dosync_arg_p;
	ctx_t *ctx_p = dosync_arg_p->ctx_p;

#ifdef _DEBUG_FORCE
	debug(15, "(\"%s\", %p): 0x%x, \"%s\"", variable_name, _dosync_arg_p, ctx_p == NULL ? 0 : ctx_p->synchandler_argf, dosync_arg_p->evmask_str);
#endif

	if ((ctx_p == NULL || (ctx_p->synchandler_argf & SHFL_INCLUDE_LIST_PATH)) && !strcmp(variable_name, "INCLUDE-LIST-PATH"))
		return dosync_arg_p->outf_path;
	else
	if ((ctx_p == NULL || (ctx_p->synchandler_argf & SHFL_EXCLUDE_LIST_PATH)) && !strcmp(variable_name, "EXCLUDE-LIST-PATH"))
		return dosync_arg_p->excf_path;
	else
	if (!strcmp(variable_name, "TYPE"))
		return dosync_arg_p->list_type_str;
	else
	if (!strcmp(variable_name, "EVENT-MASK"))
		return dosync_arg_p->evmask_str;

	errno = ENOENT;
	return NULL;
}

static char **sync_customargv(ctx_t *ctx_p, struct dosync_arg *dosync_arg_p, synchandler_args_t *args_p) {
	int d, s;
	char **argv = (char **)xcalloc(sizeof(char *), MAXARGUMENTS+2);

	s = d = 0;

	argv[d++] = strdup(ctx_p->handlerfpath);
	while (s < args_p->c) {
		char *arg        = args_p->v[s];
		char  isexpanded = args_p->isexpanded[s];
		s++;
#ifdef _DEBUG_FORCE
		debug(30, "\"%s\" [%p]", arg, arg);
#endif

		if (isexpanded) {
#ifdef _DEBUG_FORCE
			debug(19, "\"%s\" [%p] is already expanded, just strdup()-ing it", arg, arg);
#endif
			argv[d++] = strdup(arg);
			continue;
		}

		if (!strcmp(arg, "%INCLUDE-LIST%")) {
			int i = 0,              e = dosync_arg_p->include_list_count;
			const char **include_list = dosync_arg_p->include_list;
#ifdef _DEBUG_FORCE
			debug(19, "INCLUDE-LIST: e == %u; d,s: %u,%u", e, d, s);
#endif
			while (i < e) {
#ifdef PARANOID
				if (d >= MAXARGUMENTS) {
					errno = E2BIG;
					critical("Too many arguments");
				}
#endif
				argv[d++] = parameter_expand(ctx_p, strdup(include_list[i++]), 0, NULL, NULL, sync_parameter_get, dosync_arg_p);
#ifdef _DEBUG_FORCE
				debug(19, "include-list: argv[%u] == %p", d-1, argv[d-1]);
#endif
			}
			continue;
		}

#ifdef PARANOID
		if (d >= MAXARGUMENTS) {
			errno = E2BIG;
			critical("Too many arguments");
		}
#endif

		argv[d] = parameter_expand(ctx_p, strdup(arg), 0, NULL, NULL, sync_parameter_get, dosync_arg_p);
#ifdef _DEBUG_FORCE
		debug(19, "argv[%u] == %p \"%s\"", d, argv[d], argv[d]);
#endif
		d++;
	}
	argv[d]   = NULL;

#ifdef _DEBUG_FORCE
	debug(18, "return %p", argv);
#endif
	return argv;
}

static void argv_free(char **argv) {
	char **argv_p;
#ifdef _DEBUG_FORCE
	debug(18, "(%p)", argv);
#endif
#ifdef VERYPARANOID
	if (argv == NULL)
		critical(MSG_SECURITY_PROBLEM);
#endif
	argv_p = argv;
	while (*argv_p != NULL) {
#ifdef _DEBUG_FORCE
		debug(25, "free(%p)", *argv_p);
#endif
		free(*(argv_p++));
	}

	free(argv);
	return;
}

static inline int sync_initialsync_cleanup(ctx_t *ctx_p, initsync_t initsync, int ret) {
	return ret;
}

int sync_initialsync(const char *path, ctx_t *ctx_p, indexes_t *indexes_p, initsync_t initsync) {
	int ret;
	queue_id_t queue_id;
	debug(3, "(\"%s\", ctx_p, indexes_p, %i)", path, initsync);

#ifdef CLUSTER_SUPPORT
	if(initsync == INITSYNC_FULL) {
		if(ctx_p->cluster_iface)
			return cluster_initialsync();
	}
#endif

	if (initsync == INITSYNC_FULL)
		queue_id = QUEUE_INSTANT;
	else
		queue_id = QUEUE_NORMAL;

	// non-RSYNC case:
	if(
		!(
			(ctx_p->flags[MODE]==MODE_RSYNCDIRECT)	||
			(ctx_p->flags[MODE]==MODE_RSYNCSHELL)	||
			(ctx_p->flags[MODE]==MODE_RSYNCSO)
		)
	) {
		debug(3, "syncing \"%s\"", path);

		if(ctx_p->flags[HAVERECURSIVESYNC]) {
			if(ctx_p->flags[MODE] == MODE_SO) {
				api_eventinfo_t *ei = (api_eventinfo_t *)xmalloc(sizeof(*ei));
#ifdef PARANIOD
				memset(ei, 0, sizeof(*ei));
#endif

				api_evinfo_initialevmask(ctx_p, ei, 1);
				ei->flags       = EVIF_RECURSIVELY;
				ei->path_len    = strlen(path);
				ei->path        = strdup(path);
				ei->objtype_old = EOT_DOESNTEXIST;
				ei->objtype_new = EOT_DIR;

				ret = so_call_sync(ctx_p, indexes_p, 1, ei);
				return sync_initialsync_cleanup(ctx_p, initsync, ret);
			} else {

				struct dosync_arg dosync_arg;
				synchandler_args_t *args_p;

				args_p = ctx_p->synchandler_args[SHARGS_INITIAL].c ?
						&ctx_p->synchandler_args[SHARGS_INITIAL] :
						&ctx_p->synchandler_args[SHARGS_PRIMARY];

				 dosync_arg.ctx_p	       = ctx_p;
				*dosync_arg.include_list       = path;
				 dosync_arg.include_list_count = 1;
				 dosync_arg.list_type_str      = "initialsync";
				char **argv = sync_customargv(ctx_p, &dosync_arg, args_p);
				ret = SYNC_EXEC_ARGV(
					ctx_p,
					indexes_p,
					NULL,
					NULL,
					argv);

				if (!SHOULD_THREAD(ctx_p))	// If it's a thread then it will free the argv in GC. If not a thread then we have to free right here.
					argv_free(argv);

				return sync_initialsync_cleanup(ctx_p, initsync, ret);
			}
		}
#ifdef DOXYGEN
		sync_exec_argv(NULL, NULL); sync_exec_argv_thread(NULL, NULL);
#endif

		ret = sync_initialsync_walk(ctx_p, path, indexes_p, queue_id, initsync);
		if(ret)
			error("Cannot get synclist");

		return sync_initialsync_cleanup(ctx_p, initsync, ret);
	}

	// RSYNC case:

	if(!ctx_p->flags[RSYNCPREFERINCLUDE]) {
		queueinfo_t *queueinfo = &ctx_p->_queues[queue_id];

		if(!queueinfo->stime)
			queueinfo->stime = time(NULL); // Useful for debugging


		eventinfo_t *evinfo = (eventinfo_t *)xmalloc(sizeof(*evinfo));
		memset(evinfo, 0, sizeof(*evinfo));
		evinfo->flags |= EVIF_RECURSIVELY;
		evinfo->seqid_min = sync_seqid();
		evinfo->seqid_max = evinfo->seqid_min;
		evinfo->objtype_old  = EOT_DOESNTEXIST;
		evinfo->objtype_new  = EOT_DIR;

		// Searching for excludes
		ret = sync_initialsync_walk(ctx_p, path, indexes_p, queue_id, initsync);
		if(ret) {
			error("Cannot get exclude what to exclude");
			return sync_initialsync_cleanup(ctx_p, initsync, ret);
		}

		debug(3, "queueing \"%s\" with int-flags %p", path, (void *)(unsigned long)evinfo->flags);

		char *path_rel = sync_path_abs2rel(ctx_p, path, -1, NULL, NULL);

		ret = indexes_queueevent(indexes_p, path_rel, evinfo, queue_id);
		return sync_initialsync_cleanup(ctx_p, initsync, ret);
	}

	// Searching for includes
	ret = sync_initialsync_walk(ctx_p, path, indexes_p, queue_id, initsync);
	return sync_initialsync_cleanup(ctx_p, initsync, ret);
}

int sync_notify_mark(ctx_t *ctx_p, const char *accpath, const char *path, size_t pathlen, indexes_t *indexes_p) {
	debug(3, "(..., \"%s\", %i,...)", path, pathlen);
	int wd = indexes_fpath2wd(indexes_p, path);
	if(wd != -1) {
		debug(1, "\"%s\" is already marked (wd: %i). Skipping.", path, wd);
		return wd;
	}

	debug(5, "ctx_p->notifyenginefunct.add_watch_dir(ctx_p, indexes_p, \"%s\")", accpath);
	if((wd = ctx_p->notifyenginefunct.add_watch_dir(ctx_p, indexes_p, accpath)) == -1) {
		if(errno == ENOENT)
			return -2;

		error("Cannot ctx_p->notifyenginefunct.add_watch_dir() on \"%s\".", 
			path);
		return -1;
	}
	debug(6, "endof ctx_p->notifyenginefunct.add_watch_dir(ctx_p, indexes_p, \"%s\")", accpath);
	indexes_add_wd(indexes_p, wd, path, pathlen);

	return wd;
}

#ifdef CLUSTER_SUPPORT
static inline int sync_mark_walk_cluster_modtime_update(ctx_t *ctx_p, const char *path, short int dirlevel, mode_t st_mode) {
	if(ctx_p->cluster_iface) {
		int ret=cluster_modtime_update(path, dirlevel, st_mode);
		if(ret) error("cannot cluster_modtime_update()");
		return ret;
	}
	return 0;
}
#endif

int sync_mark_walk(ctx_t *ctx_p, const char *dirpath, indexes_t *indexes_p) {
	int ret = 0;
	const char *rootpaths[] = {dirpath, NULL};
	FTS *tree;
	rule_t *rules_p = ctx_p->rules;
	debug(2, "(ctx_p, \"%s\", indexes_p).", dirpath);

	int fts_opts = FTS_NOCHDIR|FTS_PHYSICAL|FTS_NOSTAT|(ctx_p->flags[ONEFILESYSTEM]?FTS_XDEV:0);

        debug(3, "fts_opts == %p", (void *)(long)fts_opts);
	tree = privileged_fts_open((char *const *)&rootpaths, fts_opts, NULL, PC_SYNC_MARK_WALK_FTS_OPEN);

	if (tree == NULL) {
		error_or_debug((ctx_p->state == STATE_STARTING) ?-1:2, "Cannot privileged_fts_open() on \"%s\".", dirpath);
		return errno;
	}

	FTSENT *node;
	char  *path_rel		= NULL;
	size_t path_rel_len	= 0;

	while ((node = privileged_fts_read(tree, PC_SYNC_MARK_WALK_FTS_READ))) {
#ifdef CLUSTER_SUPPORT
		int ret;
#endif
		debug(2, "walking: \"%s\" (depth %u): fts_info == %i", node->fts_path, node->fts_level, node->fts_info);

		switch(node->fts_info) {
			// Duplicates:
			case FTS_DP:
				continue;
			// Files:
			case FTS_DEFAULT:
			case FTS_SL:
			case FTS_SLNONE:
			case FTS_F:
			case FTS_NSOK:
#ifdef CLUSTER_SUPPORT
				if ((ret=sync_mark_walk_cluster_modtime_update(ctx_p, node->fts_path, node->fts_level, S_IFREG)))
					goto l_sync_mark_walk_end;
#endif
				continue;
			// Directories (to mark):
			case FTS_D:
			case FTS_DC:    // TODO: think about case of FTS_DC
			case FTS_DOT:
#ifdef CLUSTER_SUPPORT
				if ((ret=sync_mark_walk_cluster_modtime_update(ctx_p, node->fts_path, node->fts_level, S_IFDIR)))
					goto l_sync_mark_walk_end;
#endif
				break;
			// Error cases:
			case FTS_ERR:
			case FTS_NS:
			case FTS_DNR:
				if (errno == ENOENT) {
					debug(1, "Got error while privileged_fts_read(); fts_info: %i.", node->fts_info);
					continue;
				} else {
					error_or_debug((ctx_p->state == STATE_STARTING) ?-1:2, "Got error while privileged_fts_read(); fts_info: %i.", node->fts_info);
					ret = errno;
					goto l_sync_mark_walk_end;
				}
			default:
				error_or_debug((ctx_p->state == STATE_STARTING) ?-1:2, "Got unknown fts_info vlaue while privileged_fts_read(): %i.", node->fts_info);
				ret = EINVAL;
				goto l_sync_mark_walk_end;
		}

		path_rel = sync_path_abs2rel(ctx_p, node->fts_path, -1, &path_rel_len, path_rel);
		ruleaction_t perm = rules_search_getperm(path_rel, S_IFDIR, rules_p, RA_WALK, NULL);

		if (!(perm&RA_WALK)) {
			fts_set(tree, node, FTS_SKIP);
			continue;
		}

		debug(2, "marking \"%s\" (depth %u)", node->fts_path, node->fts_level);
		int wd = sync_notify_mark(ctx_p, node->fts_accpath, node->fts_path, node->fts_pathlen, indexes_p);
		if (wd == -1) {
			error_or_debug((ctx_p->state == STATE_STARTING) ?-1:2, "Got error while notify-marking \"%s\".", node->fts_path);
			ret = errno;
			goto l_sync_mark_walk_end;
		}
		debug(2, "watching descriptor is %i.", wd);
	}
	if (errno) {
		error_or_debug((ctx_p->state == STATE_STARTING) ?-1:2, "Got error while privileged_fts_read() and related routines.");
		ret = errno;
		goto l_sync_mark_walk_end;
	}

	if (privileged_fts_close(tree, PC_SYNC_MARK_WALK_FTS_CLOSE)) {
		error_or_debug((ctx_p->state == STATE_STARTING) ?-1:2, "Got error while privileged_fts_close().");
		ret = errno;
		goto l_sync_mark_walk_end;
	}

l_sync_mark_walk_end:
	if (path_rel != NULL)
		free(path_rel);
	return ret;
}

int sync_notify_init(ctx_t *ctx_p) {
	switch (ctx_p->flags[MONITOR]) {
#ifdef FANOTIFY_SUPPORT
		case NE_FANOTIFY: {
			ctx_p->fsmondata = (long)fanotify_init(FANOTIFY_FLAGS, FANOTIFY_EVFLAGS);
			if((long)ctx_p->fsmondata == -1) {
				error("cannot fanotify_init(%i, %i).", FANOTIFY_FLAGS, FANOTIFY_EVFLAGS);
				return -1;
			}

			return 0;
		}
#endif
#ifdef INOTIFY_SUPPORT
		case NE_INOTIFY: {
#if INOTIFY_OLD
			ctx_p->fsmondata = (void *)(long)inotify_init();
#else
			ctx_p->fsmondata = (void *)(long)inotify_init1(INOTIFY_FLAGS);
#endif
			if ((long)ctx_p->fsmondata == -1) {
				error("cannot inotify_init(%i).", INOTIFY_FLAGS);
				return -1;
			}

			return 0;
		}
#endif
#ifdef KQUEUE_SUPPORT
		case NE_KQUEUE: {
			int kqueue_d = kqueue_init(ctx_p);
			if(kqueue_d == -1) {
				error("cannot kqueue_init(ctx_p).");
				return -1;
			}

			return 0;
		}
#endif
#ifdef BSM_SUPPORT
		case NE_BSM: {
			int bsm_d = bsm_init(ctx_p);
			if(bsm_d == -1) {
				error("cannot bsm_init(ctx_p).");
				return -1;
			}

			return 0;
		}
#endif
	}
	error("unknown notify-engine: %i", ctx_p->flags[MONITOR]);
	errno = EINVAL;
	return -1;
}

static inline int sync_dosync_exec(ctx_t *ctx_p, indexes_t *indexes_p, const char *evmask_str, const char *fpath) {
	int rc;
	struct dosync_arg dosync_arg;
	debug(20, "(ctx_p, indexes_p, \"%s\", \"%s\")", evmask_str, fpath);

	 dosync_arg.ctx_p	       = ctx_p;
	*dosync_arg.include_list       = fpath;
	 dosync_arg.include_list_count = 1;
	 dosync_arg.list_type_str      = "sync";
	 dosync_arg.evmask_str         = evmask_str;

	char **argv = sync_customargv(ctx_p, &dosync_arg, &ctx_p->synchandler_args[SHARGS_PRIMARY]);
	rc = SYNC_EXEC_ARGV(
		ctx_p,
		indexes_p,
		NULL, NULL,
		argv);
	
	if (!SHOULD_THREAD(ctx_p))	// If it's a thread then it will free the argv in GC. If not a thread then we have to free right here.
		argv_free(argv);
	return rc;

#ifdef DOXYGEN
	sync_exec_argv(NULL, NULL); sync_exec_argv_thread(NULL, NULL);
#endif
}

int sync_dosync(const char *fpath, uint32_t evmask, ctx_t *ctx_p, indexes_t *indexes_p) {
	int ret;

#ifdef CLUSTER_SUPPORT
	ret = cluster_lock(fpath);
	if(ret) return ret;
#endif

	char *evmask_str = xmalloc(1<<8);
	sprintf(evmask_str, "%u", evmask);
	ret = sync_dosync_exec(ctx_p, indexes_p, evmask_str, fpath);
	free(evmask_str);

#ifdef CLUSTER_SUPPORT
	ret = cluster_unlock_all();
#endif

	return ret;
}

int sync_prequeue_loadmark
(
		int monitored,

		ctx_t     *ctx_p,
		indexes_t *indexes_p,

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

		eventinfo_t *evinfo
) {
	debug(5, "");
#ifdef PARANOID
	// &path_buf and &path_buf_len are passed to do not reallocate memory for path_rel/path_full each time
	if ((path_buf_p == NULL || path_buf_len_p == NULL) && (path_full == NULL || path_rel == NULL)) {
		error("path_rel_p == NULL || path_rel_len_p == NULL");
		return EINVAL;
	}
#endif
#ifdef VERYPARANOID
	if (path_full == NULL && path_rel == NULL) {
		error("path_full == NULL && path_rel == NULL");
		return EINVAL;
	}
#endif


	if (path_rel == NULL) {
		*path_buf_p   = sync_path_abs2rel(ctx_p, path_full, -1, path_buf_len_p, *path_buf_p);
		 path_rel     = *path_buf_p;
	}

	ruleaction_t perm = RA_ALL;
	if (st_mode) {
		// Checking by filter rules
		perm = rules_getperm(path_rel, st_mode, ctx_p->rules, RA_WALK|RA_MONITOR);

		if(!(perm&(RA_MONITOR|RA_WALK))) {
			return 0;
		}
	}

	// Handling different cases

	int is_dir	= objtype_old == EOT_DIR || objtype_new == EOT_DIR;
	int is_created	= objtype_old == EOT_DOESNTEXIST;
	int is_deleted	= objtype_new == EOT_DOESNTEXIST;

	debug(4, "is_dir == %x; is_created == %x; is_deleted == %x", is_dir, is_created, is_deleted);

	if (is_dir) {
		if (is_created) {
			int ret;

			if (perm & RA_WALK) {
				if (path_full == NULL) {
					*path_buf_p   = sync_path_rel2abs(ctx_p, path_rel,  -1, path_buf_len_p, *path_buf_p);
					path_full    = *path_buf_p;
				}

				if (monitored) {
					ret = sync_mark_walk(ctx_p, path_full, indexes_p);
					if(ret) {
						debug(1, "Seems, that directory \"%s\" disappeared, while trying to mark it.", path_full);
						return 0;
					}
				}

				ret = sync_initialsync(path_full, ctx_p, indexes_p, INITSYNC_SUBDIR);
				if (ret) {
					errno = ret;
					error("Got error from sync_initialsync()");
					return errno;
				}
			}

			return 0;
		} else 
		if (is_deleted) {
			debug(2, "Disappeared \".../%s\".", path_rel);
		}
	}

	if (!(perm&RA_WALK)) {
		return 0;
	}

	// Locally queueing the event

	int isnew = 0;

	if (evinfo == NULL)
		evinfo = indexes_fpath2ei(indexes_p, path_rel);
	else
		isnew++;	// It's new for prequeue (but old for lockwait queue)

	if (evinfo == NULL) {
		evinfo = (eventinfo_t *)xmalloc(sizeof(*evinfo));
		memset(evinfo, 0, sizeof(*evinfo));
		evinfo->fsize        = st_size;
		evinfo->wd           = event_wd;
		evinfo->seqid_min    = sync_seqid();
		evinfo->seqid_max    = evinfo->seqid_min;
		evinfo->objtype_old  = objtype_old;
		isnew++;
		debug(3, "new event: fsize == %i; wd == %i", evinfo->fsize, evinfo->wd);
	} else {
		evinfo->seqid_max    = sync_seqid();
	}

	switch(ctx_p->flags[MONITOR]) {
#ifdef KQUEUE_SUPPORT
		case NE_KQUEUE:
#endif
#ifdef INOTIFY_SUPPORT
		case NE_INOTIFY:
#endif
#if KQUEUE_SUPPORT | INOTIFY_SUPPORT
			evinfo->evmask |= event_mask;
			break;
#endif
#ifdef BSM_SUPPORT
		case NE_BSM:
			evinfo->evmask  = event_mask;
			break;
#endif
	}

	evinfo->objtype_new = objtype_new;

	debug(2, "path_rel == \"%s\"; evinfo->objtype_old == %i; evinfo->objtype_new == %i; "
		 "evinfo->seqid_min == %u; evinfo->seqid_max == %u", 
		 path_rel, evinfo->objtype_old, evinfo->objtype_new,
		 evinfo->seqid_min, evinfo->seqid_max
	     );

	if (isnew)
		indexes_fpath2ei_add(indexes_p, strdup(path_rel), evinfo);

	return 0;
}

void _sync_idle_dosync_collectedexcludes(gpointer fpath_gp, gpointer flags_gp, gpointer arg_gp) {
	char *fpath		  = (char *)fpath_gp;
	indexes_t *indexes_p 	  = ((struct dosync_arg *)arg_gp)->indexes_p;

	debug(3, "\"%s\", %u (%p).", fpath, GPOINTER_TO_INT(flags_gp), flags_gp);

	indexes_addexclude_aggr(indexes_p, strdup(fpath), (eventinfo_flags_t)GPOINTER_TO_INT(flags_gp));

	return;
}

// Is not a thread-save function!
eventinfo_t *ht_fpath_isincluded(GHashTable *ht, const char *const fpath) {
	static char buf[PATH_MAX+2]={0};
	char *ptr, *end;
	eventinfo_t *evinfo = g_hash_table_lookup(ht, fpath);
	debug(5, "looking up for \"%s\": %p", fpath, evinfo);
	if (evinfo != NULL)
		return evinfo;

	if (!*fpath)
		return NULL;

	evinfo = g_hash_table_lookup(ht, "");

	if (evinfo != NULL) {
		debug(5, "recursive looking up for \"\": %p (%x: recusively: %x)", evinfo, evinfo->flags, evinfo->flags & EVIF_RECURSIVELY);
		if (evinfo->flags & EVIF_RECURSIVELY)
			return evinfo;
	}

	size_t fpath_len = strlen(fpath);
	memcpy(buf, fpath, fpath_len+1);
	ptr  =  buf;
	end  = &buf[fpath_len];

	while(ptr < end) {
		if (*ptr == '/') {
			*ptr = 0;
			evinfo = g_hash_table_lookup(ht, buf);

			if (evinfo != NULL) {
				debug(5, "recursive looking up for \"%s\": %p (%x: recusively: %x)", buf, evinfo, evinfo->flags, evinfo->flags & EVIF_RECURSIVELY);
				*ptr = '/';
				if (evinfo->flags & EVIF_RECURSIVELY)
					return evinfo;
			}
		}

		ptr++;
	}

	return evinfo;
}

int _sync_islocked(threadinfo_t *threadinfo_p, void *_fpath) {
	char *fpath = _fpath;

	eventinfo_t *evinfo = ht_fpath_isincluded(threadinfo_p->fpath2ei_ht, fpath);
	debug(4, "scanning thread %p: fpath<%s> -> evinfo<%p>", threadinfo_p->pthread, fpath, evinfo);
	if (evinfo != NULL)
		return 1;

	return 0;
}

static inline int sync_islocked(const char *const fpath) {
	int rc = threads_foreach(_sync_islocked, STATE_RUNNING, (void *)fpath);
	debug(3, "<%s>: %u", fpath, rc);
	return rc;
}

void _sync_idle_dosync_collectedevents(gpointer fpath_gp, gpointer evinfo_gp, gpointer arg_gp) {
	char *fpath		  = (char *)fpath_gp;
	eventinfo_t *evinfo	  = (eventinfo_t *)evinfo_gp;
	int *evcount_p		  =&((struct dosync_arg *)arg_gp)->evcount;
	ctx_t *ctx_p 		  = ((struct dosync_arg *)arg_gp)->ctx_p;
	indexes_t *indexes_p 	  = ((struct dosync_arg *)arg_gp)->indexes_p;
	queue_id_t queue_id	  = (queue_id_t)((struct dosync_arg *)arg_gp)->data;

	debug(3, "queue_id == %i.", queue_id);

	if (ctx_p->flags[THREADING] == PM_SAFE)
		if (sync_islocked(fpath)) {
			debug(3, "\"%s\" is locked, dropping to waitlock queue", fpath);

			eventinfo_t *evinfo_dup = xmalloc(sizeof(*evinfo_dup));
			memcpy(evinfo_dup, evinfo, sizeof(*evinfo));
			
			sync_queuesync(fpath, evinfo_dup, ctx_p, indexes_p, QUEUE_LOCKWAIT);
			return;
		}
	

	if ((ctx_p->listoutdir == NULL) && (!(ctx_p->synchandler_argf & SHFL_INCLUDE_LIST)) && (!(ctx_p->flags[MODE]==MODE_SO))) {
		debug(3, "calling sync_dosync()");
		int ret;
		if((ret=sync_dosync(fpath, evinfo->evmask, ctx_p, indexes_p))) {
			error("unable to sync \"%s\" (evmask %i).", fpath, evinfo->evmask);
			exit(ret);	// TODO: remove this from here
		}
	}

	int isnew = 0;
	eventinfo_t *evinfo_idx = indexes_fpath2ei(indexes_p, fpath);

	if (evinfo_idx == NULL) {
		evinfo_idx = (eventinfo_t *)xmalloc(sizeof(*evinfo_idx));
		memset(evinfo_idx, 0, sizeof(*evinfo_idx));
		isnew++;
		(*evcount_p)++;

		evinfo_idx->evmask       = evinfo->evmask;
		evinfo_idx->flags        = evinfo->flags;
		evinfo_idx->objtype_old  = evinfo->objtype_old;
		evinfo_idx->objtype_new  = evinfo->objtype_new;
		evinfo_idx->seqid_min    = evinfo->seqid_min;
		evinfo_idx->seqid_max    = evinfo->seqid_max;
	} else
		evinfo_merge(ctx_p, evinfo_idx, evinfo);


	int _queue_id = 0;
	while (_queue_id < QUEUE_MAX) {
		if(_queue_id == queue_id) {
			_queue_id++;
			continue;
		}

		eventinfo_t *evinfo_q = indexes_lookupinqueue(indexes_p, fpath, _queue_id);
		if(evinfo_q != NULL) {
			evinfo_merge(ctx_p, evinfo_idx, evinfo_q);

			indexes_removefromqueue(indexes_p, fpath, _queue_id);
			if(!indexes_queuelen(indexes_p, _queue_id))
				ctx_p->_queues[_queue_id].stime = 0;
		}
		_queue_id++;
	}

	if (isnew) {
		debug(4, "Collecting \"%s\"", fpath);
		indexes_fpath2ei_add(indexes_p, strdup(fpath), evinfo_idx);
	} else
		free(fpath);

	return;
}

struct trylocked_arg {
	char   *path_full;
	size_t  path_full_len;
};
gboolean sync_trylocked(gpointer fpath_gp, gpointer evinfo_gp, gpointer arg_gp) {
	char *fpath		   = (char *)fpath_gp;
	eventinfo_t *evinfo	   = (eventinfo_t *)evinfo_gp;

	struct dosync_arg *arg_p   = (struct dosync_arg *)arg_gp;

	ctx_t *ctx_p 		   =  arg_p->ctx_p;
	indexes_t *indexes_p 	   =  arg_p->indexes_p;

	struct trylocked_arg *data =  arg_p->data;

	if (!sync_islocked(fpath)) {
		if (sync_prequeue_loadmark(0, ctx_p, indexes_p, NULL, fpath, 
				evinfo->evmask,
				evinfo->objtype_old,
				evinfo->objtype_new,
				0, 0, 0, &data->path_full, &data->path_full_len, evinfo)) {
			critical("Cannot re-queue \"%s\" to be synced", fpath);
			return FALSE;
		}
		return TRUE;
	}
	return FALSE;
}

int sync_idle_dosync_collectedevents_cleanup(ctx_t *ctx_p, thread_callbackfunct_arg_t *arg_p) {
	int ret0 = 0, ret1 = 0;
	if(ctx_p->flags[DONTUNLINK]) 
		return 0;

	debug(3, "(ctx_p, {inc: %p, exc: %p}) thread %p", arg_p->incfpath, arg_p->excfpath, pthread_self());

	if (arg_p->excfpath != NULL) {
		debug(3, "unlink()-ing exclude-file: \"%s\"", arg_p->excfpath);
		ret0 = unlink(arg_p->excfpath);
		free(arg_p->excfpath);
	}

	if (arg_p->incfpath != NULL) {
		debug(3, "unlink()-ing include-file: \"%s\"", arg_p->incfpath);
		ret1 = unlink(arg_p->incfpath);
		free(arg_p->incfpath);
	}

	free(arg_p);
	return ret0 ? ret0 : ret1;
}

void sync_queuesync_wrapper(gpointer fpath_gp, gpointer evinfo_gp, gpointer arg_gp) {
	char *fpath_rel		  = (char *)fpath_gp;
	eventinfo_t *evinfo	  = (eventinfo_t *)evinfo_gp;
	ctx_t *ctx_p 		  = ((struct dosync_arg *)arg_gp)->ctx_p;
	indexes_t *indexes_p 	  = ((struct dosync_arg *)arg_gp)->indexes_p;

	sync_queuesync(fpath_rel, evinfo, ctx_p, indexes_p, QUEUE_AUTO);

	return;
}

int sync_prequeue_unload(ctx_t *ctx_p, indexes_t *indexes_p) {
	struct dosync_arg dosync_arg;
	dosync_arg.ctx_p 	= ctx_p;
	dosync_arg.indexes_p	= indexes_p;

	debug(3, "collected %i events per this time.", g_hash_table_size(indexes_p->fpath2ei_ht));

	g_hash_table_foreach(indexes_p->fpath2ei_ht, sync_queuesync_wrapper, &dosync_arg);
	g_hash_table_remove_all(indexes_p->fpath2ei_ht);

	return 0;
}

int sync_idle_dosync_collectedevents_aggrqueue(queue_id_t queue_id, ctx_t *ctx_p, indexes_t *indexes_p, struct dosync_arg *dosync_arg) {
	time_t tm = time(NULL);

	queueinfo_t *queueinfo = &ctx_p->_queues[queue_id];

	if ((queueinfo->stime + queueinfo->collectdelay > tm) && (queueinfo->collectdelay != COLLECTDELAY_INSTANT) && (!ctx_p->flags[EXITONNOEVENTS])) {
		debug(3, "(%i, ...): too early (%i + %i > %i).", queue_id, queueinfo->stime, queueinfo->collectdelay, tm);
		return 0;
	}
	queueinfo->stime = 0;

	int evcount_real = g_hash_table_size(indexes_p->fpath2ei_coll_ht[queue_id]);

	debug(3, "(%i, ...): evcount_real == %i", queue_id, evcount_real);

	if (evcount_real<=0) {
		debug(3, "(%i, ...): no events, return 0.", queue_id);
		return 0;
	}

	switch (queue_id) {
		case QUEUE_LOCKWAIT: {
			struct trylocked_arg arg_data = {0};

			dosync_arg->data = &arg_data;
			g_hash_table_foreach_remove(indexes_p->fpath2ei_coll_ht[queue_id], sync_trylocked, dosync_arg);

			// Placing to global queues recently unlocked objects
			sync_prequeue_unload(ctx_p, indexes_p);

#ifdef PARANOID
			if (arg_data.path_full != NULL)
#endif
				free(arg_data.path_full);
			break;
		}
		default: {
			g_hash_table_foreach(indexes_p->fpath2ei_coll_ht[queue_id], _sync_idle_dosync_collectedevents, dosync_arg);
			g_hash_table_remove_all(indexes_p->fpath2ei_coll_ht[queue_id]);

			if(!ctx_p->flags[RSYNCPREFERINCLUDE]) {
				g_hash_table_foreach(indexes_p->exc_fpath_coll_ht[queue_id], _sync_idle_dosync_collectedexcludes, dosync_arg);
				g_hash_table_remove_all(indexes_p->exc_fpath_coll_ht[queue_id]);
			}
			break;
		}
	}

	return 0;
}

int sync_idle_dosync_collectedevents_uniqfname(ctx_t *ctx_p, char *fpath, char *name) {
	pid_t pid = getpid();
	time_t tm = time(NULL);
	stat64_t stat64;

	int counter = 0;
	do {
		snprintf(fpath, PATH_MAX, "%s/.clsync-%s.%u.%lu.%lu.%u", ctx_p->listoutdir, name, pid, (long)pthread_self(), (unsigned long)tm, rand());	// To be unique
		lstat64(fpath, &stat64);
		if(counter++ > COUNTER_LIMIT) {
			error("Cannot find unused filename for list-file. The last try was \"%s\".", fpath);
			return ENOENT;
		}
	} while(errno != ENOENT);	// TODO: find another way to check if the object exists
	errno=0;

	return 0;
}

int sync_idle_dosync_collectedevents_listcreate(struct dosync_arg *dosync_arg_p, char *name) {
	debug(3, "Creating %s file", name);
	char *fpath = dosync_arg_p->outf_path;
	ctx_t *ctx_p = dosync_arg_p->ctx_p;

	int ret;
	if ((ret=sync_idle_dosync_collectedevents_uniqfname(ctx_p, fpath, name))) {
		error("sync_idle_dosync_collectedevents_listcreate: Cannot get unique file name.");
		return ret;
	}

	dosync_arg_p->outf = fopen(fpath, "w");

	if (dosync_arg_p->outf == NULL) {
		error("Cannot open \"%s\" as file for writing.", fpath);
		return errno;
	}

	setbuffer(dosync_arg_p->outf, dosync_arg_p->buf, BUFSIZ);
	debug(3, "Created list-file \"%s\"", fpath);
	dosync_arg_p->linescount = 0;

	return 0;
}

size_t rsync_escape_result_size = 0;
char *rsync_escape_result 	= NULL;

void rsync_escape_cleanup() {
	if(rsync_escape_result_size)
		free(rsync_escape_result);
}

const char *rsync_escape(const char *path) {
	size_t sc_count       = 0;

	size_t i = 0;

	while(1) {
		switch(path[i]) {
			case 0:
				goto l_rsync_escape_loop0_end;
			case '[':
			case ']':
			case '*':
			case '?':
			case '\\':
				sc_count++;
		}
		i++;
	};
l_rsync_escape_loop0_end:

	if(!sc_count)
		return path;

	size_t required_size = i+sc_count+1;
	if(required_size >= rsync_escape_result_size) {
		rsync_escape_result_size = required_size + ALLOC_PORTION;
		rsync_escape_result	 = xrealloc(rsync_escape_result, rsync_escape_result_size);
	}

	// TODO: Optimize this. Second "switch" is a bad way.
	i++;
	while(i--) {
		rsync_escape_result[i+sc_count] = path[i];

		switch(path[i]) {
			case '[':
			case ']':
			case '*':
			case '?':
			case '\\':
				sc_count--;
				rsync_escape_result[i+sc_count] = '\\';
				break;
		}
	} 

	return rsync_escape_result;
}

static inline int rsync_outline(FILE *outf, char *outline, eventinfo_flags_t flags) {
#ifdef VERYPARANOID
	critical_on(outf == NULL);
#endif

	if (flags & EVIF_RECURSIVELY) {
		debug(3, "Recursively \"%s\": Writing to rsynclist: \"%s/***\".", outline, outline);
		fprintf(outf, "%s/***\n", outline);
	} else
	if (flags & EVIF_CONTENTRECURSIVELY) {
		debug(3, "Content-recursively \"%s\": Writing to rsynclist: \"%s/**\".", outline, outline);
		fprintf(outf, "%s/**\n", outline);
	} else {
		debug(3, "Non-recursively \"%s\": Writing to rsynclist: \"%s\".", outline, outline);
		fprintf(outf, "%s\n", outline);
	}

	return 0;
}

gboolean rsync_aggrout(gpointer outline_gp, gpointer flags_gp, gpointer arg_gp) {
	struct dosync_arg *dosync_arg_p = (struct dosync_arg *)arg_gp;
	char *outline		  = (char *)outline_gp;
	FILE *outf		  = dosync_arg_p->outf;
	eventinfo_flags_t flags	 = (eventinfo_flags_t)GPOINTER_TO_INT(flags_gp);
//	debug(3, "\"%s\"", outline);

	int ret;
	if((ret=rsync_outline(outf, outline, flags))) {
		error("Got error from rsync_outline(). Exit.");
		exit(ret);	// TODO: replace this with kill(0, ...)
	}

	return TRUE;
}

static inline int rsync_listpush(indexes_t *indexes_p, const char *fpath, size_t fpath_len, eventinfo_flags_t flags, int *linescount_p) {
	char *fpathwslash;
	if(fpath_len>0) {
		// Prepending with the slash

		fpathwslash = alloca(fpath_len+2);
		fpathwslash[0] = '/';
		memcpy(&fpathwslash[1], fpath, fpath_len+1);
	} else {

		// In this case slash is not required
		fpathwslash = (char *)fpath;
	}


	fpathwslash = (char *)rsync_escape(fpathwslash);

	char *end=fpathwslash;

	debug(3, "\"%s\": Adding to rsynclist: \"%s\" with flags %p.", 
		fpathwslash, fpathwslash, (void *)(long)flags);
	indexes_outaggr_add(indexes_p, strdup(fpathwslash), flags);
	if(linescount_p != NULL)
		(*linescount_p)++;

	while(end != NULL) {
		if(*fpathwslash == 0x00)
			break;
		debug(3, "Non-recursively \"%s\": Adding to rsynclist: \"%s\".", fpathwslash, fpathwslash);
		indexes_outaggr_add(indexes_p, strdup(fpathwslash), EVIF_NONE);
		if(linescount_p != NULL)
			(*linescount_p)++;
		end = strrchr(fpathwslash, '/');
		if(end == NULL)
			break;
		if(end - fpathwslash <= 0)
			break;

		*end = 0x00;
	};

	return 0;
}

gboolean sync_idle_dosync_collectedevents_rsync_exclistpush(gpointer fpath_gp, gpointer flags_gp, gpointer arg_gp) {
	struct dosync_arg *dosync_arg_p = (struct dosync_arg *)arg_gp;
	char *fpath		  = (char *)fpath_gp;
	FILE *excf		  = dosync_arg_p->outf;
	eventinfo_flags_t flags	  = GPOINTER_TO_INT(flags_gp);
//	ctx_t *ctx_p 	  = dosync_arg_p->ctx_p;
//	indexes_t *indexes_p	  = dosync_arg_p->indexes_p;
	debug(3, "\"%s\"", fpath);

	size_t fpath_len = strlen(fpath);
	char *fpathwslash;
	if(fpath_len>0) {
		// Prepending with the slash

		fpathwslash = alloca(fpath_len+2);
		fpathwslash[0] = '/';
		memcpy(&fpathwslash[1], fpath, fpath_len+1);
	} else {

		// In this case slash is not required
		fpathwslash = fpath;
	}

	fpathwslash = (char *)rsync_escape(fpathwslash);

	int ret;
	if((ret=rsync_outline(excf, fpathwslash, flags))) {
		error("Got error from rsync_outline(). Exit.");
		exit(ret);	// TODO: replace this with kill(0, ...)
	}

	return TRUE;
}

int sync_idle_dosync_collectedevents_commitpart(struct dosync_arg *dosync_arg_p) {
	ctx_t *ctx_p = dosync_arg_p->ctx_p;
	indexes_t *indexes_p = dosync_arg_p->indexes_p;

	debug(3, "Committing the file (flags[MODE] == %i)", ctx_p->flags[MODE]);

	if (
		(ctx_p->flags[MODE] == MODE_RSYNCDIRECT) || 
		(ctx_p->flags[MODE] == MODE_RSYNCSHELL)	 ||
		(ctx_p->flags[MODE] == MODE_RSYNCSO)
	)
		g_hash_table_foreach_remove(indexes_p->out_lines_aggr_ht, rsync_aggrout, dosync_arg_p);

	if (dosync_arg_p->outf != NULL) {
		fclose(dosync_arg_p->outf);
		dosync_arg_p->outf = NULL;
	}

	if (dosync_arg_p->evcount > 0) {
		thread_callbackfunct_arg_t *callback_arg_p;

		debug(3, "%s [%s] (%p) -> %s [%s]", ctx_p->watchdir, ctx_p->watchdirwslash, ctx_p->watchdirwslash, 
								ctx_p->destdir?ctx_p->destdir:"", ctx_p->destdirwslash?ctx_p->destdirwslash:"");

		if (ctx_p->flags[MODE] == MODE_SO) {
			api_eventinfo_t *ei = dosync_arg_p->api_ei;
			return so_call_sync(ctx_p, indexes_p, dosync_arg_p->evcount, ei);
		}

		if (ctx_p->flags[MODE] == MODE_RSYNCSO) 
			return so_call_rsync(
				ctx_p, 
				indexes_p, 
				dosync_arg_p->outf_path, 
				*(dosync_arg_p->excf_path) ? dosync_arg_p->excf_path : NULL);

		callback_arg_p = xcalloc(1, sizeof(*callback_arg_p));

		if (ctx_p->synchandler_argf & SHFL_INCLUDE_LIST_PATH)
			callback_arg_p->incfpath = strdup(dosync_arg_p->outf_path);

		if (ctx_p->synchandler_argf & SHFL_EXCLUDE_LIST_PATH)
			callback_arg_p->excfpath = strdup(dosync_arg_p->excf_path);

		{
			int rc;
			dosync_arg_p->list_type_str =
				ctx_p->flags[MODE]==MODE_RSYNCDIRECT ||
				ctx_p->flags[MODE]==MODE_RSYNCSHELL
					? "rsynclist" : "synclist";

			debug(9, "dosync_arg_p->include_list_count == %u", dosync_arg_p->include_list_count);
			char **argv = sync_customargv(ctx_p, dosync_arg_p, &ctx_p->synchandler_args[SHARGS_PRIMARY]);

			while (dosync_arg_p->include_list_count)
				free((char *)dosync_arg_p->include_list[--dosync_arg_p->include_list_count]);

			rc = SYNC_EXEC_ARGV(
				ctx_p,
				indexes_p,
				sync_idle_dosync_collectedevents_cleanup,
				callback_arg_p,
				argv);

			if (!SHOULD_THREAD(ctx_p))	// If it's a thread then it will free the argv in GC. If not a thread then we have to free right here.
				argv_free(argv);
			return rc;
		}
	}

	return 0;

#ifdef DOXYGEN
	sync_exec_argv(NULL, NULL);	sync_exec_argv_thread(NULL, NULL);
#endif
}

void sync_inclist_rotate(ctx_t *ctx_p, struct dosync_arg *dosync_arg_p) {
	int ret;
	char newexc_path[PATH_MAX+1];

	if (ctx_p->synchandler_argf & SHFL_EXCLUDE_LIST_PATH) {
		// TODO: optimize this out {
		if ((ret=sync_idle_dosync_collectedevents_uniqfname(ctx_p, newexc_path, "exclist"))) {
			error("Cannot get unique file name.");
			exit(ret);
		}
		if ((ret=fileutils_copy(dosync_arg_p->excf_path, newexc_path))) {
			error("Cannot copy file \"%s\" to \"%s\".", dosync_arg_p->excf_path, newexc_path);
			exit(ret);
		}
		// }
		// That's required to copy excludes' list file for every rsync execution.
		// The problem appears do to unlink()-ing the excludes' list file on callback function 
		// "sync_idle_dosync_collectedevents_cleanup()" of every execution.
	}

	if ((ret=sync_idle_dosync_collectedevents_commitpart(dosync_arg_p))) {
		error("Cannot commit list-file \"%s\"", dosync_arg_p->outf_path);
		exit(ret);	// TODO: replace with kill(0, ...);
	}

	if (ctx_p->synchandler_argf & SHFL_INCLUDE_LIST_PATH) {
#ifdef VERYPARANOID
		require_strlen_le(newexc_path, PATH_MAX);
#endif
		strcpy(dosync_arg_p->excf_path, newexc_path);		// TODO: optimize this out

		if ((ret=sync_idle_dosync_collectedevents_listcreate(dosync_arg_p, "list"))) {
			error("Cannot create new list-file");
			exit(ret);	// TODO: replace with kill(0, ...);
		}
	}

	return;
}

void sync_idle_dosync_collectedevents_listpush(gpointer fpath_gp, gpointer evinfo_gp, gpointer arg_gp) {
	struct dosync_arg *dosync_arg_p = (struct dosync_arg *)arg_gp;
	char *fpath		   =  (char *)fpath_gp;
	eventinfo_t *evinfo	   =  (eventinfo_t *)evinfo_gp;
	//int *evcount_p		  =&dosync_arg_p->evcount;
	FILE *outf		   =  dosync_arg_p->outf;
	ctx_t *ctx_p 		   =  dosync_arg_p->ctx_p;
	int *linescount_p	   = &dosync_arg_p->linescount;
	indexes_t *indexes_p 	   =  dosync_arg_p->indexes_p;
	api_eventinfo_t **api_ei_p = &dosync_arg_p->api_ei;
	int *api_ei_count_p 	   = &dosync_arg_p->api_ei_count;
	debug(3, "\"%s\" with int-flags %p. "
			"evinfo: seqid_min == %u, seqid_max == %u type_o == %i, type_n == %i", 
			fpath, (void *)(unsigned long)evinfo->flags,
			evinfo->seqid_min,   evinfo->seqid_max,
			evinfo->objtype_old, evinfo->objtype_new
		);

	// so-module case:
	if (ctx_p->flags[MODE] == MODE_SO) {
		api_eventinfo_t *ei = &(*api_ei_p)[(*api_ei_count_p)++];
		ei->evmask      = evinfo->evmask;
		ei->flags       = evinfo->flags;
		ei->objtype_old = evinfo->objtype_old;
		ei->objtype_new = evinfo->objtype_new;
		ei->path_len    = strlen(fpath);
		ei->path        = strdup(fpath);
		return;
	}

	if (ctx_p->synchandler_argf & SHFL_INCLUDE_LIST) {
		dosync_arg_p->include_list[dosync_arg_p->include_list_count++] = strdup(fpath);
		if (
			dosync_arg_p->include_list_count >= 
				(MAXARGUMENTS - 
					MAX(
						ctx_p->synchandler_args[SHARGS_PRIMARY].c,
						ctx_p->synchandler_args[SHARGS_INITIAL].c
					)
				)
		)
			sync_inclist_rotate(ctx_p, dosync_arg_p);
	}

	// Finish if we don't use list files
	if (!(ctx_p->synchandler_argf &
		( SHFL_INCLUDE_LIST_PATH | SHFL_EXCLUDE_LIST_PATH ) ))

		return;

	// List files cases:

	// non-RSYNC case
	if (!(
		(ctx_p->flags[MODE] == MODE_RSYNCSHELL)	 || 
		(ctx_p->flags[MODE] == MODE_RSYNCDIRECT) ||
		(ctx_p->flags[MODE] == MODE_RSYNCSO)
	)) {
		if (ctx_p->flags[SYNCLISTSIMPLIFY])
			fprintf(outf, "%s\n", fpath);
		else 
			fprintf(outf, "sync %s %i %s\n", ctx_p->label, evinfo->evmask, fpath);
		return;
	}

	// RSYNC case
	if (ctx_p->rsyncinclimit && (*linescount_p >= ctx_p->rsyncinclimit))
		sync_inclist_rotate(ctx_p, dosync_arg_p);

	int ret;
	if ((ret=rsync_listpush(indexes_p, fpath, strlen(fpath), evinfo->flags, linescount_p))) {
		error("Got error from rsync_listpush(). Exit.");
		exit(ret);
	}

	return;
}

static inline void setenv_iteration(uint32_t iteration_num)
{
	char iterations[sizeof("4294967296")];	// 4294967296 == 2**32
	sprintf(iterations, "%i", iteration_num);
	setenv("CLSYNC_ITERATION", iterations, 1);
}

int sync_idle_dosync_collectedevents(ctx_t *ctx_p, indexes_t *indexes_p) {
	debug(3, "");
	struct dosync_arg dosync_arg = {0};

	dosync_arg.ctx_p 	= ctx_p;
	dosync_arg.indexes_p	= indexes_p;

	char isrsyncpreferexclude = 
		(
			(ctx_p->flags[MODE] == MODE_RSYNCDIRECT) ||
			(ctx_p->flags[MODE] == MODE_RSYNCSHELL)	 ||
			(ctx_p->flags[MODE] == MODE_RSYNCSO)
		) && (!ctx_p->flags[RSYNCPREFERINCLUDE]);

#ifdef PARANOID
	if(ctx_p->listoutdir != NULL) {
		g_hash_table_remove_all(indexes_p->fpath2ei_ht);
		if(isrsyncpreferexclude)
			g_hash_table_remove_all(indexes_p->exc_fpath_ht);
	}
#endif

	// Setting the time to sync not before it:
	ctx_p->synctime = time(NULL) + ctx_p->syncdelay;
	debug(3, "Next sync will be not before: %u", ctx_p->synctime);

	int queue_id=0;
	while (queue_id < QUEUE_MAX) {
		int ret;

		if ((queue_id == QUEUE_LOCKWAIT) && (ctx_p->flags[THREADING] != PM_SAFE)) {
			queue_id++;
			continue;
		}

		queue_id_t *queue_id_p = (queue_id_t *)&dosync_arg.data;
		*queue_id_p = queue_id;
		ret = sync_idle_dosync_collectedevents_aggrqueue(queue_id, ctx_p, indexes_p, &dosync_arg);
		if(ret) {
			error("Got error while processing queue #%i\n.", queue_id);
			g_hash_table_remove_all(indexes_p->fpath2ei_ht);
			if(isrsyncpreferexclude)
				g_hash_table_remove_all(indexes_p->exc_fpath_ht);
			return ret;
		}

		queue_id++;
	}

	if (!dosync_arg.evcount) {
		debug(3, "Summary events' count is zero. Return 0.");
		return 0;
	}

	if (ctx_p->flags[MODE] == MODE_SO) {
		//dosync_arg.evcount = g_hash_table_size(indexes_p->fpath2ei_ht);
		debug(3, "There's %i events. Processing.", dosync_arg.evcount);
		dosync_arg.api_ei = (api_eventinfo_t *)xmalloc(dosync_arg.evcount * sizeof(*dosync_arg.api_ei));
	}

	{
		int ret;
		if ((ctx_p->listoutdir != NULL) || (ctx_p->flags[MODE] == MODE_SO)) {
			if (!(ctx_p->flags[MODE]==MODE_SO)) {
				*(dosync_arg.excf_path) = 0x00;
				if (isrsyncpreferexclude) {
					if ((ret=sync_idle_dosync_collectedevents_listcreate(&dosync_arg, "exclist"))) {
						error("Cannot create list-file");
						return ret;
					}

#ifdef PARANOID
					g_hash_table_remove_all(indexes_p->out_lines_aggr_ht);
#endif
					g_hash_table_foreach_remove(indexes_p->exc_fpath_ht, sync_idle_dosync_collectedevents_rsync_exclistpush, &dosync_arg);
					g_hash_table_foreach_remove(indexes_p->out_lines_aggr_ht, rsync_aggrout, &dosync_arg);
					fclose(dosync_arg.outf);
#ifdef VERYPARANOID
					require_strlen_le(dosync_arg.outf_path, PATH_MAX);
#endif
					strcpy(dosync_arg.excf_path, dosync_arg.outf_path);	// TODO: remove this strcpy()
				}

				if ((ret=sync_idle_dosync_collectedevents_listcreate(&dosync_arg, "list"))) {
					error("Cannot create list-file");
					return ret;
				}
			}
		}


		if ((ctx_p->listoutdir != NULL) || (ctx_p->flags[MODE] == MODE_SO) || (ctx_p->synchandler_argf & SHFL_INCLUDE_LIST)) {

#ifdef PARANOID
			g_hash_table_remove_all(indexes_p->out_lines_aggr_ht);
#endif

			g_hash_table_foreach(indexes_p->fpath2ei_ht, sync_idle_dosync_collectedevents_listpush, &dosync_arg);

			if ((ret=sync_idle_dosync_collectedevents_commitpart(&dosync_arg))) {
				error("Cannot submit to sync the list \"%s\"", dosync_arg.outf_path);
				// TODO: free dosync_arg.api_ei on case of error
				g_hash_table_remove_all(indexes_p->fpath2ei_ht);
				return ret;
			}

			g_hash_table_remove_all(indexes_p->fpath2ei_ht);
		}
	}

	if(ctx_p->iteration_num < ~0) // ~0 is the max value for unsigned variables
		ctx_p->iteration_num++;

	if (!ctx_p->flags[THREADING])
		setenv_iteration(ctx_p->iteration_num); 

	debug(3, "next iteration: %u/%u", 
		ctx_p->iteration_num, ctx_p->flags[MAXITERATIONS]);

	return 0;
}

int apievinfo2rsynclist(indexes_t *indexes_p, FILE *listfile, int n, api_eventinfo_t *apievinfo) {
	int i;

	if (listfile == NULL) {
		error("listfile == NULL.");
		return EINVAL;
	}

	i=0;
	while (i<n) {
		rsync_listpush(indexes_p, apievinfo[i].path, apievinfo[i].path_len, apievinfo[i].flags, NULL);
		i++;
	}

	struct dosync_arg dosync_arg = {0};
	dosync_arg.outf = listfile;
	g_hash_table_foreach_remove(indexes_p->out_lines_aggr_ht, rsync_aggrout, &dosync_arg);

	return 0;
}

int sync_idle(ctx_t *ctx_p, indexes_t *indexes_p) {

	// Collecting garbage

	int ret=thread_gc(ctx_p);
	if(ret) return ret;

	// Checking if we can sync

	if(ctx_p->flags[STANDBYFILE]) {
		struct stat st;
		if(!stat(ctx_p->standbyfile, &st)) {
			debug(1, "Found standby file. Holding over syncs. Sleeping "XTOSTR(SLEEP_SECONDS)" second.");
			sleep(SLEEP_SECONDS);
			return 0;
		}
	}

	// Syncing

	debug(3, "calling sync_idle_dosync_collectedevents()");

#ifdef CLUSTER_SUPPORT
	ret = cluster_lock_byindexes();
	if(ret) return ret;
#endif

	ret = sync_idle_dosync_collectedevents(ctx_p, indexes_p);
	if(ret) return ret;

#ifdef CLUSTER_SUPPORT
	ret = cluster_unlock_all();
	if(ret) return ret;
#endif

	return 0;
}

int notify_wait(ctx_t *ctx_p, indexes_t *indexes_p) {
	static struct timeval tv;
	time_t tm = time(NULL);
	long delay = ((unsigned long)~0 >> 1);

	threadsinfo_t *threadsinfo_p = thread_info();

	debug(4, "pthread_mutex_unlock(&threadsinfo_p->mutex[PTHREAD_MUTEX_STATE])");
	pthread_cond_broadcast(&threadsinfo_p->cond[PTHREAD_MUTEX_STATE]);
	pthread_mutex_unlock(&threadsinfo_p->mutex[PTHREAD_MUTEX_STATE]);

	long queue_id = 0;
	while (queue_id < QUEUE_MAX) {
		queueinfo_t *queueinfo = &ctx_p->_queues[queue_id++];

		if (!queueinfo->stime)
			continue;

		if (queueinfo->collectdelay == COLLECTDELAY_INSTANT) {
			debug(3, "There're events in instant queue (#%i), don't waiting.", queue_id-1);
			return 0;
		}

		int qdelay = queueinfo->stime + queueinfo->collectdelay - tm;
		debug(3, "queue #%i: %i %i %i -> %i", queue_id-1, queueinfo->stime, queueinfo->collectdelay, tm, qdelay);
		if (qdelay < -(long)ctx_p->syncdelay)
			qdelay = -(long)ctx_p->syncdelay;

		delay = MIN(delay, qdelay);
	}

	long synctime_delay = ((long)ctx_p->synctime) - ((long)tm);
	synctime_delay = synctime_delay > 0 ? synctime_delay : 0;

	debug(3, "delay = MAX(%li, %li)", delay, synctime_delay);
	delay = MAX(delay, synctime_delay);
	delay = delay > 0 ? delay : 0;

	if (ctx_p->flags[THREADING]) {
		time_t _thread_nextexpiretime = thread_nextexpiretime();
		debug(3, "thread_nextexpiretime == %i", _thread_nextexpiretime);
		if(_thread_nextexpiretime) {
			long thread_expiredelay = (long)thread_nextexpiretime() - (long)tm + 1; // +1 is to make "tm>threadinfo_p->expiretime" after select() definitely TRUE
			debug(3, "thread_expiredelay == %i", thread_expiredelay);
			thread_expiredelay = thread_expiredelay > 0 ? thread_expiredelay : 0;
			debug(3, "delay = MIN(%li, %li)", delay, thread_expiredelay);
			delay = MIN(delay, thread_expiredelay);
		}
	}

	if ((!delay) || (ctx_p->state != STATE_RUNNING))
		return 0;

	if (ctx_p->flags[EXITONNOEVENTS]) { // zero delay if "--exit-on-no-events" is set
		tv.tv_sec  = 0;
		tv.tv_usec = 0;
	} else {
		debug(3, "sleeping for %li second(s).", SLEEP_SECONDS);
		sleep(SLEEP_SECONDS);
		delay = ((long)delay)>SLEEP_SECONDS ? delay-SLEEP_SECONDS : 0;

		tv.tv_sec  = delay;
		tv.tv_usec = 0;
	}

	debug(4, "pthread_mutex_lock(&threadsinfo_p->mutex[PTHREAD_MUTEX_STATE])");
	pthread_mutex_lock(&threadsinfo_p->mutex[PTHREAD_MUTEX_STATE]);

	if (ctx_p->state != STATE_RUNNING)
		return 0;

	debug(4, "pthread_mutex_unlock(&threadsinfo_p->mutex[PTHREAD_MUTEX_STATE])");
	pthread_cond_broadcast(&threadsinfo_p->cond[PTHREAD_MUTEX_STATE]);
	pthread_mutex_lock(&threadsinfo_p->mutex[PTHREAD_MUTEX_SELECT]);
	pthread_mutex_unlock(&threadsinfo_p->mutex[PTHREAD_MUTEX_STATE]);

	int ret = ctx_p->notifyenginefunct.wait(ctx_p, indexes_p, &tv);

	pthread_mutex_unlock(&threadsinfo_p->mutex[PTHREAD_MUTEX_SELECT]);

	if ((ret == -1) && (errno == EINTR)) {
		errno = 0;
		ret   = 0;
	}

	debug(4, "pthread_mutex_lock(&threadsinfo_p->mutex[PTHREAD_MUTEX_STATE])");
	pthread_mutex_lock(&threadsinfo_p->mutex[PTHREAD_MUTEX_STATE]);

	if ((ctx_p->flags[EXITONNOEVENTS]) && (ret == 0)) {
		// if not events and "--exit-on-no-events" is set
		if (ctx_p->flags[PREEXITHOOK])
			ctx_p->state = STATE_PREEXIT;
		else
			ctx_p->state = STATE_EXIT;
	}

	return ret;
}

#define SYNC_LOOP_IDLE {\
	int ret;\
	if((ret=sync_idle(ctx_p, indexes_p))) {\
		error("got error while sync_idle().");\
		return ret;\
	}\
}

#define SYNC_LOOP_CONTINUE_UNLOCK {\
	pthread_cond_broadcast(&threadsinfo_p->cond[PTHREAD_MUTEX_STATE]);\
	debug(4, "pthread_mutex_unlock()");\
	pthread_mutex_unlock(&threadsinfo_p->mutex[PTHREAD_MUTEX_STATE]);\
	continue;\
}

void hook_preexit(ctx_t *ctx_p) {
	debug(2, "\"%s\" \"%s\"", ctx_p->preexithookfile, ctx_p->label);

#ifdef VERYPARANOID
	if (ctx_p->preexithookfile == NULL)
		critical("ctx_p->preexithookfile == NULL");
#endif

	char *argv[] = { ctx_p->preexithookfile, ctx_p->label, NULL};
	exec_argv(argv, NULL);

	return;
}

int sync_loop(ctx_t *ctx_p, indexes_t *indexes_p) {
	int ret;
	threadsinfo_t *threadsinfo_p = thread_info();
	state_p = &ctx_p->state;
	ctx_p->state = ctx_p->flags[SKIPINITSYNC] ? STATE_RUNNING : STATE_INITSYNC;

	while (ctx_p->state != STATE_EXIT) {
		int events;

		debug(4, "pthread_mutex_lock()");
		pthread_mutex_lock(&threadsinfo_p->mutex[PTHREAD_MUTEX_STATE]);
		debug(3, "current state is %i (iteration: %u/%u); threadsinfo_p->used == %u",
			ctx_p->state, ctx_p->iteration_num, ctx_p->flags[MAXITERATIONS], threadsinfo_p->used);

		while ((ctx_p->flags[THREADING] == PM_OFF) && threadsinfo_p->used) {
			debug(1, "We are in non-threading mode but have %u syncer threads. Waiting for them end.", threadsinfo_p->used);

			pthread_cond_wait(&threadsinfo_p->cond[PTHREAD_MUTEX_STATE], &threadsinfo_p->mutex[PTHREAD_MUTEX_STATE]);
			pthread_mutex_unlock(&threadsinfo_p->mutex[PTHREAD_MUTEX_STATE]);
		}

		events = 0;
		switch (ctx_p->state) {
			case STATE_THREAD_GC:
				main_status_update(ctx_p);
				if (thread_gc(ctx_p)) {
					ctx_p->state = STATE_EXIT;
					break;
				}
				ctx_p->state = STATE_RUNNING;
				SYNC_LOOP_CONTINUE_UNLOCK;
			case STATE_INITSYNC:
				if (!ctx_p->flags[THREADING]) {
					ctx_p->iteration_num = 0;
					setenv_iteration(ctx_p->iteration_num);
				}

				main_status_update(ctx_p);
				pthread_cond_broadcast(&threadsinfo_p->cond[PTHREAD_MUTEX_STATE]);
				pthread_mutex_unlock(&threadsinfo_p->mutex[PTHREAD_MUTEX_STATE]);
				ret = sync_initialsync(ctx_p->watchdir, ctx_p, indexes_p, INITSYNC_FULL);
				if(ret) return ret;

				if(ctx_p->flags[ONLYINITSYNC]) {
					SYNC_LOOP_IDLE;
					ctx_p->state = STATE_EXIT;
					return ret;
				}

				ctx_p->state = STATE_RUNNING;
				continue;
			case STATE_PREEXIT:
			case STATE_RUNNING:
				if ((!ctx_p->flags[THREADING]) && ctx_p->flags[MAXITERATIONS]) {
					if (ctx_p->flags[MAXITERATIONS] == ctx_p->iteration_num-1)
						ctx_p->state = STATE_PREEXIT;
					else
					if (ctx_p->flags[MAXITERATIONS] <= ctx_p->iteration_num)
						ctx_p->state = STATE_EXIT;
				}

				switch (ctx_p->state) {
					case STATE_PREEXIT:
						main_status_update(ctx_p);
						if (ctx_p->flags[PREEXITHOOK])
							hook_preexit(ctx_p);

						ctx_p->state = STATE_TERM;
					case STATE_RUNNING:
						events = notify_wait(ctx_p, indexes_p);
						break;
					default:
						SYNC_LOOP_CONTINUE_UNLOCK;
				}

				break;
			case STATE_REHASH:
				main_status_update(ctx_p);
				debug(1, "rehashing.");
				main_rehash(ctx_p);
				ctx_p->state = STATE_RUNNING;
				SYNC_LOOP_CONTINUE_UNLOCK;
			case STATE_TERM:
				main_status_update(ctx_p);
				ctx_p->state = STATE_EXIT;
			case STATE_EXIT:
				main_status_update(ctx_p);
				SYNC_LOOP_CONTINUE_UNLOCK;
			default:
				critical("internal error: ctx_p->state == %u", ctx_p->state);
				break;
		}

		pthread_cond_broadcast(&threadsinfo_p->cond[PTHREAD_MUTEX_STATE]);
		pthread_mutex_unlock(&threadsinfo_p->mutex[PTHREAD_MUTEX_STATE]);

		if (events == 0) {
			debug(2, "sync_x_wait(ctx_p, indexes_p) timed-out.");
			SYNC_LOOP_IDLE;
			continue;	// Timeout
		}
		if (events  < 0) {
			error("Got error while waiting for event from notify subsystem.");
			return errno;
		}

		int count = ctx_p->notifyenginefunct.handle(ctx_p, indexes_p);
		if (count  <= 0) {
			error("Cannot handle with notify events.");
			return errno;
		}
		main_status_update(ctx_p);

		if (ctx_p->flags[EXITONNOEVENTS]) // clsync exits on no events, so sync_idle() is never called. We have to force the calling of it.
			SYNC_LOOP_IDLE;
	}

	SYNC_LOOP_IDLE;

	debug(1, "end");
	return exitcode;

#ifdef DOXYGEN
	sync_idle(0, NULL, NULL);
#endif
}

void sync_sig_int(int signal) {
	debug(2, "%i: Thread %p", signal, pthread_self());
	return;
}

int sync_tryforcecycle(pthread_t pthread_parent) {
	debug(3, "sending signal to interrupt blocking operations like select()-s and so on");
	pthread_kill(pthread_parent, SIGUSR_BLOPINT);
#ifdef PARANOID
	int i=0;
	if (++i > KILL_TIMEOUT) {
		error("Seems we got a deadlock.");
		return EDEADLK;
	}
#endif

#ifdef SYNC_SWITCHSTATE_COND_TIMEDWAIT // Hangs
	struct timespec time_timeout;
	clock_gettime(CLOCK_REALTIME, &time_timeout);
	time_timeout.tv_sec++;
//		time_timeout.tv_sec  = now.tv_sec;
	debug(3, "pthread_cond_timedwait() until %li.%li", time_timeout.tv_sec, time_timeout.tv_nsec);
	if (pthread_cond_timedwait(pthread_cond_state, pthread_mutex_state, &time_timeout) != ETIMEDOUT)
		return 0;
#else
	sleep(1);	// TODO: replace this with pthread_cond_timedwait()
#endif

	return EINPROGRESS;
}

int sync_switch_state(pthread_t pthread_parent, int newstate) {
	if (state_p == NULL) {
		debug(3, "sync_switch_state(%p, %i), but state_p == NULL", pthread_parent, newstate);
		return 0;
	}

	debug(3, "sync_switch_state(%p, %i)", pthread_parent, newstate);

	// Getting mutexes
	threadsinfo_t *threadsinfo_p = thread_info();
	if (threadsinfo_p == NULL) {
		// If no mutexes, just change the state
		goto l_sync_parent_interrupt_end;
	}
	if (!threadsinfo_p->mutex_init) {
		// If no mutexes, just change the state
		goto l_sync_parent_interrupt_end;
	}
	pthread_mutex_t *pthread_mutex_state  = &threadsinfo_p->mutex[PTHREAD_MUTEX_STATE];
	pthread_mutex_t *pthread_mutex_select = &threadsinfo_p->mutex[PTHREAD_MUTEX_SELECT];
	pthread_cond_t  *pthread_cond_state   = &threadsinfo_p->cond [PTHREAD_MUTEX_STATE];

	// Locking all necessary mutexes
	debug(4, "while(pthread_mutex_trylock( pthread_mutex_state ))");
	while (pthread_mutex_trylock(pthread_mutex_state) == EBUSY) {
		int rc = sync_tryforcecycle(pthread_parent);
		if (rc && rc != EINPROGRESS)
			return rc;
		if (!rc)
			break;
	}
	debug(4, "while(pthread_mutex_trylock( pthread_mutex_select ))");
	while (pthread_mutex_trylock(pthread_mutex_select) == EBUSY) {
		int rc = sync_tryforcecycle(pthread_parent);
		if (rc && rc != EINPROGRESS)
			return rc;
		if (!rc)
			break;
	}
	// Changing the state

	*state_p = newstate;

#ifdef PARANOID
	pthread_kill(pthread_parent, SIGUSR_BLOPINT);
#endif

	// Unlocking mutexes

	debug(4, "pthread_cond_broadcast(). New state is %i.", *state_p);
	pthread_cond_broadcast(pthread_cond_state);
	debug(4, "pthread_mutex_unlock( pthread_mutex_state )");
	pthread_mutex_unlock(pthread_mutex_state);
	debug(4, "pthread_mutex_unlock( pthread_mutex_select )");
	pthread_mutex_unlock(pthread_mutex_select);

	return thread_info_unlock(0);

l_sync_parent_interrupt_end:

	*state_p = newstate;
	pthread_kill(pthread_parent, SIGUSR_BLOPINT);

	return thread_info_unlock(0);
}

/* === DUMP === */

enum dump_dirfd_obj {
	DUMP_DIRFD_ROOT = 0,
	DUMP_DIRFD_QUEUE,
	DUMP_DIRFD_THREAD,

	DUMP_DIRFD_MAX
};

enum dump_ltype {
	DUMP_LTYPE_INCLUDE,
	DUMP_LTYPE_EXCLUDE,
	DUMP_LTYPE_EVINFO,
};

struct sync_dump_arg {
	ctx_t 		*ctx_p;
	int 		 dirfd[DUMP_DIRFD_MAX];
	int		 fd_out;
	int		 data;
};

void sync_dump_liststep(gpointer fpath_gp, gpointer evinfo_gp, gpointer arg_gp) {
	char *fpath			=         (char *)fpath_gp;
	eventinfo_t *evinfo		=  (eventinfo_t *)evinfo_gp;
	struct sync_dump_arg *arg 	= 		  arg_gp;
	char act, num;

	if (fpath == NULL || evinfo == NULL)
		return;

	switch (arg->data) {
		case DUMP_LTYPE_INCLUDE:
			act = '+';
			num = '1';
			break;
		case DUMP_LTYPE_EXCLUDE:
			act = '-';
			num = '1';
			break;
		case DUMP_LTYPE_EVINFO:
			act = '+';
			num = 	 evinfo->flags&EVIF_RECURSIVELY        ? '*' : 
				(evinfo->flags&EVIF_CONTENTRECURSIVELY ? '/' : '1');
			break;
		default:
			act = '?';
			num = '?';
	}

	dprintf(arg->fd_out, "%c%c\t%s\n", act, num, fpath);

	return;
}

int sync_dump_thread(threadinfo_t *threadinfo_p, void *_arg) {
	struct sync_dump_arg *arg = _arg;
	char buf[BUFSIZ];

	snprintf(buf, BUFSIZ, "%u-%u-%lx", threadinfo_p->iteration, threadinfo_p->thread_num, (long)threadinfo_p->pthread);

	arg->fd_out = openat(arg->dirfd[DUMP_DIRFD_THREAD], buf, O_WRONLY|O_CREAT, DUMP_FILEMODE);
	if (arg->fd_out == -1)
		return errno;

	{
		char **argv;

		dprintf(arg->fd_out, 
			"thread:\n\titeration == %u\n\tnum == %u\n\tpthread == %lx\n\tstarttime == %lu\n\texpiretime == %lu\n\tchild_pid == %u\n\ttry_n == %u\nCommand:",
				threadinfo_p->iteration,
				threadinfo_p->thread_num,
				(long)threadinfo_p->pthread,
				threadinfo_p->starttime,
				threadinfo_p->expiretime,
				threadinfo_p->child_pid,
				threadinfo_p->try_n
			);

		argv = threadinfo_p->argv;
		while (*argv != NULL)
			dprintf(arg->fd_out, " \"%s\"", *(argv++));

		dprintf(arg->fd_out, "\n");
	}

	arg->data = DUMP_LTYPE_EVINFO;
	g_hash_table_foreach(threadinfo_p->fpath2ei_ht, sync_dump_liststep, arg);

	close(arg->fd_out);

	return 0;
}

int sync_dump(ctx_t *ctx_p, const char *const dir_path) {
	indexes_t	*indexes_p	= ctx_p->indexes_p;

	int rootfd, fd_out;
	struct sync_dump_arg arg = {0};
	enum dump_dirfd_obj dirfd_obj;

	arg.ctx_p	 = ctx_p;

	debug(3, "%s", dir_path);

	if (dir_path == NULL)
		return EINVAL;

	static const char *const subdirs[] = {
		[DUMP_DIRFD_QUEUE]	= "queue",
		[DUMP_DIRFD_THREAD]	= "threads"
	};

	errno = 0;

	rootfd = mkdirat_open(dir_path, AT_FDCWD, DUMP_DIRMODE);
	if (rootfd == -1) {
		error("Cannot open directory \"%s\"", dir_path);
		goto l_sync_dump_end;
	}

	fd_out = openat(rootfd, "instance", O_WRONLY|O_CREAT, DUMP_FILEMODE);
	if (fd_out == -1) {
		error("Cannot open file \"%s\" for writing");
		goto l_sync_dump_end;
	}

	dprintf(fd_out, "status == %s\n", getenv("CLSYNC_STATUS"));	// TODO: remove getenv() from here
	arg.fd_out = fd_out;
	arg.data   = DUMP_LTYPE_EVINFO;
	if (indexes_p->nonthreaded_syncing_fpath2ei_ht != NULL)
		g_hash_table_foreach(indexes_p->nonthreaded_syncing_fpath2ei_ht, sync_dump_liststep, &arg);

	close(fd_out);

	arg.dirfd[DUMP_DIRFD_ROOT] = rootfd;

	dirfd_obj = DUMP_DIRFD_ROOT+1;
	while (dirfd_obj < DUMP_DIRFD_MAX) {
		const char *const subdir = subdirs[dirfd_obj];

		arg.dirfd[dirfd_obj] = mkdirat_open(subdir, rootfd, DUMP_DIRMODE);
		if (arg.dirfd[dirfd_obj] == -1) {
			error("Cannot open directory \"%s\"", subdir);
			goto l_sync_dump_end;
		}

		dirfd_obj++;
	}

	int queue_id = 0;
	while (queue_id < QUEUE_MAX) {
		char buf[BUFSIZ];
		snprintf(buf, BUFSIZ, "%u", queue_id);

		arg.fd_out = openat(arg.dirfd[DUMP_DIRFD_QUEUE], buf, O_WRONLY|O_CREAT, DUMP_FILEMODE);

		arg.data = DUMP_LTYPE_EVINFO;
		g_hash_table_foreach(indexes_p->fpath2ei_coll_ht[queue_id],  sync_dump_liststep, &arg);
		if (indexes_p->exc_fpath_coll_ht[queue_id] != NULL) {
			arg.data = DUMP_LTYPE_EXCLUDE;
			g_hash_table_foreach(indexes_p->exc_fpath_coll_ht[queue_id], sync_dump_liststep, &arg);
		}

		close(arg.fd_out);
		queue_id++;
	}

	threads_foreach(sync_dump_thread, STATE_RUNNING, &arg);

l_sync_dump_end:
	dirfd_obj = DUMP_DIRFD_ROOT;
	while (dirfd_obj < DUMP_DIRFD_MAX) {
		if (arg.dirfd[dirfd_obj] != -1 && arg.dirfd[dirfd_obj] != 0)
			close(arg.dirfd[dirfd_obj]);
		dirfd_obj++;
	}

	if (errno)
		error("Cannot create the dump to \"%s\"", dir_path);

	return errno;
}

/* === /DUMP === */

int *sync_sighandler_exitcode_p = NULL;
int sync_sighandler(sighandler_arg_t *sighandler_arg_p) {
	int signal = 0, ret;
	ctx_t *ctx_p		 = sighandler_arg_p->ctx_p;
//	indexes_t *indexes_p	 = sighandler_arg_p->indexes_p;
	pthread_t pthread_parent = sighandler_arg_p->pthread_parent;
	sigset_t *sigset_p	 = sighandler_arg_p->sigset_p;
	int *exitcode_p		 = sighandler_arg_p->exitcode_p;

	sync_sighandler_exitcode_p = exitcode_p;

	while (state_p == NULL || ((ctx_p->state != STATE_TERM) && (ctx_p->state != STATE_EXIT))) {
		debug(3, "waiting for signal");
		ret = sigwait(sigset_p, &signal);

		if (state_p == NULL) {

			switch (signal) {
				case SIGALRM:
					*exitcode_p = ETIME;
				case SIGQUIT:
				case SIGTERM:
				case SIGINT:
					// TODO: remove the exit() from here. Main thread should exit itself
					exit(*exitcode_p);
					break;
				default:
					warning("Got signal %i, but the main loop is not started, yet. Ignoring the signal.", signal);
					break;
			}
			continue;
		}

		debug(3, "got signal %i. ctx_p->state == %i.", signal, ctx_p->state);

		if (ret) {
			// TODO: handle an error here
		}

		if (ctx_p->customsignal[signal] != NULL) {
			if (config_block_parse(ctx_p, ctx_p->customsignal[signal])) {
				*exitcode_p = errno;
				 signal = SIGTERM;
			}
			continue;
		}

		switch (signal) {
			case SIGALRM:
				*exitcode_p = ETIME;
			case SIGQUIT:
				if (ctx_p->flags[PREEXITHOOK])
					sync_switch_state(pthread_parent, STATE_PREEXIT);
				else
					sync_switch_state(pthread_parent, STATE_TERM);
				break;
			case SIGTERM:
			case SIGINT:
				sync_switch_state(pthread_parent, STATE_TERM);
				// bugfix of https://github.com/xaionaro/clsync/issues/44
				while (ctx_p->children) { // Killing children if non-pthread mode or/and (mode=="so" or mode=="rsyncso")
					pid_t child_pid = ctx_p->child_pid[--ctx_p->children];

					if (privileged_kill_child(child_pid, signal) == ENOENT)
						continue;
					if (signal != SIGQUIT)
						if (privileged_kill_child(child_pid, SIGQUIT) == ENOENT)
							continue;
					if (signal != SIGTERM)
						if (privileged_kill_child(child_pid, SIGTERM) == ENOENT)
							continue;
					if (privileged_kill_child(child_pid, SIGKILL) == ENOENT)
						continue;
				}
				break;
			case SIGHUP:
				sync_switch_state(pthread_parent, STATE_REHASH);
				break;
			case SIGUSR_THREAD_GC:
				sync_switch_state(pthread_parent, STATE_THREAD_GC);
				break;
			case SIGUSR_INITSYNC:
				sync_switch_state(pthread_parent, STATE_INITSYNC);
				break;
			case SIGUSR_DUMP:
				sync_dump(ctx_p, ctx_p->dump_path);
				break;
			default:
				error("Unknown signal: %i. Exit.", signal);
				sync_switch_state(pthread_parent, STATE_TERM);
				break;
		}

	}

	debug(3, "signal handler closed.");
	return 0;
}

int sync_term(int exitcode) {
	*sync_sighandler_exitcode_p = exitcode;
	return pthread_kill(pthread_sighandler, SIGTERM);
}


int sync_run(ctx_t *ctx_p) {
	int ret;
	sighandler_arg_t sighandler_arg = {0};
	indexes_t        indexes        = {NULL};

	// Creating signal handler thread
	{
		int i;

		sigset_t sigset_sighandler;
		sigemptyset(&sigset_sighandler);
		sigaddset(&sigset_sighandler, SIGALRM);
		sigaddset(&sigset_sighandler, SIGHUP);
		sigaddset(&sigset_sighandler, SIGQUIT);
		sigaddset(&sigset_sighandler, SIGTERM);
		sigaddset(&sigset_sighandler, SIGINT);
		sigaddset(&sigset_sighandler, SIGUSR_THREAD_GC);
		sigaddset(&sigset_sighandler, SIGUSR_INITSYNC);
		sigaddset(&sigset_sighandler, SIGUSR_DUMP);

		i = 0;
		while (i < MAXSIGNALNUM) {
			if (ctx_p->customsignal[i] != NULL)
				sigaddset(&sigset_sighandler, i);
			i++;
		}

		ret = pthread_sigmask(SIG_BLOCK, &sigset_sighandler, NULL);
		if (ret) return ret;

		sighandler_arg.ctx_p		=  ctx_p;
		sighandler_arg.pthread_parent	=  pthread_self();
		sighandler_arg.exitcode_p	= &ret;
		sighandler_arg.sigset_p		= &sigset_sighandler;
		ret = pthread_create(&pthread_sighandler, NULL, (void *(*)(void *))sync_sighandler, &sighandler_arg);
		if (ret) return ret;

		sigset_t sigset_parent;
		sigemptyset(&sigset_parent);

		sigaddset(&sigset_parent, SIGUSR_BLOPINT);
		ret = pthread_sigmask(SIG_UNBLOCK, &sigset_parent, NULL);
		if (ret) return ret;

		signal(SIGUSR_BLOPINT,	sync_sig_int);
	}

	if ((ret=privileged_init(ctx_p)))
		return ret;

	// Creating hash tables
	{
		int i;

		ctx_p->indexes_p	  = &indexes;

		indexes.wd2fpath_ht	  =  g_hash_table_new_full(g_direct_hash, g_direct_equal, 0,    0);
		indexes.fpath2wd_ht	  =  g_hash_table_new_full(g_str_hash,	 g_str_equal,	 free, 0);
		indexes.fpath2ei_ht	  =  g_hash_table_new_full(g_str_hash,	 g_str_equal,	 free, free);
		indexes.exc_fpath_ht	  =  g_hash_table_new_full(g_str_hash,	 g_str_equal,	 free, 0);
		indexes.out_lines_aggr_ht =  g_hash_table_new_full(g_str_hash,	 g_str_equal,	 free, 0);
		i=0;
		while (i<QUEUE_MAX) {
			switch (i) {
				case QUEUE_LOCKWAIT:
					indexes.fpath2ei_coll_ht[i]  = g_hash_table_new_full(g_str_hash,    g_str_equal,    free, 0);
					break;
				default:
					indexes.fpath2ei_coll_ht[i]  = g_hash_table_new_full(g_str_hash,    g_str_equal,    free, free);
					indexes.exc_fpath_coll_ht[i] = g_hash_table_new_full(g_str_hash,    g_str_equal,    free, 0);
			}
			i++;
		}
	}

	// Loading dynamical libraries
	if (ctx_p->flags[MODE] == MODE_SO || ctx_p->flags[MODE] == MODE_RSYNCSO) {
		/* security checks before dlopen */
		struct stat so_stat;
		if (stat(ctx_p->handlerfpath, &so_stat) == -1) {
			error("Can't stat shared object file \"%s\": %s", ctx_p->handlerfpath, strerror(errno));
			return errno;
		}
		// allow normal files only (stat will follow symlinks)
		if (!S_ISREG(so_stat.st_mode)) {
			error("Shared object \"%s\" must be a regular file (or symlink to a regular file).",
				ctx_p->handlerfpath, so_stat.st_uid);
			return EPERM;
		}
		// allowed owners are: root and real uid (who started clsync prior to setuid)
		if (so_stat.st_uid && so_stat.st_uid != getuid()) {
			/* check for rare case when clsync binary owner is neither root nor current uid */
			struct stat cl_stat;
			char *cl_str = alloca(20); // allocate for "/proc/PID/exe"
			int ret;
			snprintf(cl_str, 20, "/proc/%i/exe", getpid());
			// stat clsync binary itself to get its owner's uid
			if ((ret = stat(cl_str, &cl_stat)) == -1) {
				error("Can't stat clsync binary file \"%s\": %s", cl_str, strerror(errno));
			}
			if (ret == -1 || so_stat.st_uid != cl_stat.st_uid) {
				error("Wrong owner for shared object \"%s\": %i"
					"Only root, clsync file owner and user started the program are allowed.",
				ctx_p->handlerfpath, so_stat.st_uid);
				return EPERM;
			}
		}
		// do not allow special bits and g+w,o+w
		if (so_stat.st_mode & (S_ISUID | S_ISGID | S_ISVTX | S_IWGRP | S_IWOTH)) {
			error("Wrong shared object \"%s\" permissions: %#lo"
				"Special bits, group and world writable are not allowed.",
				ctx_p->handlerfpath, so_stat.st_mode & 07777);
			return EPERM;
		}

		// dlopen()
		void *synchandler_handle = dlopen(ctx_p->handlerfpath, RTLD_NOW|RTLD_LOCAL);
		if(synchandler_handle == NULL) {
			error("Cannot load shared object file \"%s\": %s", ctx_p->handlerfpath, dlerror());
			return -1;
		}

		// resolving init, sync and deinit functions' handlers
		ctx_p->handler_handle = synchandler_handle;
		ctx_p->handler_funct.init   = (api_funct_init)  dlsym(ctx_p->handler_handle, API_PREFIX"init");
		if(ctx_p->flags[MODE] == MODE_RSYNCSO) {
			ctx_p->handler_funct.rsync  = (api_funct_rsync)dlsym(ctx_p->handler_handle, API_PREFIX"rsync");
			if(ctx_p->handler_funct.rsync == NULL) {
				char *dlerror_str = dlerror();
				error("Cannot resolve symbol "API_PREFIX"rsync in shared object \"%s\": %s",
					ctx_p->handlerfpath, dlerror_str != NULL ? dlerror_str : "No error description returned.");
			}
		} else {
			ctx_p->handler_funct.sync   =  (api_funct_sync)dlsym(ctx_p->handler_handle, API_PREFIX"sync");
			if(ctx_p->handler_funct.sync == NULL) {
				char *dlerror_str = dlerror();
				error("Cannot resolve symbol "API_PREFIX"sync in shared object \"%s\": %s",
					ctx_p->handlerfpath, dlerror_str != NULL ? dlerror_str : "No error description returned.");
			}
		}
		ctx_p->handler_funct.deinit = (api_funct_deinit)dlsym(ctx_p->handler_handle, API_PREFIX"deinit");

		// running init function
		if(ctx_p->handler_funct.init != NULL)
			if((ret = ctx_p->handler_funct.init(ctx_p, &indexes))) {
				error("Cannot init sync-handler module.");
				return ret;
			}
	}

#ifdef CLUSTER_SUPPORT
	// Initializing cluster subsystem

	if(ctx_p->cluster_iface != NULL) {
		ret = cluster_init(ctx_p, &indexes);
		if(ret) {
			error("Cannot initialize cluster subsystem.");
			cluster_deinit();
			return ret;
		}
	}
#endif

	// Initializing rand-generator if it's required

	if(ctx_p->listoutdir)
		srand(time(NULL));

	{
		// Preparing monitor subsystem context function pointers
		switch (ctx_p->flags[MONITOR]) {
#ifdef INOTIFY_SUPPORT
			case NE_INOTIFY:
				ctx_p->notifyenginefunct.add_watch_dir = inotify_add_watch_dir;
				ctx_p->notifyenginefunct.wait          = inotify_wait;
				ctx_p->notifyenginefunct.handle        = inotify_handle;
				break;
#endif
#ifdef KQUEUE_SUPPORT
			case NE_KQUEUE:
				ctx_p->notifyenginefunct.add_watch_dir = kqueue_add_watch_dir;
				ctx_p->notifyenginefunct.wait          = kqueue_wait;
				ctx_p->notifyenginefunct.handle        = kqueue_handle;
				break;
#endif
#ifdef BSM_SUPPORT
			case NE_BSM:
				ctx_p->notifyenginefunct.add_watch_dir = bsm_add_watch_dir;
				ctx_p->notifyenginefunct.wait          = bsm_wait;
				ctx_p->notifyenginefunct.handle        = bsm_handle;
				break;
#endif
#ifdef DTRACEPIPE_SUPPORT
			case NE_DTRACEPIPE:
				ctx_p->notifyenginefunct.add_watch_dir = dtracepipe_add_watch_dir;
				ctx_p->notifyenginefunct.wait          = dtracepipe_wait;
				ctx_p->notifyenginefunct.handle        = dtracepipe_handle;
				break;
#endif
#ifdef VERYPARANOID
			default:
				critical("Unknown FS monitor subsystem: %i", ctx_p->flags[MONITOR]);
#endif
		}
	}

#ifdef ENABLE_SOCKET
	// Creating control socket
	if(ctx_p->socketpath != NULL)
		ret = control_run(ctx_p);
#endif

	if(!ctx_p->flags[ONLYINITSYNC]) {

		// Initializing FS monitor kernel subsystem in this userspace application

		if(sync_notify_init(ctx_p))
			return errno;

		// Marking file tree for FS monitor
		ret = sync_mark_walk(ctx_p, ctx_p->watchdir, &indexes);
		if(ret) return ret;

	}

	// "Infinite" loop of processling the events
	ret = sync_loop(ctx_p, &indexes);
	if (ret) return ret;
	debug(1, "sync_loop() ended");

#ifdef ENABLE_SOCKET
	// Removing control socket
	if (ctx_p->socketpath != NULL)
		control_cleanup(ctx_p);
#endif

	debug(1, "killing sighandler");
	// TODO: Do cleanup of watching points
	pthread_kill(pthread_sighandler, SIGINT);
	pthread_join(pthread_sighandler, NULL);

	// Killing children

	thread_cleanup(ctx_p);

	// Closing rest sockets and files

	switch (ctx_p->flags[MONITOR]) {
#ifdef INOTIFY_SUPPORT
		case NE_INOTIFY:
			inotify_deinit(ctx_p);
			break;
#endif
#ifdef KQUEUE_SUPPORT
		case NE_KQUEUE:
			kqueue_deinit(ctx_p);
			break;
#endif
#ifdef BSM_SUPPORT
		case NE_BSM:
			bsm_deinit(ctx_p);
			break;
#endif
#ifdef DTRACEPIPE_SUPPORT
		case NE_DTRACEPIPE:
			dtracepipe_deinit(ctx_p);
			break;
#endif
	}

	// Closing shared libraries
	if (ctx_p->flags[MODE] == MODE_SO) {
		int _ret;
		if (ctx_p->handler_funct.deinit != NULL)
			if ((_ret = ctx_p->handler_funct.deinit())) {
				error("Cannot deinit sync-handler module.");
				if(!ret) ret = _ret;
			}

		if (dlclose(ctx_p->handler_handle)) {
			error("Cannot unload shared object file \"%s\": %s",
				ctx_p->handlerfpath, dlerror());
			if (!ret) ret = -1;
		}
	}

	// Cleaning up run-time routines
	rsync_escape_cleanup();

	// Removing hash-tables
	{
		int i;

		debug(3, "Closing hash tables");
		g_hash_table_destroy(indexes.wd2fpath_ht);
		g_hash_table_destroy(indexes.fpath2wd_ht);
		g_hash_table_destroy(indexes.fpath2ei_ht);
		g_hash_table_destroy(indexes.exc_fpath_ht);
		g_hash_table_destroy(indexes.out_lines_aggr_ht);
		i = 0;
		while (i<QUEUE_MAX) {
			switch (i) {
				case QUEUE_LOCKWAIT:
					g_hash_table_destroy(indexes.fpath2ei_coll_ht[i]);
					break;
				default:
					g_hash_table_destroy(indexes.fpath2ei_coll_ht[i]);
					g_hash_table_destroy(indexes.exc_fpath_coll_ht[i]);
			}
			i++;
		}
	}

	// Deinitializing cluster subsystem
#ifdef CLUSTER_SUPPORT
	if (ctx_p->cluster_iface != NULL) {
		int _ret;
		_ret = cluster_deinit();
		if (_ret) {
			error("Cannot deinitialize cluster subsystem.", strerror(_ret), _ret);
			ret = _ret;
		}
	}
#endif

#ifdef VERYPARANOID
	// One second for another threads
	sleep(1);
#endif

	if (ctx_p->flags[EXITHOOK]) {
		char *argv[] = { ctx_p->exithookfile, ctx_p->label, NULL};
		exec_argv(argv, NULL);
	}

	ret |= privileged_deinit(ctx_p);

	return ret;
}

