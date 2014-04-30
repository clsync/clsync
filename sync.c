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


#include "common.h"
#include "main.h"
#include "error.h"
#include "fileutils.h"
#include "malloc.h"
#include "cluster.h"
#include "sync.h"
#include "glibex.h"
#include "control.h"

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

static inline void evinfo_merge(eventinfo_t *evinfo_dst, eventinfo_t *evinfo_src) {
	debug(3, "evinfo_dst: seqid_min == %u; seqid_max == %u; objtype_old == %i; objtype_new == %i; \t"
			"evinfo_src: seqid_min == %u; seqid_max == %u; objtype_old == %i; objtype_new == %i",
			evinfo_dst->seqid_min, evinfo_dst->seqid_max, evinfo_dst->objtype_old, evinfo_dst->objtype_new,
			evinfo_src->seqid_min, evinfo_src->seqid_max, evinfo_src->objtype_old, evinfo_src->objtype_new
		);

	evinfo_dst->evmask |= evinfo_src->evmask;
	evinfo_dst->flags  |= evinfo_src->flags;

	if(SEQID_LE(evinfo_src->seqid_min, evinfo_dst->seqid_min)) {
		evinfo_dst->objtype_old = evinfo_src->objtype_old;
		evinfo_dst->seqid_min   = evinfo_src->seqid_min;
	}

	if(SEQID_GE(evinfo_src->seqid_max,  evinfo_dst->seqid_max))  {
		evinfo_dst->objtype_new = evinfo_src->objtype_new;
		evinfo_dst->seqid_max   = evinfo_src->seqid_max;
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

/**
 * @brief 			Checks file path by rules' expressions (parsed from file)
 * 
 * @param[in] 	fpath		Path to file of directory
 * @param[in] 	st_mode		st_mode received via *stat() functions
 * @param[in] 	rules_p		Pointer to start of rules array
 * @param[in] 	ruleaction	Operaton ID (see ruleaction_t)
 * @param[i/o] 	rule_pp		Pointer to pointer to rule, where the last search ended. Next search will be started from the specified rule. Can be "NULL" to disable this feature.
 *
 * @retval	perm		Permission bitmask
 * 
 */
// Checks file path by rules' expressions (parsed from file)
// Return: RS_PERMIT or RS_REJECT for the "file path" and specified ruleaction

ruleaction_t rules_search_getperm(const char *fpath, mode_t st_mode, rule_t *rules_p, ruleaction_t ruleaction, rule_t **rule_pp) {
	debug(3, "rules_search_getperm(\"%s\", %p, %p, %p, %p)", 
			fpath, (void *)(unsigned long)st_mode, rules_p,
			(void *)(long)ruleaction, (void *)(long)rule_pp
		);

	int i;
	i = 0;
	rule_t *rule_p = rules_p;
	mode_t ftype = st_mode & S_IFMT;

#ifdef _DEBUG
	debug(3, "Rules (p == %p):", rules_p);
	i=0;
	do {
		debug(3, "\t%i\t%i\t%p/%p", i, rules_p[i].objtype, (void *)(long)rules_p[i].perm, (void *)(long)rules_p[i].mask);
		i++;
	} while(rules_p[i].mask != RA_NONE);
#endif

        i=0;
	if(rule_pp != NULL)
		if(*rule_pp != NULL) {
			debug(3, "Previous position is set.");
			if(rule_p->mask == RA_NONE)
				return rule_p->perm;

			rule_p = ++(*rule_pp);
			i = rule_p->num;
		}

	debug(3, "Starting from position %i", i);
	while(rule_p->mask != RA_NONE) {
		debug(3, "%i -> %p/%p: type compare: %p, %p -> %p", 
				i,
				(void *)(long)rule_p->perm, (void *)(long)rule_p->mask,
				(void *)(unsigned long)ftype, (void *)(unsigned long)rule_p->objtype, 
				(unsigned char)!(rule_p->objtype && (rule_p->objtype != ftype))
			);

		if(!(rule_p->mask & ruleaction)) {	// Checking wrong operation type
			debug(3, "action-mask mismatch. Skipping.");
			rule_p++;i++;// = &rules_p[++i];
			continue;
		}

		if(rule_p->objtype && (rule_p->objtype != ftype)) {
			debug(3, "objtype mismatch. Skipping.");
			rule_p++;i++;// = &rules_p[++i];
			continue;
		}

		if(!regexec(&rule_p->expr, fpath, 0, NULL, 0))
			break;

		debug(3, "doesn't match regex. Skipping.");
		rule_p++;i++;// = &rules_p[++i];

	}

	debug(2, "matched to rule #%u for \"%s\":\t%p/%p (queried: %p).", rule_p->mask==RA_NONE?-1:i, fpath, 
			(void *)(long)rule_p->perm, (void *)(long)rule_p->mask,
			(void *)(long)ruleaction
		);

	if(rule_pp != NULL)
		*rule_pp = rule_p;

	return rule_p->perm;
}

static inline ruleaction_t rules_getperm(const char *fpath, mode_t st_mode, rule_t *rules_p, ruleaction_t ruleactions) {
	rule_t *rule_p = NULL;
	ruleaction_t gotpermto  = 0;
	ruleaction_t resultperm = 0;
	debug(3, "rules_getperm(\"%s\", %p, %p (#%u), %p)", 
		fpath, (void *)(long)st_mode, rules_p, rules_p->num, (void *)(long)ruleactions);

	while((gotpermto&ruleactions) != ruleactions) {
		rules_search_getperm(fpath, st_mode, rules_p, ruleactions, &rule_p);
		if(rule_p->mask == RA_NONE) { // End of rules' list 
			resultperm |= rule_p->perm & (gotpermto^RA_ALL);
			break;
		}
		resultperm |= rule_p->perm & ((gotpermto^rule_p->mask)&rule_p->mask);	// Adding perm bitmask of operations that was unknown before
		gotpermto  |= rule_p->mask;						// Adding the mask
	}

	debug(3, "rules_getperm(\"%s\", %p, rules_p, %p): result perm is %p",
		fpath, (void *)(long)st_mode, (void *)(long)ruleactions, (void *)(long)resultperm);

	return resultperm;
}

// Removes necessary rows from hash_tables if some watching descriptor closed
// Return: 0 on success, non-zero on fail

static inline int indexes_remove_bywd(indexes_t *indexes_p, int wd) {
	int ret=0;

	char *fpath = g_hash_table_lookup(indexes_p->wd2fpath_ht, GINT_TO_POINTER(wd));

	ret |= g_hash_table_remove(indexes_p->wd2fpath_ht, GINT_TO_POINTER(wd));
	if(fpath == NULL) {
		error("Cannot remove from index \"fpath2wd\" by wd %i.", wd);
		return -1;
	}
	ret |= g_hash_table_remove(indexes_p->fpath2wd_ht, fpath);

	return ret;
}

// Adds necessary rows to hash_tables if some watching descriptor opened
// Return: 0 on success, non-zero on fail

static inline int indexes_add_wd(indexes_t *indexes_p, int wd, const char *fpath_const, size_t fpathlen) {
	debug(3, "indexes_add_wd(indexes_p, %i, \"%s\", %i)", wd, fpath_const, fpathlen);

	char *fpath = xmalloc(fpathlen+1);
	memcpy(fpath, fpath_const, fpathlen+1);
	g_hash_table_insert(indexes_p->wd2fpath_ht, GINT_TO_POINTER(wd), fpath);
	g_hash_table_insert(indexes_p->fpath2wd_ht, fpath, GINT_TO_POINTER(wd));

	return 0;
}

// Lookups file path by watching descriptor from hash_tables
// Return: file path on success, NULL on fail

static inline char *indexes_wd2fpath(indexes_t *indexes_p, int wd) {
	return g_hash_table_lookup(indexes_p->wd2fpath_ht, GINT_TO_POINTER(wd));
}

//

static inline int indexes_fpath2wd(indexes_t *indexes_p, const char *fpath) {
	gpointer gint_p = g_hash_table_lookup(indexes_p->fpath2wd_ht, fpath);
	if(gint_p == NULL)
		return -1;

	return GPOINTER_TO_INT(gint_p);
}

static inline eventinfo_t *indexes_fpath2ei(indexes_t *indexes_p, const char *fpath) {
	return (eventinfo_t *)g_hash_table_lookup(indexes_p->fpath2ei_ht, fpath);
}

static inline int indexes_fpath2ei_add(indexes_t *indexes_p, char *fpath, eventinfo_t *evinfo) {
	g_hash_table_replace(indexes_p->fpath2ei_ht, fpath, evinfo);

	return 0;
}

static inline int indexes_queueevent(indexes_t *indexes_p, char *fpath, eventinfo_t *evinfo, queue_id_t queue_id) {

	g_hash_table_replace(indexes_p->fpath2ei_coll_ht[queue_id], fpath, evinfo);

	debug(3, "indexes_queueevent(indexes_p, \"%s\", evinfo, %i). It's now %i events collected in queue %i.", fpath, queue_id, g_hash_table_size(indexes_p->fpath2ei_coll_ht[queue_id]), queue_id);
	return 0;
}

static inline eventinfo_t *indexes_lookupinqueue(indexes_t *indexes_p, const char *fpath, queue_id_t queue_id) {
	return (eventinfo_t *)g_hash_table_lookup(indexes_p->fpath2ei_coll_ht[queue_id], fpath);
}

static inline int indexes_queuelen(indexes_t *indexes_p, queue_id_t queue_id) {
	return g_hash_table_size(indexes_p->fpath2ei_coll_ht[queue_id]);
}

static inline int indexes_removefromqueue(indexes_t *indexes_p, char *fpath, queue_id_t queue_id) {
//	debug(3, "indexes_removefromqueue(indexes_p, \"%s\", %i).", fpath, queue_id);

	g_hash_table_remove(indexes_p->fpath2ei_coll_ht[queue_id], fpath);

	debug(3, "indexes_removefromqueue(indexes_p, \"%s\", %i). It's now %i events collected in queue %i.", fpath, queue_id, g_hash_table_size(indexes_p->fpath2ei_coll_ht[queue_id]), queue_id);
	return 0;
}

static inline int indexes_addexclude(indexes_t *indexes_p, char *fpath, eventinfo_flags_t flags, queue_id_t queue_id) {
	g_hash_table_replace(indexes_p->exc_fpath_coll_ht[queue_id], fpath, GINT_TO_POINTER(flags));

	debug(3, "indexes_addexclude(indexes_p, \"%s\", %i). It's now %i events collected in queue %i.", fpath, queue_id, g_hash_table_size(indexes_p->exc_fpath_coll_ht[queue_id]), queue_id);
	return 0;
}

static inline int indexes_addexclude_aggr(indexes_t *indexes_p, char *fpath, eventinfo_flags_t flags) {
	debug(3, "indexes_addexclude_aggr(indexes_p, \"%s\", %u).", fpath, flags);

	gpointer flags_gp = g_hash_table_lookup(indexes_p->exc_fpath_ht, fpath);
	if(flags_gp != NULL)
		flags |= GPOINTER_TO_INT(flags_gp);

	// Removing extra flags
	if((flags&(EVIF_RECURSIVELY | EVIF_CONTENTRECURSIVELY)) == (EVIF_RECURSIVELY | EVIF_CONTENTRECURSIVELY))
		flags &= ~EVIF_CONTENTRECURSIVELY;

	g_hash_table_replace(indexes_p->exc_fpath_ht, fpath, GINT_TO_POINTER(flags));

	debug(3, "indexes_addexclude_aggr(indexes_p, \"%s\", flags): %u.", fpath, flags);
	return 0;
}

static inline int indexes_outaggr_add(indexes_t *indexes_p, char *outline, eventinfo_flags_t flags) {
	gpointer flags_gp = g_hash_table_lookup(indexes_p->out_lines_aggr_ht, outline);
	if(flags_gp != NULL)
		flags |= GPOINTER_TO_INT(flags_gp);

	// Removing extra flags
	if((flags&(EVIF_RECURSIVELY | EVIF_CONTENTRECURSIVELY)) == (EVIF_RECURSIVELY | EVIF_CONTENTRECURSIVELY))
		flags &= ~EVIF_CONTENTRECURSIVELY;

	g_hash_table_replace(indexes_p->out_lines_aggr_ht, outline, GINT_TO_POINTER(flags));

	debug(3, "indexes_outaggr_aggr(indexes_p, \"%s\").", outline);
	return 0;
}

static threadsinfo_t *thread_getinfo() {	// TODO: optimize this
	static threadsinfo_t threadsinfo={{{{0}}},{{{0}}},0};
	if(!threadsinfo.mutex_init) {
		int i=0;
		while(i < PTHREAD_MUTEX_MAX) {
			if(pthread_mutex_init(&threadsinfo.mutex[i], NULL)) {
				error("Cannot pthread_mutex_init().");
				return NULL;
			}
			if(pthread_cond_init (&threadsinfo.cond [i], NULL)) {
				error("Cannot pthread_cond_init().");
				return NULL;
			}
			i++;
		}
		threadsinfo.mutex_init++;
	}
//	pthread_mutex_lock(&threadsinfo._mutex);

	return &threadsinfo;
}

time_t thread_nextexpiretime() {
	time_t nextexpiretime = 0;
	threadsinfo_t *threadsinfo_p = thread_getinfo();
	if(threadsinfo_p == NULL)
		return 0;

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

	debug(3, "nextexpiretime == %i", nextexpiretime);
	return nextexpiretime;
}

threadinfo_t *thread_new() {
	threadsinfo_t *threadsinfo_p = thread_getinfo();
	if(threadsinfo_p == NULL)
		return NULL;

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
	return threadinfo_p;
}

int thread_del_bynum(int thread_num) {
	debug(2, "thread_del_bynum(%i)", thread_num);
	threadsinfo_t *threadsinfo_p = thread_getinfo();
	if(threadsinfo_p == NULL)
		return errno;

	if(thread_num >= threadsinfo_p->used)
		return EINVAL;

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
		return 0;
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
			return EINVAL;
		}
#endif
		threadsinfo_p->threadsstack[threadsinfo_p->stacklen++] = threadinfo_p;
	}

	debug(3, "thread_del_bynum(%i): there're %i threads left (#1).", thread_num, threadsinfo_p->used - threadsinfo_p->stacklen);
	return 0;
}

int thread_gc(ctx_t *ctx_p) {
	int thread_num;
	time_t tm = time(NULL);
	debug(3, "tm == %i; thread %p", tm, pthread_self());
	if(!ctx_p->flags[PTHREAD])
		return 0;

	threadsinfo_t *threadsinfo_p = thread_getinfo();
	if(threadsinfo_p == NULL)
		return errno;

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
				return ETIME;
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
				return errno;

		}

		if(threadinfo_p->errcode) {
			error("Got error from thread #%i: errcode %i.", thread_num, threadinfo_p->errcode);
			thread_del_bynum(thread_num);
			return threadinfo_p->errcode;
		}

		if(thread_del_bynum(thread_num))
			return errno;
	}

	debug(3, "There're %i threads left.", threadsinfo_p->used - threadsinfo_p->stacklen);
	return 0;
}

int thread_cleanup(ctx_t *ctx_p) {
	debug(3, "");
	threadsinfo_t *threadsinfo_p = thread_getinfo();
	if(threadsinfo_p == NULL)
		return errno;

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
				error("Warning: Got error from callback function.", strerror(err), err);
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
	return 0;
}

int *state_p = NULL;
int exitcode = 0;

int exec_argv(char **argv, int *child_pid) {
	debug(3, "Thread %p.", pthread_self());
	pid_t pid;
	int status;

	// Forking
	pid = fork();
	switch(pid) {
		case -1: 
			error("Cannot fork().");
			return errno;
		case  0:
			execvp(argv[0], (char *const *)argv);
			return errno;
	}
//	debug(3, "After fork thread %p"")".", pthread_self() );

	// Setting *child_pid value
	if(child_pid)
		*child_pid = pid;

	// Waiting for process end
#ifdef VERYPARANOID
	sigset_t sigset_exec, sigset_old;
	sigemptyset(&sigset_exec);
	sigaddset(&sigset_exec, SIGUSR_BLOPINT);
	pthread_sigmask(SIG_BLOCK, &sigset_exec, &sigset_old);
#endif

//	debug(3, "Pre-wait thread %p"")".", pthread_self() );
	if(waitpid(pid, &status, 0) != pid) {
		error("Cannot waitid().");
		return errno;
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

#if _DEBUG | VERYPARANOID
	if(threadinfo_p->pthread != pthread_self()) {
		error("pthread id mismatch! (i_p->p) %p != (p) %p""", threadinfo_p->pthread, pthread_self() );
		return EINVAL;
	}
#endif

	if(threadinfo_p->callback) {
		if(threadinfo_p->ctx_p->flags[DEBUG]>2) {
			debug(3, "thread %p, argv: ", threadinfo_p->pthread);
			char **argv = threadinfo_p->argv;
			while(*argv) {
				debug(3, "\t%p == %s", *argv, *argv);
				argv++;
			}
		}
		if((err=threadinfo_p->callback(threadinfo_p->ctx_p, threadinfo_p->argv))) {
			error("Got error from callback function.", strerror(err), err);
			threadinfo_p->errcode = err;
		}
	}

	// Notifying the parent-thread, that it's time to collect garbage threads
	threadinfo_p->state    = STATE_TERM;
	debug(3, "thread %p is sending signal to sighandler to call GC", threadinfo_p->pthread);
	return pthread_kill(pthread_sighandler, SIGUSR_PTHREAD_GC);
}

static inline void so_call_sync_finished(int n, api_eventinfo_t *ei) {
	int i = 0;
	api_eventinfo_t *ei_i = ei;
	while(i < n) {
#ifdef PARANOID
		if(ei_i->path == NULL) {
			error("Warning: so_call_sync_finished(): ei_i->path == NULL");
			i++;
			continue;
		}
#endif
		free((char *)ei_i->path);
		ei_i++;
		i++;
	}
	if(ei != NULL)
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

		if((err=exitcode_process(threadinfo_p->ctx_p, rc))) {
			try_again = ((!ctx_p->retries) || (threadinfo_p->try_n < ctx_p->retries)) && (*state_p != STATE_TERM) && (*state_p != STATE_EXIT);
			error("Warning: so_call_sync_thread(): Bad exitcode %i (errcode %i). %s.", rc, err, try_again?"Retrying":"Give up");
			if(try_again) {
				debug(2, "Sleeping for %u seconds before the retry.", ctx_p->syncdelay);
				sleep(ctx_p->syncdelay);
			}
		}

	} while(err && ((!ctx_p->retries) || (threadinfo_p->try_n < ctx_p->retries)) && (*state_p != STATE_TERM) && (*state_p != STATE_EXIT));

	if(err) {
		error("Bad exitcode %i (errcode %i)", rc, err);
		threadinfo_p->errcode = err;
	}

	so_call_sync_finished(n, ei);

	if((err=thread_exit(threadinfo_p, rc ))) {
		exitcode = err;	// This's global variable "exitcode"
		pthread_kill(pthread_sighandler, SIGTERM);
	}

	return rc;
}

static inline int so_call_sync(ctx_t *ctx_p, indexes_t *indexes_p, int n, api_eventinfo_t *ei) {
	debug(2, "n == %i", n);

	if(!ctx_p->flags[PTHREAD]) {
		int rc=0, ret=0, err=0;
		int try_n=0, try_again;
		do {
			try_again = 0;
			try_n++;

			alarm(ctx_p->synctimeout);
			rc = ctx_p->handler_funct.sync(n, ei);
			alarm(0);

			if((err=exitcode_process(ctx_p, rc))) {
				try_again = ((!ctx_p->retries) || (try_n < ctx_p->retries)) && (*state_p != STATE_TERM) && (*state_p != STATE_EXIT);
				error("Warning: so_call_sync(): Bad exitcode %i (errcode %i). %s.", rc, err, try_again?"Retrying":"Give up");
				if(try_again) {
					debug(2, "Sleeping for %u seconds before the retry.", ctx_p->syncdelay);
					sleep(ctx_p->syncdelay);
				}
			}
		} while(err && ((!ctx_p->retries) || (try_n < ctx_p->retries)) && (*state_p != STATE_TERM) && (*state_p != STATE_EXIT));
		if(err) {
			error("Bad exitcode %i (errcode %i)", rc, err);
			ret = err;
		}
		so_call_sync_finished(n, ei);
		return ret;
	}

	threadinfo_t *threadinfo_p = thread_new();
	if(threadinfo_p == NULL)
		return errno;

	threadinfo_p->try_n       = 0;
	threadinfo_p->callback    = NULL;
	threadinfo_p->argv        = NULL;
	threadinfo_p->ctx_p   = ctx_p;
	threadinfo_p->starttime	  = time(NULL);
	threadinfo_p->fpath2ei_ht = g_hash_table_dup(indexes_p->fpath2ei_ht, g_str_hash, g_str_equal, free, free, (gpointer(*)(gpointer))strdup, eidup);
	threadinfo_p->n           = n;
	threadinfo_p->ei          = ei;

	if(ctx_p->synctimeout)
		threadinfo_p->expiretime = threadinfo_p->starttime + ctx_p->synctimeout;

	if(pthread_create(&threadinfo_p->pthread, NULL, (void *(*)(void *))so_call_sync_thread, threadinfo_p)) {
		error("Cannot pthread_create().");
		return errno;
	}
	debug(3, "thread %p", threadinfo_p->pthread);
	return 0;

}

static inline int so_call_rsync_finished(ctx_t *ctx_p, const char *inclistfile, const char *exclistfile) {
	int ret0, ret1;
	if(inclistfile == NULL) {
		error("inclistfile == NULL.");
		return EINVAL;
	}

	debug(3, "unlink()-ing \"%s\"", inclistfile);
	ret0 = unlink(inclistfile);

	if(ctx_p->flags[RSYNCPREFERINCLUDE])
		return ret0;

	if(exclistfile == NULL) {
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
		if((err=exitcode_process(threadinfo_p->ctx_p, rc))) {
			try_again = ((!ctx_p->retries) || (threadinfo_p->try_n < ctx_p->retries)) && (*state_p != STATE_TERM) && (*state_p != STATE_EXIT);
			error("Warning: so_call_rsync_thread(): Bad exitcode %i (errcode %i). %s.", rc, err, try_again?"Retrying":"Give up");
			if(try_again) {
				debug(2, "Sleeping for %u seconds before the retry.", ctx_p->syncdelay);
				sleep(ctx_p->syncdelay);
			}
		}
	} while(try_again);

	if(err) {
		error("Bad exitcode %i (errcode %i)", rc, err);
		threadinfo_p->errcode = err;
	}

	if((err=so_call_rsync_finished(ctx_p, argv[0], argv[1]))) {
		exitcode = err;	// This's global variable "exitcode"
		pthread_kill(pthread_sighandler, SIGTERM);
	}

	free(argv[0]);
	free(argv[1]);
	free(argv);

	if((err=thread_exit(threadinfo_p, rc))) {
		exitcode = err;	// This's global variable "exitcode"
		pthread_kill(pthread_sighandler, SIGTERM);
	}

	return rc;
}

static inline int so_call_rsync(ctx_t *ctx_p, indexes_t *indexes_p, const char *inclistfile, const char *exclistfile) {
	debug(2, "inclistfile == \"%s\"; exclistfile == \"%s\"", inclistfile, exclistfile);

	if(!ctx_p->flags[PTHREAD]) {
		debug(3, "ctx_p->handler_funct.rsync == %p", ctx_p->handler_funct.rsync);

		int rc=0, err=0;
		int try_n=0, try_again;
		do {
			try_again = 0;
			try_n++;

			alarm(ctx_p->synctimeout);
			rc = ctx_p->handler_funct.rsync(inclistfile, exclistfile);
			alarm(0);

			if((err=exitcode_process(ctx_p, rc))) {
				try_again = ((!ctx_p->retries) || (try_n < ctx_p->retries)) && (*state_p != STATE_TERM) && (*state_p != STATE_EXIT);
				error("Warning: so_call_rsync(): Bad exitcode %i (errcode %i). %s.", rc, err, try_again?"Retrying":"Give up");
				if(try_again) {
					debug(2, "Sleeping for %u seconds before the retry.", ctx_p->syncdelay);
					sleep(ctx_p->syncdelay);
				}
			}
		} while(try_again);
		if(err) {
			error("Bad exitcode %i (errcode %i)", rc, err);
			rc = err;
		}

		int ret_cleanup;
		if((ret_cleanup=so_call_rsync_finished(ctx_p, inclistfile, exclistfile)))
			return rc ? rc : ret_cleanup;
		return rc;
	}

	threadinfo_t *threadinfo_p = thread_new();
	if(threadinfo_p == NULL)
		return errno;

	threadinfo_p->try_n       = 0;
	threadinfo_p->callback    = NULL;
	threadinfo_p->argv        = xmalloc(sizeof(char *) * 3);
	threadinfo_p->ctx_p   = ctx_p;
	threadinfo_p->starttime	  = time(NULL);
	threadinfo_p->fpath2ei_ht = g_hash_table_dup(indexes_p->fpath2ei_ht, g_str_hash, g_str_equal, free, free, (gpointer(*)(gpointer))strdup, eidup);

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

#define SYNC_EXEC(...) (ctx_p->flags[PTHREAD]?sync_exec_thread:sync_exec)(__VA_ARGS__)


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
\
		debug(2, "argv[%i] = %s", i, argv[i]);\
	} while(argv[i++] != NULL);\
	va_end(arglist);\
}

char *sync_path_abs2rel(ctx_t *ctx_p, const char *path_abs, size_t path_abs_len, size_t *path_rel_len_p, char *path_rel_oldptr) {
	if(path_abs == NULL)
		return NULL;

	if(path_abs_len == -1)
		path_abs_len = strlen(path_abs);

	size_t path_rel_len;
	char  *path_rel;
	size_t watchdirlen = (ctx_p->watchdir == ctx_p->watchdirwslash /* if watch-dir == "/" */) 
				? 0 : ctx_p->watchdirlen;

	signed long path_rel_len_signed = path_abs_len - (watchdirlen+1);

	path_rel_len = (path_rel_len_signed > 0) ? path_rel_len_signed : 0;

	if(path_rel_oldptr == NULL) {
		path_rel = xmalloc(path_abs_len+1);
	} else {
		if(path_rel_len > *path_rel_len_p) {
			path_rel = xrealloc(path_rel_oldptr, path_rel_len+1);
		} else {
			path_rel = path_rel_oldptr;
		}
	}

	if(!path_rel_len) {
		path_rel[0] = 0;
		return path_rel;
	}

	memcpy(path_rel, &path_abs[watchdirlen+1], path_rel_len+1);

#ifdef VERYPARANOID
	// Removing "/" on the end
	debug(3, "sync_path_abs2rel(): \"%s\" (len: %i) --%i--> \"%s\" (len: %i) + ", 
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
//	if(ctx_p->flags[PTHREAD])
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

static inline int sync_exec(ctx_t *ctx_p, indexes_t *indexes_p, thread_callbackfunct_t callback, ...) {
	debug(2, "sync_exec()");

	char **argv = (char **)xcalloc(sizeof(char *), MAXARGUMENTS);
	memset(argv, 0, sizeof(char *)*MAXARGUMENTS);

	_sync_exec_getargv(argv, callback, arg);

	int exitcode=0, ret=0, err=0;
	int try_n=0, try_again;
	do {
		try_again = 0;
		try_n++;
		debug(2, "try_n == %u (retries == %u)", try_n, ctx_p->retries);

		alarm(ctx_p->synctimeout);
		ctx_p->children = 1;
		exitcode = exec_argv(argv, ctx_p->child_pid );
		ctx_p->children = 0;
		alarm(0);

		if((err=exitcode_process(ctx_p, exitcode))) {
			try_again = ((!ctx_p->retries) || (try_n < ctx_p->retries)) && (*state_p != STATE_TERM) && (*state_p != STATE_EXIT);
			error("Warning: sync_exec(): Bad exitcode %i (errcode %i). %s.", exitcode, err, try_again?"Retrying":"Give up");
			if(try_again) {
				debug(2, "Sleeping for %u seconds before the retry.", ctx_p->syncdelay);
				sleep(ctx_p->syncdelay);
			}
		}
	} while(try_again);

	if(err) {
		error("Bad exitcode %i (errcode %i)", exitcode, err);
		ret = err;
//		goto l_sync_exec_end;
	}

	if(callback != NULL) {
		int nret = callback(ctx_p, argv);
		if(nret) {
			error("Got error while callback().");
			if(!ret) ret=nret;
//			goto l_sync_exec_end;
		}
	}

//l_sync_exec_end:
	free(argv);
	return ret;
}

int __sync_exec_thread(threadinfo_t *threadinfo_p) {
	char **argv			= threadinfo_p->argv;
	ctx_t *ctx_p		= threadinfo_p->ctx_p;
#ifdef _DEBUG
	int _rand=rand();
#endif

	debug(3, "thread_num == %i; threadinfo_p == %p; i_p->pthread %p; thread %p""", 
			threadinfo_p->thread_num, threadinfo_p, threadinfo_p->pthread, pthread_self() );

	int err=0, exec_exitcode=0, try_again;
	do {
		try_again = 0;
		threadinfo_p->try_n++;

		exec_exitcode = exec_argv(argv, &threadinfo_p->child_pid );

		if((err=exitcode_process(threadinfo_p->ctx_p, exec_exitcode))) {
			try_again = ((!ctx_p->retries) || (threadinfo_p->try_n < ctx_p->retries)) && (*state_p != STATE_TERM) && (*state_p != STATE_EXIT);
			error("Warning: __sync_exec_thread(): Bad exitcode %i (errcode %i). %s.", exec_exitcode, err, try_again?"Retrying":"Give up");
			if(try_again) {
				debug(2, "Sleeping for %u seconds before the retry.", ctx_p->syncdelay);
				sleep(ctx_p->syncdelay);
			}
		}

	} while(try_again);

	if(err) {
		error("Bad exitcode %i (errcode %i)", exec_exitcode, err);
		threadinfo_p->errcode = err;
	}

	g_hash_table_destroy(threadinfo_p->fpath2ei_ht);

	if((err=thread_exit(threadinfo_p, exec_exitcode ))) {
		exitcode = err;	// This's global variable "exitcode"
		pthread_kill(pthread_sighandler, SIGTERM);
	}

	debug(3, "thread_num == %i; threadinfo_p == %p; i_p->pthread %p; thread %p""; errcode %i", 
			threadinfo_p->thread_num, threadinfo_p, threadinfo_p->pthread, pthread_self(),  threadinfo_p->errcode);
	return exec_exitcode;
}

static inline int sync_exec_thread(ctx_t *ctx_p, indexes_t *indexes_p, thread_callbackfunct_t callback, ...) {
	debug(2, "sync_exec_thread()");

	char **argv = (char **)xcalloc(sizeof(char *), MAXARGUMENTS);
	memset(argv, 0, sizeof(char *)*MAXARGUMENTS);

	_sync_exec_getargv(argv, callback, strdup(arg));

	threadinfo_t *threadinfo_p = thread_new();
	if(threadinfo_p == NULL)
		return errno;

	threadinfo_p->try_n       = 0;
	threadinfo_p->callback    = callback;
	threadinfo_p->argv        = argv;
	threadinfo_p->ctx_p   = ctx_p;
	threadinfo_p->starttime	  = time(NULL);
	threadinfo_p->fpath2ei_ht = g_hash_table_dup(indexes_p->fpath2ei_ht, g_str_hash, g_str_equal, free, free, (gpointer(*)(gpointer))strdup, eidup);

	if(ctx_p->synctimeout)
		threadinfo_p->expiretime = threadinfo_p->starttime + ctx_p->synctimeout;

	if(pthread_create(&threadinfo_p->pthread, NULL, (void *(*)(void *))__sync_exec_thread, threadinfo_p)) {
		error("Cannot pthread_create().");
		return errno;
	}
	debug(3, "thread %p", threadinfo_p->pthread);
	return 0;
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
		evinfo_merge(evinfo_q, evinfo);
	}

	return 0;
}

int sync_initialsync_walk(ctx_t *ctx_p, const char *dirpath, indexes_t *indexes_p, queue_id_t queue_id, initsync_t initsync) {
	int ret = 0;
	const char *rootpaths[] = {dirpath, NULL};
	eventinfo_t evinfo;
	FTS *tree;
	rule_t *rules_p = ctx_p->rules;
	debug(2, "sync_initialsync_walk(ctx_p, \"%s\", indexes_p, %i, %i).", dirpath, queue_id, initsync);

	char skip_rules = (initsync==INITSYNC_FULL) && ctx_p->flags[INITFULL];

	char rsync_and_prefer_excludes =
			(
				(ctx_p->flags[MODE]==MODE_RSYNCDIRECT) ||
				(ctx_p->flags[MODE]==MODE_RSYNCSHELL)  ||
				(ctx_p->flags[MODE]==MODE_RSYNCSO)
			) && 
			!ctx_p->flags[RSYNCPREFERINCLUDE];

	if((!ctx_p->flags[RSYNCPREFERINCLUDE]) && skip_rules)
		return 0;

	char fts_no_stat = (initsync==INITSYNC_FULL) && !(ctx_p->flags[EXCLUDEMOUNTPOINTS]);

	int fts_opts =  FTS_NOCHDIR | FTS_PHYSICAL | 
			(fts_no_stat				? FTS_NOSTAT	: 0) | 
			(ctx_p->flags[ONEFILESYSTEM] 	? FTS_XDEV	: 0); 

        debug(3, "sync_initialsync_walk() fts_opts == %p", (void *)(long)fts_opts);

	tree = fts_open((char *const *)&rootpaths, fts_opts, NULL);

	if(tree == NULL) {
		error("Cannot fts_open() on \"%s\".", dirpath);
		return errno;
	}

	memset(&evinfo, 0, sizeof(evinfo));

	FTSENT *node;
	char  *path_rel		= NULL;
	size_t path_rel_len	= 0;

	while((node = fts_read(tree))) {
		switch(node->fts_info) {
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
			case FTS_DNR:
				if(node->fts_errno == ENOENT) {
					debug(1, "Got error while fts_read(): %s (errno: %i; fts_info: %i).", strerror(node->fts_errno), node->fts_errno, node->fts_info);
					continue;
				} else {
					error("Got error while fts_read(): %s (errno: %i; fts_info: %i).", strerror(node->fts_errno), node->fts_errno, node->fts_info);
					ret = node->fts_errno;
					goto l_sync_initialsync_walk_end;
				}
			default:

				error("Got unknown fts_info vlaue while fts_read(): %i.", node->fts_info);
				ret = EINVAL;
				goto l_sync_initialsync_walk_end;
		}
		path_rel = sync_path_abs2rel(ctx_p, node->fts_path, -1, &path_rel_len, path_rel);

		debug(3, "Pointing to \"%s\" (node->fts_info == %i)", path_rel, node->fts_info);

		if(ctx_p->flags[EXCLUDEMOUNTPOINTS] && node->fts_info==FTS_D) {
			if(rsync_and_prefer_excludes) {
				if(node->fts_statp->st_dev != ctx_p->st_dev) {
					if(queue_id == QUEUE_AUTO) {
						int i=0;
						while(i<QUEUE_MAX)
							indexes_addexclude(indexes_p, strdup(path_rel), EVIF_CONTENTRECURSIVELY, i++);
					} else
						indexes_addexclude(indexes_p, strdup(path_rel), EVIF_CONTENTRECURSIVELY, queue_id);
				}
			} else {
				error("Excluding mount points is not implentemted for non \"rsync*\" modes.");
			}
		}

		mode_t st_mode = fts_no_stat ? (node->fts_info==FTS_D ? S_IFDIR : S_IFREG) : node->fts_statp->st_mode;

		if(!skip_rules) {
			ruleaction_t perm = rules_getperm(path_rel, st_mode, rules_p, RA_WALK|RA_MONITOR);

			if(!(perm&RA_WALK)) {
				debug(3, "Rejecting to walk into \"%s\".", path_rel);
				fts_set(tree, node, FTS_SKIP);
			}

			if(!(perm&RA_MONITOR)) {
				debug(3, "Excluding \"%s\".", path_rel);
				if(rsync_and_prefer_excludes) {
					if(queue_id == QUEUE_AUTO) {
						int i=0;
						while(i<QUEUE_MAX)
							indexes_addexclude(indexes_p, strdup(path_rel), EVIF_NONE, i++);
					} else
						indexes_addexclude(indexes_p, strdup(path_rel), EVIF_NONE, queue_id);
				}
				continue;
			}
		}

		evinfo.seqid_min    = sync_seqid();
		evinfo.seqid_max    = evinfo.seqid_min;
		evinfo.objtype_old  = EOT_DOESNTEXIST;
		evinfo.objtype_new  = node->fts_info==FTS_D ? EOT_DIR : EOT_FILE;
		evinfo.fsize        = fts_no_stat ? 0 : node->fts_statp->st_size;
		switch(ctx_p->notifyengine) {
#ifdef FANOTIFY_SUPPORT
			case NE_FANOTIFY:
				break;
#endif
			case NE_INOTIFY:
				evinfo.evmask = IN_CREATE_SELF;
				if(node->fts_info==FTS_D) {
					evinfo.evmask |= IN_ISDIR;
				}
				break;
		}

		if(!rsync_and_prefer_excludes) {
			debug(3, "queueing \"%s\" (depth: %i) with int-flags %p", node->fts_path, node->fts_level, (void *)(unsigned long)evinfo.flags);
			int _ret = sync_queuesync(path_rel, &evinfo, ctx_p, indexes_p, queue_id);

			if(_ret) {
				error("Got error while queueing \"%s\".", node->fts_path);
				ret = errno;
				goto l_sync_initialsync_walk_end;
			}
		}
	}
	if(errno) {
		error("Got error while fts_read() and related routines.");
		ret = errno;
		goto l_sync_initialsync_walk_end;
	}

	if(fts_close(tree)) {
		error("Got error while fts_close().");
		ret = errno;
		goto l_sync_initialsync_walk_end;
	}

l_sync_initialsync_walk_end:
	if(path_rel != NULL)
		free(path_rel);
	return ret;
}

int sync_initialsync(const char *path, ctx_t *ctx_p, indexes_t *indexes_p, initsync_t initsync) {
	debug(3, "sync_initialsync(\"%s\", ctx_p, indexes_p, %i)", path, initsync);

#ifdef CLUSTER_SUPPORT
	if(initsync == INITSYNC_FULL) {
		if(ctx_p->cluster_iface)
			return cluster_initialsync();
	}
#endif

	queue_id_t queue_id = (initsync==INITSYNC_FULL) ? QUEUE_INSTANT : QUEUE_NORMAL;

	// non-RSYNC case:
	if(
		!(
			(ctx_p->flags[MODE]==MODE_RSYNCDIRECT)	||
			(ctx_p->flags[MODE]==MODE_RSYNCSHELL)	||
			(ctx_p->flags[MODE]==MODE_RSYNCSO)
		)
	) {
		debug(3, "syncing \"%s\"", path);
/*
		if(ctx_p->flags[PTHREAD])
			return sync_exec_thread(ctx_p, NULL, ctx_p->handlerfpath, "initialsync", ctx_p->label, path, NULL);
		else
			return sync_exec       (ctx_p, NULL, ctx_p->handlerfpath, "initialsync", ctx_p->label, path, NULL);*/

		if(ctx_p->flags[HAVERECURSIVESYNC]) {
			if(ctx_p->flags[MODE] == MODE_SO) {
				api_eventinfo_t *ei = (api_eventinfo_t *)xmalloc(sizeof(*ei));
#ifdef PARANIOD
				memset(ei, 0, sizeof(*ei));
#endif

				ei->evmask      = IN_CREATE|IN_ISDIR;
				ei->flags       = EVIF_RECURSIVELY;
				ei->path_len    = strlen(path);
				ei->path        = strdup(path);
				ei->objtype_old = EOT_DOESNTEXIST;
				ei->objtype_new = EOT_DIR;

				return so_call_sync(ctx_p, indexes_p, 1, ei);
			} else {
				return SYNC_EXEC(
						ctx_p,
						indexes_p,
						NULL,
						ctx_p->handlerfpath, 
						"initialsync",
						ctx_p->label,
						path,
						NULL
					);
			}
		}
#ifdef DOXYGEN
		sync_exec(NULL, NULL); sync_exec_thread(NULL, NULL);
#endif

		int ret = sync_initialsync_walk(ctx_p, path, indexes_p, queue_id, initsync);
		if(ret)
			error("Cannot get synclist");

		return ret;
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
		int ret = sync_initialsync_walk(ctx_p, path, indexes_p, queue_id, initsync);
		if(ret) {
			error("Cannot get exclude what to exclude");
			return ret;
		}

		debug(3, "queueing \"%s\" with int-flags %p", path, (void *)(unsigned long)evinfo->flags);

		char *path_rel = sync_path_abs2rel(ctx_p, path, -1, NULL, NULL);

		return indexes_queueevent(indexes_p, path_rel, evinfo, queue_id);
	}

	// Searching for includes
	return sync_initialsync_walk(ctx_p, path, indexes_p, queue_id, initsync);
}

int sync_notify_mark(int notify_d, ctx_t *ctx_p, const char *accpath, const char *path, size_t pathlen, indexes_t *indexes_p) {
	debug(3, "sync_notify_mark(..., \"%s\", %i,...)", path, pathlen);
	int wd = indexes_fpath2wd(indexes_p, path);
	if(wd != -1) {
		debug(1, "\"%s\" is already marked (wd: %i). Skipping.", path, wd);
		return wd;
	}

	switch(ctx_p->notifyengine) {
#ifdef FANOTIFY_SUPPORT
		case NE_FANOTIFY: {
			int fanotify_d = notify_d;

			if((wd = fanotify_mark(fanotify_d, FAN_MARK_ADD | FAN_MARK_DONT_FOLLOW,
				FANOTIFY_MARKMASK, AT_FDCWD, accpath)) == -1)
			{
				if(errno == ENOENT)
					return -2;

				error("Cannot fanotify_mark() on \"%s\".", 
					path);
				return -1;
			}
			break;
		}
#endif
		case NE_INOTIFY: {
			int inotify_d = notify_d;

			if((wd = inotify_add_watch(inotify_d, accpath, INOTIFY_MARKMASK)) == -1) {
				if(errno == ENOENT)
					return -2;

				error("Cannot inotify_add_watch() on \"%s\".", 
					path);
				return -1;
			}
			break;
		}
		default: {
			error("unknown notify-engine: %i", ctx_p->notifyengine);
			errno = EINVAL;
			return -1;
		}
	}
	indexes_add_wd(indexes_p, wd, path, pathlen);

	return wd;
}

#ifdef CLUSTER_SUPPORT
static inline int sync_mark_walk_cluster_modtime_update(ctx_t *ctx_p, const char *path, short int dirlevel, mode_t st_mode) {
	if(ctx_p->cluster_iface) {
		int ret=cluster_modtime_update(path, dirlevel, st_mode);
		if(ret) error("sync_mark_walk() cannot cluster_modtime_update()");
		return ret;
	}
	return 0;
}
#endif

int sync_mark_walk(int notify_d, ctx_t *ctx_p, const char *dirpath, indexes_t *indexes_p) {
	int ret = 0;
	const char *rootpaths[] = {dirpath, NULL};
	FTS *tree;
	rule_t *rules_p = ctx_p->rules;
	debug(2, "sync_mark_walk(%i, ctx_p, \"%s\", indexes_p).", notify_d, dirpath);

	int fts_opts = FTS_NOCHDIR|FTS_PHYSICAL|FTS_NOSTAT|(ctx_p->flags[ONEFILESYSTEM]?FTS_XDEV:0);

        debug(3, "fts_opts == %p", (void *)(long)fts_opts);
	tree = fts_open((char *const *)&rootpaths, fts_opts, NULL);

	if(tree == NULL) {
		error_or_debug(STATE_STARTING(state_p)?-1:2, "Cannot fts_open() on \"%s\".", dirpath);
		return errno;
	}

	FTSENT *node;
	char  *path_rel		= NULL;
	size_t path_rel_len	= 0;

	while((node = fts_read(tree))) {
#ifdef CLUSTER_SUPPORT
		int ret;
#endif
		debug(2, "walking: \"%s\" (depth %u): fts_info == %i", node->fts_path, node->fts_level, node->fts_info);

		switch(node->fts_info) {
			// Duplicates:
			case FTS_DP:
				continue;
			case FTS_DEFAULT:
			case FTS_SL:
			case FTS_SLNONE:
			case FTS_F:
			case FTS_NSOK:
#ifdef CLUSTER_SUPPORT
				if((ret=sync_mark_walk_cluster_modtime_update(ctx_p, node->fts_path, node->fts_level, S_IFREG)))
					goto l_sync_mark_walk_end;
#endif
				continue;
			// To mark:
			case FTS_D:
			case FTS_DC:    // TODO: think about case of FTS_DC
			case FTS_DOT:
#ifdef CLUSTER_SUPPORT
				if((ret=sync_mark_walk_cluster_modtime_update(ctx_p, node->fts_path, node->fts_level, S_IFDIR)))
					goto l_sync_mark_walk_end;
#endif
				break;
			// Error cases:
			case FTS_ERR:
			case FTS_NS:
			case FTS_DNR:
				if(errno == ENOENT) {
					debug(1, "Got error while fts_read(): %s (errno: %i; fts_info: %i).", node->fts_info);
					continue;
				} else {
					error_or_debug(STATE_STARTING(state_p)?-1:2, "Got error while fts_read(): %s (errno: %i; fts_info: %i).", node->fts_info);
					ret = errno;
					goto l_sync_mark_walk_end;
				}
			default:
				error_or_debug(STATE_STARTING(state_p)?-1:2, "Got unknown fts_info vlaue while fts_read(): %i.", node->fts_info);
				ret = EINVAL;
				goto l_sync_mark_walk_end;
		}

		path_rel = sync_path_abs2rel(ctx_p, node->fts_path, -1, &path_rel_len, path_rel);
		ruleaction_t perm = rules_search_getperm(path_rel, S_IFDIR, rules_p, RA_WALK, NULL);

		if(!(perm&RA_WALK)) {
			fts_set(tree, node, FTS_SKIP);
			continue;
		}

		debug(2, "marking \"%s\" (depth %u)", node->fts_path, node->fts_level);
		int wd = sync_notify_mark(notify_d, ctx_p, node->fts_accpath, node->fts_path, node->fts_pathlen, indexes_p);
		if(wd == -1) {
			error_or_debug(STATE_STARTING(state_p)?-1:2, "Got error while notify-marking \"%s\".", node->fts_path);
			ret = errno;
			goto l_sync_mark_walk_end;
		}
		debug(2, "watching descriptor is %i.", wd);
	}
	if(errno) {
		error_or_debug(STATE_STARTING(state_p)?-1:2, "Got error while fts_read() and related routines.");
		ret = errno;
		goto l_sync_mark_walk_end;
	}

	if(fts_close(tree)) {
		error_or_debug(STATE_STARTING(state_p)?-1:2, "Got error while fts_close().");
		ret = errno;
		goto l_sync_mark_walk_end;
	}

l_sync_mark_walk_end:
	if(path_rel != NULL)
		free(path_rel);
	return ret;
}

int sync_notify_init(ctx_t *ctx_p) {
	switch(ctx_p->notifyengine) {
#ifdef FANOTIFY_SUPPORT
		case NE_FANOTIFY: {
			int fanotify_d = fanotify_init(FANOTIFY_FLAGS, FANOTIFY_EVFLAGS);
			if(fanotify_d == -1) {
				error("cannot fanotify_init(%i, %i).", FANOTIFY_FLAGS, FANOTIFY_EVFLAGS);
				return -1;
			}

			return fanotify_d;
		}
#endif
		case NE_INOTIFY: {
#ifdef OLDSYSTEM
			int inotify_d = inotify_init();
#else
			int inotify_d = inotify_init1(INOTIFY_FLAGS);
#endif
			if(inotify_d == -1) {
				error("cannot inotify_init(%i).", INOTIFY_FLAGS);
				return -1;
			}

			return inotify_d;
		}
	}
	error("unknown notify-engine: %i", ctx_p->notifyengine);
	errno = EINVAL;
	return -1;
}

static inline int sync_dosync_exec(ctx_t *ctx_p, indexes_t *indexes_p, const char *evmask_str, const char *fpath) {
/*
	if(ctx_p->flags[PTHREAD])
		return sync_exec_thread(ctx_p, NULL, ctx_p->handlerfpath, "sync", ctx_p->label, evmask_str, fpath, NULL);
	else
		return sync_exec       (ctx_p, NULL, ctx_p->handlerfpath, "sync", ctx_p->label, evmask_str, fpath, NULL);*/
	return SYNC_EXEC(ctx_p, indexes_p, NULL, ctx_p->handlerfpath, "sync", ctx_p->label, evmask_str, fpath, NULL);

#ifdef DOXYGEN
	sync_exec(NULL, NULL); sync_exec_thread(NULL, NULL);
#endif

}

static int sync_dosync(const char *fpath, uint32_t evmask, ctx_t *ctx_p, indexes_t *indexes_p) {
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

void _sync_idle_dosync_collectedexcludes(gpointer fpath_gp, gpointer flags_gp, gpointer arg_gp) {
	char *fpath		  = (char *)fpath_gp;
	indexes_t *indexes_p 	  = ((struct dosync_arg *)arg_gp)->indexes_p;

	debug(3, "\"%s\", %u (%p).", fpath, GPOINTER_TO_INT(flags_gp), flags_gp);

	indexes_addexclude_aggr(indexes_p, strdup(fpath), (eventinfo_flags_t)GPOINTER_TO_INT(flags_gp));

	return;
}

void _sync_idle_dosync_collectedevents(gpointer fpath_gp, gpointer evinfo_gp, gpointer arg_gp) {
	char *fpath		  = (char *)fpath_gp;
	eventinfo_t *evinfo	  = (eventinfo_t *)evinfo_gp;
	int *evcount_p		  =&((struct dosync_arg *)arg_gp)->evcount;
//	FILE *outf		  = ((struct dosync_arg *)arg_gp)->outf;
	ctx_t *ctx_p 	  = ((struct dosync_arg *)arg_gp)->ctx_p;
	indexes_t *indexes_p 	  = ((struct dosync_arg *)arg_gp)->indexes_p;
	queue_id_t queue_id	  = (queue_id_t)((struct dosync_arg *)arg_gp)->data;

	debug(3, "queue_id == %i.", queue_id);

	if((ctx_p->listoutdir == NULL) && (!(ctx_p->flags[MODE]==MODE_SO))) {
		debug(3, "calling sync_dosync()");
		int ret;
		if((ret=sync_dosync(fpath, evinfo->evmask, ctx_p, indexes_p))) {
			error("unable to sync \"%s\" (evmask %i).", fpath, evinfo->evmask);
			exit(ret);	// TODO: remove this from here
		}
	}

	int isnew = 0;
	eventinfo_t *evinfo_idx = indexes_fpath2ei(indexes_p, fpath);

	if(evinfo_idx == NULL) {
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
		evinfo_merge(evinfo_idx, evinfo);


	int _queue_id = 0;
	while(_queue_id < QUEUE_MAX) {
		if(_queue_id == queue_id) {
			_queue_id++;
			continue;
		}

		eventinfo_t *evinfo_q = indexes_lookupinqueue(indexes_p, fpath, _queue_id);
		if(evinfo_q != NULL) {
			evinfo_merge(evinfo_idx, evinfo_q);

			indexes_removefromqueue(indexes_p, fpath, _queue_id);
			if(!indexes_queuelen(indexes_p, _queue_id))
				ctx_p->_queues[_queue_id].stime = 0;
		}
		_queue_id++;
	}

	if(isnew)
		indexes_fpath2ei_add(indexes_p, strdup(fpath), evinfo_idx);
	else
		free(fpath);

	return;
}

int sync_idle_dosync_collectedevents_cleanup(ctx_t *ctx_p, char **argv) {
	if(ctx_p->flags[DONTUNLINK]) 
		return 0;

	debug(3, "thread %p", pthread_self());

	if(ctx_p->flags[MODE] == MODE_RSYNCDIRECT) {
		int ret0, ret1;
		if(argv[5] == NULL) {
			error("Unexpected *argv[] end.");
			return EINVAL;
		}

		debug(3, "unlink()-ing \"%s\"", argv[5]);
		ret0 = unlink(argv[5]);

		if(ctx_p->flags[RSYNCPREFERINCLUDE])
			return ret0;

		if(argv[7] == NULL) {
			error("Unexpected *argv[] end.");
			return EINVAL;
		}

		debug(3, "unlink()-ing \"%s\"", argv[7]);
		ret1 = unlink(argv[7]);

		return ret0 == 0 ? ret1 : ret0;
	}

	if(argv[3] == NULL) {
		error("Unexpected *argv[] end.");
		return EINVAL;
	}

	int ret0;
	debug(3, "unlink()-ing \"%s\"", argv[3]);
	ret0 = unlink(argv[3]);

	if(ctx_p->flags[MODE] == MODE_RSYNCSHELL) {
		int ret1;

		// There's no exclude file-list if "--rsyncpreferinclude" is enabled, so return
		if(ctx_p->flags[RSYNCPREFERINCLUDE])
			return ret0;

		if(argv[4] == NULL) 
			return ret0;

		if(*argv[4] == 0x00)
			return ret0;

		debug(3, "unlink()-ing \"%s\"", argv[4]);
		ret1 = unlink(argv[4]);	// remove exclude list, too

		return ret0 == 0 ? ret1 : ret0;
	}

	return ret0;
}

int sync_idle_dosync_collectedevents_aggrqueue(queue_id_t queue_id, ctx_t *ctx_p, indexes_t *indexes_p, struct dosync_arg *dosync_arg) {
//	char *buf, *fpath;
	time_t tm = time(NULL);

	queueinfo_t *queueinfo = &ctx_p->_queues[queue_id];

	if((queueinfo->stime + queueinfo->collectdelay > tm) && (queueinfo->collectdelay != COLLECTDELAY_INSTANT) && (!ctx_p->flags[EXITONNOEVENTS])) {
		debug(3, "sync_idle_dosync_collectedevents_procqueue(%i, ...): too early (%i + %i > %i).", queue_id, queueinfo->stime, queueinfo->collectdelay, tm);
		return 0;
	}
	queueinfo->stime = 0;

	int evcount_real = g_hash_table_size(indexes_p->fpath2ei_coll_ht[queue_id]);

	debug(3, "sync_idle_dosync_collectedevents_procqueue(%i, ...): evcount_real == %i", queue_id, evcount_real);

	if(evcount_real<=0) {
		debug(3, "sync_idle_dosync_collectedevents_procqueue(%i, ...): no events, return 0.", queue_id);
		return 0;
	}

	g_hash_table_foreach(indexes_p->fpath2ei_coll_ht[queue_id], _sync_idle_dosync_collectedevents, dosync_arg);
	g_hash_table_remove_all(indexes_p->fpath2ei_coll_ht[queue_id]);

	if(!ctx_p->flags[RSYNCPREFERINCLUDE]) {
		g_hash_table_foreach(indexes_p->exc_fpath_coll_ht[queue_id], _sync_idle_dosync_collectedexcludes, dosync_arg);
		g_hash_table_remove_all(indexes_p->exc_fpath_coll_ht[queue_id]);
	}

	return 0;
}

int sync_idle_dosync_collectedevents_uniqfname(ctx_t *ctx_p, char *fpath, char *name) {
	pid_t pid = getpid();
	time_t tm = time(NULL);
	struct stat64 stat64;

	int counter = 0;
	do {
		snprintf(fpath, PATH_MAX, "%s/.clsync-%s.%u.%lu.%lu.%u", ctx_p->listoutdir, name, pid, (long)pthread_self(), (unsigned long)tm, rand());	// To be unique
		lstat64(fpath, &stat64);
		if(counter++ > COUNTER_LIMIT) {
			error("Cannot file unused filename for list-file. The last try was \"%s\".", fpath);
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
	if((ret=sync_idle_dosync_collectedevents_uniqfname(ctx_p, fpath, name))) {
		error("sync_idle_dosync_collectedevents_listcreate: Cannot get unique file name.");
		return ret;
	}

	dosync_arg_p->outf = fopen(fpath, "w");

	if(dosync_arg_p->outf == NULL) {
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
//	size_t sc_coords_size = ALLOC_PORTION;
//	size_t *sc_coords     = malloc(sizeof(*sc_coords) * sc_coords_size);
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
/*
				if(sc_count >= sc_coords_size-1) {
					sc_coords_size += ALLOC_PORTION;
					sc_coords       = realloc(sc_coords, sizeof(*sc_coords) * sc_coords_size);
				}
				sc_coords[sc_count++] = i;
*/
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
		rsync_escape_result	 = realloc(rsync_escape_result, rsync_escape_result_size);
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
//					if(!sc_count)
//						goto l_rsync_escape_loop1_end;
				break;
		}
	} 

/*		size_t end = i+sc_count;

	char *from, *to;

	sc_coords[sc_count] = end;

	while(sc_count) {
		char *from, *to;
		sc_count--;

		to   = &path[sc_coords[sc_count]+sc_count];
		from = &path[sc_coords[sc_count]+1];

		memmove(to, from, sc_coords[sc_count+1]-sc_coords[sc_count]-1);
	}
*/
//l_rsync_escape_loop1_end:

	return rsync_escape_result;
}

static inline int rsync_outline(FILE *outf, char *outline, eventinfo_flags_t flags) {
	if(flags & EVIF_RECURSIVELY) {
		debug(3, "Recursively \"%s\": Writing to rsynclist: \"%s/***\".", outline, outline);
		fprintf(outf, "%s/***", outline);
	} else
	if(flags & EVIF_CONTENTRECURSIVELY) {
		debug(3, "Content-recursively \"%s\": Writing to rsynclist: \"%s/**\".", outline, outline);
		fprintf(outf, "%s/**", outline);
	} else {
		debug(3, "Non-recursively \"%s\": Writing to rsynclist: \"%s\".", outline, outline);
		fprintf(outf, "%s", outline);
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

	if(
		(ctx_p->flags[MODE] == MODE_RSYNCDIRECT)	|| 
		(ctx_p->flags[MODE] == MODE_RSYNCSHELL)	||
		(ctx_p->flags[MODE] == MODE_RSYNCSO)
	)
		g_hash_table_foreach_remove(indexes_p->out_lines_aggr_ht, rsync_aggrout, dosync_arg_p);

	if(ctx_p->flags[MODE] != MODE_SO) {
		fclose(dosync_arg_p->outf);
		dosync_arg_p->outf = NULL;
	}

	if(dosync_arg_p->evcount > 0) {
/*
		if(ctx_p->flags[PTHREAD])
			return sync_exec_thread(ctx_p,
						sync_idle_dosync_collectedevents_cleanup,
						ctx_p->handlerfpath,
						ctx_p->flags[RSYNC]?"rsynclist":"synclist",
						ctx_p->label,
						dosync_arg_p->outf_path,
						*(dosync_arg_p->outf_path)?dosync_arg_p->outf_path:NULL,
						NULL);
		else
			return sync_exec       (ctx_p,
						sync_idle_dosync_collectedevents_cleanup,
						ctx_p->handlerfpath,
						ctx_p->flags[RSYNC]?"rsynclist":"synclist", 
						ctx_p->label,
						dosync_arg_p->outf_path,
						*(dosync_arg_p->outf_path)?dosync_arg_p->outf_path:NULL,
						NULL);*/
		debug(3, "%s [%s] (%p) -> %s [%s]", ctx_p->watchdir, ctx_p->watchdirwslash, ctx_p->watchdirwslash, 
								ctx_p->destdir?ctx_p->destdir:"", ctx_p->destdirwslash?ctx_p->destdirwslash:"");

		if(ctx_p->flags[MODE] == MODE_SO) {
			api_eventinfo_t *ei = dosync_arg_p->api_ei;
			return so_call_sync(ctx_p, indexes_p, dosync_arg_p->evcount, ei);
		}

		if(ctx_p->flags[MODE] == MODE_RSYNCSO) 
			return so_call_rsync(
				ctx_p, 
				indexes_p, 
				dosync_arg_p->outf_path, 
				*(dosync_arg_p->excf_path) ? dosync_arg_p->excf_path : NULL);

		if(ctx_p->flags[MODE] == MODE_RSYNCDIRECT)
			return SYNC_EXEC(ctx_p, indexes_p,
				sync_idle_dosync_collectedevents_cleanup,
				ctx_p->handlerfpath,
				"--inplace",
				"-aH", 
				"--delete-before",
				*(dosync_arg_p->excf_path) ? "--exclude-from"		: "--include-from",
				*(dosync_arg_p->excf_path) ? dosync_arg_p->excf_path	: dosync_arg_p->outf_path,
				*(dosync_arg_p->excf_path) ? "--include-from"		: "--exclude=*",
				*(dosync_arg_p->excf_path) ? dosync_arg_p->outf_path	: ctx_p->watchdirwslash,
				*(dosync_arg_p->excf_path) ? "--exclude=*"		: ctx_p->destdirwslash,
				*(dosync_arg_p->excf_path) ? ctx_p->watchdirwslash	: NULL,
				*(dosync_arg_p->excf_path) ? ctx_p->destdirwslash	: NULL,
				NULL);

		return SYNC_EXEC(ctx_p, indexes_p,
			sync_idle_dosync_collectedevents_cleanup,
			ctx_p->handlerfpath,
			ctx_p->flags[MODE]==MODE_RSYNCSHELL?"rsynclist":"synclist", 
			ctx_p->label,
			dosync_arg_p->outf_path,
			*(dosync_arg_p->excf_path)?dosync_arg_p->excf_path:NULL,
			NULL);
	}

	return 0;

#ifdef DOXYGEN
	sync_exec(NULL, NULL); sync_exec_thread(NULL, NULL);
#endif
}

void sync_idle_dosync_collectedevents_listpush(gpointer fpath_gp, gpointer evinfo_gp, gpointer arg_gp) {
	struct dosync_arg *dosync_arg_p = (struct dosync_arg *)arg_gp;
	char *fpath		   =  (char *)fpath_gp;
	eventinfo_t *evinfo	   =  (eventinfo_t *)evinfo_gp;
	//int *evcount_p		  =&dosync_arg_p->evcount;
	FILE *outf		   =  dosync_arg_p->outf;
	ctx_t *ctx_p 	   =  dosync_arg_p->ctx_p;
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
	if(ctx_p->flags[MODE] == MODE_SO) {
		api_eventinfo_t *ei = &(*api_ei_p)[(*api_ei_count_p)++];
		ei->evmask      = evinfo->evmask;
		ei->flags       = evinfo->flags;
		ei->objtype_old = evinfo->objtype_old;
		ei->objtype_new = evinfo->objtype_new;
		ei->path_len    = strlen(fpath);
		ei->path        = strdup(fpath);
		return;
	}

	if(!(
		(ctx_p->flags[MODE] == MODE_RSYNCSHELL)	|| 
		(ctx_p->flags[MODE] == MODE_RSYNCDIRECT)	||
		(ctx_p->flags[MODE] == MODE_RSYNCSO)
	)) {
		// non-RSYNC case
		if(ctx_p->flags[SYNCLISTSIMPLIFY])
			fprintf(outf, "%s", fpath);
		else 
			fprintf(outf, "sync %s %i %s", ctx_p->label, evinfo->evmask, fpath);
		return;
	}

	// RSYNC case
	if(ctx_p->rsyncinclimit && (*linescount_p >= ctx_p->rsyncinclimit)) {
		int ret;

		// TODO: optimize this out {
		char newexc_path[PATH_MAX+1];
		if((ret=sync_idle_dosync_collectedevents_uniqfname(ctx_p, newexc_path, "exclist"))) {
			error("Cannot get unique file name.");
			exit(ret);
		}
		if((ret=fileutils_copy(dosync_arg_p->excf_path, newexc_path))) {
			error("Cannot copy file \"%s\" to \"%s\".", dosync_arg_p->excf_path, newexc_path);
			exit(ret);
		}
		// }
		// That's required to copy excludes' list file for every rsync execution.
		// The problem appears do to unlink()-ing the excludes' list file on callback function 
		// "sync_idle_dosync_collectedevents_cleanup()" of every execution.

		if((ret=sync_idle_dosync_collectedevents_commitpart(dosync_arg_p))) {
			error("Cannot commit list-file \"%s\"", dosync_arg_p->outf_path);
			exit(ret);	// TODO: replace with kill(0, ...);
		}

		strcpy(dosync_arg_p->excf_path, newexc_path);		// TODO: optimize this out

		if((ret=sync_idle_dosync_collectedevents_listcreate(dosync_arg_p, "list"))) {
			error("Cannot create new list-file");
			exit(ret);	// TODO: replace with kill(0, ...);
		}
		outf = dosync_arg_p->outf;
	}

	int ret;
	if((ret=rsync_listpush(indexes_p, fpath, strlen(fpath), evinfo->flags, linescount_p))) {
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
	debug(3, "sync_idle_dosync_collectedevents()");
	struct dosync_arg dosync_arg = {0};

	dosync_arg.ctx_p 	= ctx_p;
	dosync_arg.indexes_p	= indexes_p;

	char isrsyncpreferexclude = 
		(
			(ctx_p->flags[MODE] == MODE_RSYNCDIRECT)	||
			(ctx_p->flags[MODE] == MODE_RSYNCSHELL)	||
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
	while(queue_id < QUEUE_MAX) {
		int ret;
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

	if(!dosync_arg.evcount) {
		debug(3, "Summary events' count is zero. Return 0.");
		return 0;
	}

	if(ctx_p->flags[MODE] == MODE_SO) {
		//dosync_arg.evcount = g_hash_table_size(indexes_p->fpath2ei_ht);
		debug(3, "There's %i events. Processing.", dosync_arg.evcount);
		dosync_arg.api_ei = (api_eventinfo_t *)xmalloc(dosync_arg.evcount * sizeof(*dosync_arg.api_ei));
	}

	if((ctx_p->listoutdir != NULL) || (ctx_p->flags[MODE] == MODE_SO)) {
		int ret;

		if(!(ctx_p->flags[MODE]==MODE_SO)) {
			*(dosync_arg.excf_path) = 0x00;
			if(isrsyncpreferexclude) {
				if((ret=sync_idle_dosync_collectedevents_listcreate(&dosync_arg, "exclist"))) {
					error("Cannot create list-file");
					return ret;
				}

#ifdef PARANOID
				g_hash_table_remove_all(indexes_p->out_lines_aggr_ht);
#endif
				g_hash_table_foreach_remove(indexes_p->exc_fpath_ht, sync_idle_dosync_collectedevents_rsync_exclistpush, &dosync_arg);
				g_hash_table_foreach_remove(indexes_p->out_lines_aggr_ht, rsync_aggrout, &dosync_arg);
				fclose(dosync_arg.outf);
				strcpy(dosync_arg.excf_path, dosync_arg.outf_path);	// TODO: remove this strcpy()
			}

			if((ret=sync_idle_dosync_collectedevents_listcreate(&dosync_arg, "list"))) {
				error("Cannot create list-file");
				return ret;
			}
		}

#ifdef PARANOID
		g_hash_table_remove_all(indexes_p->out_lines_aggr_ht);
#endif

		g_hash_table_foreach(indexes_p->fpath2ei_ht, sync_idle_dosync_collectedevents_listpush, &dosync_arg);

		if((ret=sync_idle_dosync_collectedevents_commitpart(&dosync_arg))) {
			error("Cannot submit to sync the list \"%s\"", dosync_arg.outf_path);
			// TODO: free dosync_arg.api_ei on case of error
			g_hash_table_remove_all(indexes_p->fpath2ei_ht);
			return ret;
		}

		g_hash_table_remove_all(indexes_p->fpath2ei_ht);
	}

	if(!ctx_p->flags[PTHREAD]) {
		if(ctx_p->iteration_num < ~0) // ~0 is the max value for unsigned variables
			ctx_p->iteration_num++;
		setenv_iteration(ctx_p->iteration_num); 

		debug(3, "next iteration: %u/%u", 
			ctx_p->iteration_num, ctx_p->flags[MAXITERATIONS]);
	}

	return 0;
}

int apievinfo2rsynclist(indexes_t *indexes_p, FILE *listfile, int n, api_eventinfo_t *apievinfo) {
	int i;

	if(listfile == NULL) {
		error("apievinfo2rsynclist(): listfile == NULL.");
		return EINVAL;
	}

	i=0;
	while(i<n) {
		rsync_listpush(indexes_p, apievinfo[i].path, apievinfo[i].path_len, apievinfo[i].flags, NULL);
		i++;
	}

	struct dosync_arg dosync_arg = {0};
	dosync_arg.outf = listfile;
	g_hash_table_foreach_remove(indexes_p->out_lines_aggr_ht, rsync_aggrout, &dosync_arg);

	return 0;
}

int sync_idle(int notify_d, ctx_t *ctx_p, indexes_t *indexes_p) {

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

#ifdef FANOTIFY_SUPPORT
int sync_fanotify_loop(int fanotify_d, ctx_t *ctx_p, indexes_t *indexes_p) {
	struct fanotify_event_metadata buf[BUFSIZ/sizeof(struct fanotify_event_metadata) + 1];
	int state = STATE_RUNNING;
	state_p = &state;

	while(state != STATE_EXIT) {
		struct fanotify_event_metadata *metadata;
		size_t len = read(fanotify_d, (void *)buf, sizeof(buf)-sizeof(*buf));
		metadata=buf;
		if(len == -1) {
			error("cannot read(%i, &metadata, sizeof(metadata)).", fanotify_d);
			return errno;
		}
		while(FAN_EVENT_OK(metadata, len)) {
			debug(2, "metadata->pid: %i; metadata->fd: %i", metadata->pid, metadata->fd);
			if (metadata->fd != FAN_NOFD) {
				if (metadata->fd >= 0) {
					char *fpath = fd2fpath_malloc(metadata->fd);
					sync_queuesync(fpath_rel, 0, ctx_p, indexes_p, QUEUE_AUTO);
					debug(2, "Event %i on \"%s\".", metadata->mask, fpath);
					free(fpath);
				}
			}
			close(metadata->fd);
			metadata = FAN_EVENT_NEXT(metadata, len);
		}
		int ret;
		if((ret=sync_idle(fanotify_d, ctx_p, indexes_p))) {
			error("got error while sync_idle().");
			return ret;
		}
	}
	return 0;
}
#endif

int sync_inotify_wait(int inotify_d, ctx_t *ctx_p, indexes_t *indexes_p) {
	static struct timeval tv;
	time_t tm = time(NULL);
	long delay = ((unsigned long)~0 >> 1);

	threadsinfo_t *threadsinfo_p = thread_getinfo();

	pthread_cond_broadcast(&threadsinfo_p->cond[PTHREAD_MUTEX_STATE]);
	pthread_mutex_unlock(&threadsinfo_p->mutex[PTHREAD_MUTEX_STATE]);

	debug(3, "sync_inotify_wait()");

	fd_set rfds;
	FD_ZERO(&rfds);
	FD_SET(inotify_d, &rfds);

	long queue_id = 0;
	while(queue_id < QUEUE_MAX) {
		queueinfo_t *queueinfo = &ctx_p->_queues[queue_id++];

		if(!queueinfo->stime)
			continue;

		if(queueinfo->collectdelay == COLLECTDELAY_INSTANT) {
			debug(3, "There're events in instant queue (#%i), don't waiting.", queue_id-1);
			return 0;
		}

		int qdelay = queueinfo->stime + queueinfo->collectdelay - tm;
		debug(3, "queue #%i: %i %i %i -> %i", queue_id-1, queueinfo->stime, queueinfo->collectdelay, tm, qdelay);
		if(qdelay < -(long)ctx_p->syncdelay)
			qdelay = -(long)ctx_p->syncdelay;

		delay = MIN(delay, qdelay);
	}

	long synctime_delay = ((long)ctx_p->synctime) - ((long)tm);
	synctime_delay = synctime_delay > 0 ? synctime_delay : 0;

	debug(3, "delay = MAX(%li, %li)", delay, synctime_delay);
	delay = MAX(delay, synctime_delay);
	delay = delay > 0 ? delay : 0;

	if(ctx_p->flags[PTHREAD]) {
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

	if((!delay) || (*state_p != STATE_RUNNING))
		return 0;

	if(ctx_p->flags[EXITONNOEVENTS]) { // zero delay if "--exit-on-no-events" is set
		tv.tv_sec  = 0;
		tv.tv_usec = 0;
	} else {
		debug(3, "sleeping for %li second(s).", SLEEP_SECONDS);
		sleep(SLEEP_SECONDS);
		delay = ((long)delay)>SLEEP_SECONDS ? delay-SLEEP_SECONDS : 0;

		tv.tv_sec  = delay;
		tv.tv_usec = 0;
	}

	pthread_mutex_lock(&threadsinfo_p->mutex[PTHREAD_MUTEX_STATE]);

	if(*state_p != STATE_RUNNING)
		return 0;

	debug(3, "select with timeout %li secs.", tv.tv_sec);
	int ret = select(inotify_d+1, &rfds, NULL, NULL, &tv);

	if((ret == -1) && (errno == EINTR)) {
		errno = 0;
		ret   = 0;
	}

	if((ctx_p->flags[EXITONNOEVENTS]) && (ret == 0)) // if not events and "--exit-on-no-events" is set
		*state_p = STATE_EXIT;

	return ret;
}

void sync_inotify_handle_dosync(gpointer fpath_gp, gpointer evinfo_gp, gpointer arg_gp) {
	char *fpath_rel		  = (char *)fpath_gp;
	eventinfo_t *evinfo	  = (eventinfo_t *)evinfo_gp;
	ctx_t *ctx_p 	  = ((struct dosync_arg *)arg_gp)->ctx_p;
	indexes_t *indexes_p 	  = ((struct dosync_arg *)arg_gp)->indexes_p;

	sync_queuesync(fpath_rel, evinfo, ctx_p, indexes_p, QUEUE_AUTO);

	return;
}

#define SYNC_INOTIFY_HANDLE_CONTINUE {\
	ptr += sizeof(struct inotify_event) + event->len;\
	count++;\
	continue;\
}

int sync_inotify_handle(int inotify_d, ctx_t *ctx_p, indexes_t *indexes_p) {
	static struct timeval tv={0};

	int count = 0;

	fd_set rfds;
	FD_ZERO(&rfds);
	FD_SET(inotify_d, &rfds);

	char   *path_rel	= NULL;
	size_t  path_rel_len	= 0;
	char   *path_full	= 0;
	size_t  path_full_size	= 0;
	while(select(FD_SETSIZE, &rfds, NULL, NULL, &tv)) {

		char buf[BUFSIZ + 1];
		size_t r = read(inotify_d, buf, BUFSIZ);
		if(r <= 0) {
			error("Got error while reading events from inotify with read().");
			count = -1;
			goto l_sync_inotify_handle_end;
		}

#ifdef PARANOID
		g_hash_table_remove_all(indexes_p->fpath2ei_ht);
#endif

		char *ptr =  buf;
		char *end = &buf[r];
		while(ptr < end) {
			struct inotify_event *event = (struct inotify_event *)ptr;

			// Removing stale wd-s

			if(event->mask & IN_IGNORED) {
				debug(2, "Cleaning up info about watch descriptor %i.", event->wd);
				indexes_remove_bywd(indexes_p, event->wd);
				SYNC_INOTIFY_HANDLE_CONTINUE;
			}

			// Getting path

			char *fpath = indexes_wd2fpath(indexes_p, event->wd);

			if(fpath == NULL) {
				debug(2, "Event %p on stale watch (wd: %i).", (void *)(long)event->mask, event->wd);
				SYNC_INOTIFY_HANDLE_CONTINUE;
			}
			debug(2, "Event %p on \"%s\" (wd: %i; fpath: \"%s\").", (void *)(long)event->mask, event->len>0?event->name:"", event->wd, fpath);

			// Getting full path

			size_t path_full_memreq = strlen(fpath) + event->len + 2;
			if(path_full_size < path_full_memreq) {
				path_full      = xrealloc(path_full, path_full_memreq);
				path_full_size = path_full_memreq;
			}

			if(event->len>0)
				sprintf(path_full, "%s/%s", fpath, event->name);
			else
				sprintf(path_full, "%s", fpath);

			// Getting infomation about file/dir/etc

			struct stat64 lstat;
			mode_t st_mode;
			size_t st_size;
			if(lstat64(path_full, &lstat)) {
				debug(2, "Cannot lstat(\"%s\", lstat). Seems, that the object disappeared.", path_full);
				if(event->mask & IN_ISDIR)
					st_mode = S_IFDIR;
				else
					st_mode = S_IFREG;
				st_size = 0;
			} else {
				st_mode = lstat.st_mode;
				st_size = lstat.st_size;
			}

			// Checking by filter rules

			path_rel = sync_path_abs2rel(ctx_p, path_full, -1, &path_rel_len, path_rel);
			ruleaction_t perm = rules_getperm(path_rel, st_mode, ctx_p->rules, RA_WALK|RA_MONITOR);

			if(!(perm&(RA_MONITOR|RA_WALK))) {
				SYNC_INOTIFY_HANDLE_CONTINUE;
			}

			// Handling different cases

			if(event->mask & IN_ISDIR) {
				if(event->mask & (IN_CREATE|IN_MOVED_TO)) {			// Appeared
					// If new dir is created

					int ret;

					if(perm & RA_WALK) {
						ret = sync_mark_walk(inotify_d, ctx_p, path_full, indexes_p);
						if(ret) {
							debug(1, "Seems, that directory \"%s\" disappeared, while trying to mark it.", path_full);
							SYNC_INOTIFY_HANDLE_CONTINUE;
						}

						ret = sync_initialsync(path_full, ctx_p, indexes_p, INITSYNC_SUBDIR);
						if(ret) {
							error("Got error from sync_initialsync()");
							errno = ret;
							count=-1;
							goto l_sync_inotify_handle_end;
						}
					}

					SYNC_INOTIFY_HANDLE_CONTINUE;
				} else 
				if(event->mask & (IN_DELETE_SELF|IN_DELETE|IN_MOVED_FROM)) {	// Disappered
					debug(2, "Disappeared \"%s\".", path_full);
				}
			}

			if(!(perm&RA_WALK)) {
				SYNC_INOTIFY_HANDLE_CONTINUE;
			}

			// Locally queueing the event

			int isnew = 0;
			eventinfo_t *evinfo = indexes_fpath2ei(indexes_p, path_rel);
			if(evinfo == NULL) {
				evinfo = (eventinfo_t *)xmalloc(sizeof(*evinfo));
				memset(evinfo, 0, sizeof(*evinfo));
				evinfo->fsize        = st_size;
				evinfo->wd           = event->wd;
				evinfo->seqid_min    = sync_seqid();
				evinfo->seqid_max    = evinfo->seqid_min;
				evinfo->objtype_old  = (event->mask & IN_CREATE) 	? EOT_DOESNTEXIST	:
				                       (event->mask & IN_ISDIR) 	? EOT_DIR 		:
				                       EOT_FILE;
				isnew++;
				debug(3, "new event: fsize == %i; wd == %i", evinfo->fsize, evinfo->wd);
			} else {
				evinfo->seqid_max    = sync_seqid();
			}
			evinfo->evmask |= event->mask;

			evinfo->objtype_new = (event->mask & (IN_DELETE_SELF|IN_DELETE|IN_MOVED_FROM))	? EOT_DOESNTEXIST :
			                      (event->mask & IN_ISDIR)					? EOT_DIR 	  : 
			                      EOT_FILE;

			debug(2, "path_rel == \"%s\"; evinfo->objtype_old == %i; evinfo->objtype_new == %i; "
					"evinfo->seqid_min == %u; evinfo->seqid_max == %u", 
					path_rel, evinfo->objtype_old, evinfo->objtype_new,
					evinfo->seqid_min, evinfo->seqid_max
				);

			if(isnew)
				indexes_fpath2ei_add(indexes_p, strdup(path_rel), evinfo);

			SYNC_INOTIFY_HANDLE_CONTINUE;
		}

		// Globally queueing captured events

		struct dosync_arg dosync_arg;
		dosync_arg.ctx_p 	= ctx_p;
		dosync_arg.indexes_p	= indexes_p;

		debug(3, "collected %i events per this time.", g_hash_table_size(indexes_p->fpath2ei_ht));

		g_hash_table_foreach(indexes_p->fpath2ei_ht, sync_inotify_handle_dosync, &dosync_arg);
		g_hash_table_remove_all(indexes_p->fpath2ei_ht);
	}

l_sync_inotify_handle_end:
	if(path_full != NULL)
		free(path_full);

	if(path_rel  != NULL)
		free(path_rel);

	return count;
}

#define SYNC_INOTIFY_LOOP_IDLE {\
	int ret;\
	if((ret=sync_idle(inotify_d, ctx_p, indexes_p))) {\
		error("got error while sync_idle().");\
		return ret;\
	}\
}

#define SYNC_INOTIFY_LOOP_CONTINUE_UNLOCK {\
	pthread_cond_broadcast(&threadsinfo_p->cond[PTHREAD_MUTEX_STATE]);\
	pthread_mutex_unlock(&threadsinfo_p->mutex[PTHREAD_MUTEX_STATE]);\
	continue;\
}

int sync_inotify_loop(int inotify_d, ctx_t *ctx_p, indexes_t *indexes_p) {
	int state = ctx_p->flags[SKIPINITSYNC] ? STATE_RUNNING : STATE_INITSYNC;
	int ret;
	state_p = &state;

	while(state != STATE_EXIT) {
		int events;

		threadsinfo_t *threadsinfo_p = thread_getinfo();
		pthread_mutex_lock(&threadsinfo_p->mutex[PTHREAD_MUTEX_STATE]);
		debug(3, "current state is %i (iteration: %u/%u)",
			state, ctx_p->iteration_num, ctx_p->flags[MAXITERATIONS]);
		events = 0;
		switch(state) {
			case STATE_PTHREAD_GC:
				main_status_update(ctx_p, state);
				if(thread_gc(ctx_p)) {
					state=STATE_EXIT;
					break;
				}
				state = STATE_RUNNING;
				SYNC_INOTIFY_LOOP_CONTINUE_UNLOCK;
			case STATE_INITSYNC:
				if(!ctx_p->flags[PTHREAD]) {
					ctx_p->iteration_num = 0;
					setenv_iteration(ctx_p->iteration_num);
				}

				main_status_update(ctx_p, state);
				pthread_cond_broadcast(&threadsinfo_p->cond[PTHREAD_MUTEX_STATE]);
				pthread_mutex_unlock(&threadsinfo_p->mutex[PTHREAD_MUTEX_STATE]);
				ret = sync_initialsync(ctx_p->watchdir, ctx_p, indexes_p, INITSYNC_FULL);
				if(ret) return ret;

				if(ctx_p->flags[ONLYINITSYNC]) {
					SYNC_INOTIFY_LOOP_IDLE;
					state = STATE_EXIT;
					return ret;
				}

				state = STATE_RUNNING;
				continue;
			case STATE_RUNNING:
				if(!ctx_p->flags[PTHREAD])
					if (ctx_p->flags[MAXITERATIONS] &&
					    ctx_p->flags[MAXITERATIONS] <= ctx_p->iteration_num)
							state = STATE_EXIT;

				if(state == STATE_RUNNING)
					events = sync_inotify_wait(inotify_d, ctx_p, indexes_p);

				if(state != STATE_RUNNING)
					SYNC_INOTIFY_LOOP_CONTINUE_UNLOCK;
				break;
			case STATE_REHASH:
				main_status_update(ctx_p, state);
				debug(1, "rehashing.");
				main_rehash(ctx_p);
				state = STATE_RUNNING;
				SYNC_INOTIFY_LOOP_CONTINUE_UNLOCK;
			case STATE_TERM:
				main_status_update(ctx_p, state);
				state = STATE_EXIT;
			case STATE_EXIT:
				main_status_update(ctx_p, state);
				SYNC_INOTIFY_LOOP_CONTINUE_UNLOCK;
		}
		pthread_cond_broadcast(&threadsinfo_p->cond[PTHREAD_MUTEX_STATE]);
		pthread_mutex_unlock(&threadsinfo_p->mutex[PTHREAD_MUTEX_STATE]);

		if(events == 0) {
			debug(2, "sync_inotify_wait(%i, ctx_p, indexes_p) timed-out.", inotify_d);
			SYNC_INOTIFY_LOOP_IDLE;
			continue;	// Timeout
		}
		if(events  < 0) {
			error("Got error while waiting for event from inotify with select().");
			return errno;
		}

		int count=sync_inotify_handle(inotify_d, ctx_p, indexes_p);
		if(count  <= 0) {
			error("Cannot handle with inotify events.");
			return errno;
		}
		main_status_update(ctx_p, state);

		if(ctx_p->flags[EXITONNOEVENTS]) // clsync exits on no events, so sync_idle() is never called. We have to force the calling of it.
			SYNC_INOTIFY_LOOP_IDLE;
	}

	SYNC_INOTIFY_LOOP_IDLE;

	debug(1, "end");
	return exitcode;

#ifdef DOXYGEN
	sync_idle(0, NULL, NULL);
#endif
}

int sync_notify_loop(int notify_d, ctx_t *ctx_p, indexes_t *indexes_p) {
	switch(ctx_p->notifyengine) {
#ifdef FANOTIFY_SUPPORT
		case NE_FANOTIFY:
			return sync_fanotify_loop(notify_d, ctx_p, indexes_p);
#endif
		case NE_INOTIFY:
			return sync_inotify_loop (notify_d, ctx_p, indexes_p);
	}
	error("unknown notify-engine: %i", ctx_p->notifyengine);
	errno = EINVAL;
	return -1;
}

void sync_sig_int(int signal) {
	debug(2, "sync_sig_int(%i): Thread %p", signal, pthread_self());
	return;
}

int sync_switch_state(pthread_t pthread_parent, int newstate) {
	if(state_p == NULL) {
		debug(3, "sync_switch_state(%p, %i), but state_p == NULL", pthread_parent, newstate);
		return 0;
	}

	debug(3, "sync_switch_state(%p, %i)", pthread_parent, newstate);

	// Getting mutexes
	threadsinfo_t *threadsinfo_p = thread_getinfo();
	if(threadsinfo_p == NULL) {
		// If no mutexes, just change the state
		goto l_sync_parent_interrupt_end;
	}
	if(!threadsinfo_p->mutex_init) {
		// If no mutexes, just change the state
		goto l_sync_parent_interrupt_end;
	}
	pthread_mutex_t *pthread_mutex_state = &threadsinfo_p->mutex[PTHREAD_MUTEX_STATE];
	pthread_cond_t  *pthread_cond_state  = &threadsinfo_p->cond [PTHREAD_MUTEX_STATE];

	// Locking all necessary mutexes
	if(pthread_mutex_trylock(pthread_mutex_state) == EBUSY) {
		while(1) {
			struct timespec time_timeout;
			clock_gettime(CLOCK_REALTIME, &time_timeout);
			time_timeout.tv_sec++;
	//		time_timeout.tv_sec  = now.tv_sec;

			debug(3, "pthread_cond_timedwait() until %li.%li", time_timeout.tv_sec, time_timeout.tv_nsec);
			if(pthread_cond_timedwait(pthread_cond_state, pthread_mutex_state, &time_timeout) != ETIMEDOUT)
				break;
			debug(3, "sending signal to interrupt blocking operations like select()-s and so on");
			pthread_kill(pthread_parent, SIGUSR_BLOPINT);
#ifdef VERYPARANOID
			int i=0;
			if(++i > KILL_TIMEOUT) {
				error("Seems we got a deadlock.");
				return EDEADLK;
			}
#endif
		}
	}
	// Changing the state

	*state_p = newstate;

#ifdef VERYPARANOID
	pthread_kill(pthread_parent, SIGUSR_BLOPINT);
#endif

	// Unlocking mutexes
	debug(3, "pthread_mutex_unlock(). New state is %i.", *state_p);

	pthread_cond_broadcast(pthread_cond_state);
	pthread_mutex_unlock(pthread_mutex_state);
	return 0;

l_sync_parent_interrupt_end:

	*state_p = newstate;
	pthread_kill(pthread_parent, SIGUSR_BLOPINT);

	return 0;

}

int *sync_sighandler_exitcode_p = NULL;
int sync_sighandler(sighandler_arg_t *sighandler_arg_p) {
	int signal, ret;
	ctx_t *ctx_p     = sighandler_arg_p->ctx_p;
//	indexes_t *indexes_p     = sighandler_arg_p->indexes_p;
	pthread_t pthread_parent = sighandler_arg_p->pthread_parent;
	sigset_t *sigset_p	 = sighandler_arg_p->sigset_p;
	int *exitcode_p		 = sighandler_arg_p->exitcode_p;

	sync_sighandler_exitcode_p = exitcode_p;

	while(1) {
		debug(3, "waiting for signal");
		ret = sigwait(sigset_p, &signal);

		if(state_p == NULL) {

			switch(signal) {
				case SIGALRM:
					*exitcode_p = ETIME;
				case SIGTERM:
				case SIGINT:
					// TODO: remove the exit() from here. Main thread should exit itself
					exit(*exitcode_p);
					break;
				default:
					error("Warning: Got signal %i, but the main loop is not started, yet. Ignoring the signal.", signal);
					break;
			}
			continue;
		}

		debug(3, "got signal %i. *state_p == %i.", signal, *state_p);

		if(ret) {
			// TODO: handle an error here
		}

		switch(signal) {
			case SIGALRM:
				*exitcode_p = ETIME;
			case SIGTERM:
			case SIGINT:
				sync_switch_state(pthread_parent, STATE_TERM);
				// bugfix of https://github.com/xaionaro/clsync/issues/44
				while(ctx_p->children) { // Killing children if non-pthread mode or/and (mode=="so" or mode=="rsyncso")
					pid_t child_pid = ctx_p->child_pid[--ctx_p->children];
					if(waitpid(child_pid, NULL, WNOHANG)>=0) {
						debug(3, "Sending signal %u to child process with pid %u.",
							signal, child_pid);
						kill(child_pid, signal);
						sleep(1);	// TODO: replace this sleep() with something to do not sleep if process already died
					} else
						continue;
					if(waitpid(child_pid, NULL, WNOHANG)>=0) {
						debug(3, "Sending signal SIGQUIT to child process with pid %u.",
							child_pid);
						kill(child_pid, SIGQUIT);
						sleep(1);	// TODO: replace this sleep() with something to do not sleep if process already died
					} else
						continue;
					if(waitpid(child_pid, NULL, WNOHANG)>=0) {
						debug(3, "Sending signal SIGKILL to child process with pid %u.",
							child_pid);
						kill(child_pid, SIGKILL);
					}
				}
				break;
			case SIGHUP:
				sync_switch_state(pthread_parent, STATE_REHASH);
				break;
			case SIGUSR_PTHREAD_GC:
				sync_switch_state(pthread_parent, STATE_PTHREAD_GC);
				break;
			case SIGUSR_INITSYNC:
				sync_switch_state(pthread_parent, STATE_INITSYNC);
				break;
			default:
				error("Unknown signal: %i. Exit.", signal);
				sync_switch_state(pthread_parent, STATE_TERM);
				break;
		}

		if((*state_p == STATE_TERM) || (*state_p == STATE_EXIT)) {
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
	int ret, i;
	sighandler_arg_t sighandler_arg = {0};

	// Creating signal handler thread
	sigset_t sigset_sighandler;
	sigemptyset(&sigset_sighandler);
	sigaddset(&sigset_sighandler, SIGALRM);
	sigaddset(&sigset_sighandler, SIGHUP);
	sigaddset(&sigset_sighandler, SIGTERM);
	sigaddset(&sigset_sighandler, SIGINT);
	sigaddset(&sigset_sighandler, SIGUSR_PTHREAD_GC);
	sigaddset(&sigset_sighandler, SIGUSR_INITSYNC);

	ret = pthread_sigmask(SIG_BLOCK, &sigset_sighandler, NULL);
	if(ret)	return ret;

	sighandler_arg.ctx_p        =  ctx_p;
//	sighandler_arg.indexes_p        = &indexes;
	sighandler_arg.pthread_parent   =  pthread_self();
	sighandler_arg.exitcode_p	= &ret;
	sighandler_arg.sigset_p		= &sigset_sighandler;
	ret = pthread_create(&pthread_sighandler, NULL, (void *(*)(void *))sync_sighandler, &sighandler_arg);
	if(ret) return ret;

	sigset_t sigset_parent;
	sigemptyset(&sigset_parent);

	sigaddset(&sigset_parent, SIGUSR_BLOPINT);
	ret = pthread_sigmask(SIG_UNBLOCK, &sigset_parent, NULL);
	if(ret)	return ret;

	signal(SIGUSR_BLOPINT,	sync_sig_int);

	// Creating hash tables

	indexes_t indexes         = {NULL};
	indexes.wd2fpath_ht       = g_hash_table_new_full(g_direct_hash, g_direct_equal, 0,    0);
	indexes.fpath2wd_ht       = g_hash_table_new_full(g_str_hash,	 g_str_equal,	 free, 0);
	indexes.fpath2ei_ht       = g_hash_table_new_full(g_str_hash,	 g_str_equal,	 free, free);
	indexes.exc_fpath_ht      = g_hash_table_new_full(g_str_hash,	 g_str_equal,	 free, 0);
	indexes.out_lines_aggr_ht = g_hash_table_new_full(g_str_hash,	 g_str_equal,	 free, 0);
	i=0;
	while(i<QUEUE_MAX) {
		indexes.fpath2ei_coll_ht[i]  = g_hash_table_new_full(g_str_hash,    g_str_equal,    free, free);
		indexes.exc_fpath_coll_ht[i] = g_hash_table_new_full(g_str_hash,    g_str_equal,    free, 0);
		i++;
	}

	// Loading dynamical libraries
	if(ctx_p->flags[MODE] == MODE_SO || ctx_p->flags[MODE] == MODE_RSYNCSO) {
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

	int notify_d=0;

#ifdef ENABLE_SOCKET
	// Creating control socket
	if(ctx_p->socketpath != NULL)
		ret = control_run(ctx_p);
#endif

	if(!ctx_p->flags[ONLYINITSYNC]) {

		// Initializing FS monitor kernel subsystem in this userspace application

		notify_d = sync_notify_init(ctx_p);
		if(notify_d == -1) return errno;

		// Marking file tree for FS monitor
		ret = sync_mark_walk(notify_d, ctx_p, ctx_p->watchdir, &indexes);
		if(ret) return ret;

	}

	// "Infinite" loop of processling the events
	ret = sync_notify_loop(notify_d, ctx_p, &indexes);
	if(ret) return ret;
	debug(1, "sync_notify_loop() ended");

#ifdef ENABLE_SOCKET
	// Removing control socket
	if(ctx_p->socketpath != NULL)
		control_cleanup(ctx_p);
#endif

	debug(1, "killing sighandler");
	// TODO: Do cleanup of watching points
	pthread_kill(pthread_sighandler, SIGTERM);
	pthread_join(pthread_sighandler, NULL);

	// Killing children

	thread_cleanup(ctx_p);

	// Closing rest sockets and files

	debug(3, "Closing notify_d");
	close(notify_d);

	// Closing shared libraries
	if(ctx_p->flags[MODE] == MODE_SO) {
		int _ret;
		if(ctx_p->handler_funct.deinit != NULL)
			if((_ret = ctx_p->handler_funct.deinit())) {
				error("Cannot deinit sync-handler module.");
				if(!ret) ret = _ret;
			}

		if(dlclose(ctx_p->handler_handle)) {
			error("Cannot unload shared object file \"%s\": %s",
				ctx_p->handlerfpath, dlerror());
			if(!ret) ret = -1;
		}
	}

	// Cleaning up run-time routines
	rsync_escape_cleanup();

	// Removing hash-tables
	debug(3, "Closing hash tables");
	g_hash_table_destroy(indexes.wd2fpath_ht);
	g_hash_table_destroy(indexes.fpath2wd_ht);
	g_hash_table_destroy(indexes.fpath2ei_ht);
	g_hash_table_destroy(indexes.exc_fpath_ht);
	g_hash_table_destroy(indexes.out_lines_aggr_ht);
	i=0;
	while(i<QUEUE_MAX) {
		g_hash_table_destroy(indexes.fpath2ei_coll_ht[i]);
		g_hash_table_destroy(indexes.exc_fpath_coll_ht[i]);
		i++;
	}

	// Deinitializing cluster subsystem
#ifdef CLUSTER_SUPPORT
	if(ctx_p->cluster_iface != NULL) {
		int _ret;
		_ret = cluster_deinit();
		if(_ret) {
			error("Cannot deinitialize cluster subsystem.", strerror(_ret), _ret);
			ret = _ret;
		}
	}
#endif

#ifdef VERYPARANOID
	// One second for another threads
	sleep(1);
#endif

	if(ctx_p->flags[EXITHOOK]) {
		char *argv[] = { ctx_p->exithookfile, ctx_p->label, NULL};
		exec_argv(argv, NULL);
	}
	return ret;
}

