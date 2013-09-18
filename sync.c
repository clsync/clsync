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
#include "output.h"
#include "fileutils.h"
#include "malloc.h"
#include "cluster.h"
#include "sync.h"
#include "glibex.h"

#include <dlfcn.h>

pthread_t pthread_sighandler;

gpointer eidup(gpointer ei_gp) {
	eventinfo_t *ei = (eventinfo_t *)ei_gp;

	eventinfo_t *ei_dup = (eventinfo_t *)xmalloc(sizeof(*ei));
	memcpy(ei_dup, ei, sizeof(*ei));

	return (gpointer)ei_dup;
}

static inline int _exitcode_process(options_t *options_p, int exitcode) {
	if(options_p->isignoredexitcode[(unsigned char)exitcode])
		return 0;

	if(exitcode && !((options_p->flags[RSYNC]>=2) && (exitcode == 24))) {
		printf_e("Error: Got non-zero exitcode %i from __sync_exec().\n", exitcode);
		return exitcode;
	}

	return 0;
}

int exitcode_process(options_t *options_p, int exitcode) {
	int err = _exitcode_process(options_p, exitcode);

	if(err) printf_e("Error: Got error-report from exitcode_process().\nExitcode is %i, strerror(%i) returns \"%s\". However strerror() is not ensures compliance "
			"between exitcode and error description for every utility. So, e.g if you're using rsync, you should look for the error description "
			"into rsync's manpage (\"man 1 rsync\"). Also some advices about diagnostics can be found in clsync's manpage (\"man 1 clsync\", see DIAGNOSTICS)\n", 
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
	printf_ddd("Debug3: rules_search_getperm(\"%s\", %p, %p, %p, %p)\n", 
			fpath, (void *)(unsigned long)st_mode, rules_p,
			(void *)(long)ruleaction, (void *)(long)rule_pp
		);

	int i;
	i = 0;
	rule_t *rule_p = rules_p;
	mode_t ftype = st_mode & S_IFMT;

	if(rule_pp != NULL)
		if(*rule_pp != NULL) {
			printf_ddd("Debug3: rules_search_getperm(): Previous position is set.\n");
			if(rule_p->mask == RA_NONE)
				return rule_p->perm;

			rule_p = ++(*rule_pp);
			i = rule_p->num;
		}

	printf_ddd("Debug3: rules_search_getperm(): Starting from position %i\n", i);
	while(rule_p->mask != RA_NONE) {
		printf_ddd("Debug3: rules_search_getperm(): %i -> %p/%p: type compare: %p, %p -> %p\n", 
				i,
				(void *)(long)rule_p->perm, (void *)(long)rule_p->mask,
				(void *)(unsigned long)ftype, (void *)(unsigned long)rule_p->objtype, 
				(unsigned char)!(rule_p->objtype && (rule_p->objtype != ftype))
			);

		if(!(rule_p->mask & ruleaction)) {	// Checking wrong operation type
			printf_ddd("Debug3: rules_search_getperm(): action-mask mismatch. Skipping.\n");
			rule_p++;i++;// = &rules_p[++i];
			continue;
		}

		if(rule_p->objtype && (rule_p->objtype != ftype)) {
			printf_ddd("Debug3: rules_search_getperm(): objtype mismatch. Skipping.\n");
			rule_p++;i++;// = &rules_p[++i];
			continue;
		}

		if(!regexec(&rule_p->expr, fpath, 0, NULL, 0))
			break;

		printf_ddd("Debug3: rules_search_getperm(): doesn't match regex. Skipping.\n");
		rule_p++;i++;// = &rules_p[++i];

	}

	printf_dd("Debug2: matched to rule #%u for \"%s\":\t%p/%p (queried: %p).\n", rule_p->mask==RA_NONE?-1:i, fpath, 
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

	while((gotpermto&ruleactions) != ruleactions) {
		rules_search_getperm(fpath, st_mode, rules_p, ruleactions, &rule_p);
		if(rule_p->mask == RA_NONE) { // End of rules' list 
			resultperm |= rule_p->perm & (gotpermto^RA_ALL);
			break;
		}
		resultperm |= rule_p->perm & ((gotpermto^rule_p->mask)&rule_p->mask);	// Adding perm bitmask of operations that was unknown before
		gotpermto  |= rule_p->mask;						// Adding the mask
	}

	printf_ddd("Debug3: rules_getperm(\"%s\", %i, rules_p, %p): result perm is %p\n",
		fpath, st_mode, (void *)(long)ruleactions, (void *)(long)resultperm);

	return resultperm;
}

// Removes necessary rows from hash_tables if some watching descriptor closed
// Return: 0 on success, non-zero on fail

static inline int indexes_remove_bywd(indexes_t *indexes_p, int wd) {
	int ret=0;

	char *fpath = g_hash_table_lookup(indexes_p->wd2fpath_ht, GINT_TO_POINTER(wd));

	ret |= g_hash_table_remove(indexes_p->wd2fpath_ht, GINT_TO_POINTER(wd));
	if(fpath == NULL) {
		printf_e("Error: Cannot remove from index \"fpath2wd\" by wd %i.\n", wd);
		return -1;
	}
	ret |= g_hash_table_remove(indexes_p->fpath2wd_ht, fpath);

	return ret;
}

// Adds necessary rows to hash_tables if some watching descriptor opened
// Return: 0 on success, non-zero on fail

static inline int indexes_add_wd(indexes_t *indexes_p, int wd, const char *fpath_const, size_t fpathlen) {
	printf_ddd("Debug3: indexes_add_wd(indexes_p, %i, \"%s\", %i)\n", wd, fpath_const, fpathlen);

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

	printf_ddd("Debug3: indexes_queueevent(indexes_p, \"%s\", evinfo, %i). It's now %i events collected in queue %i.\n", fpath, queue_id, g_hash_table_size(indexes_p->fpath2ei_coll_ht[queue_id]), queue_id);
	return 0;
}

static inline int indexes_removefromqueue(indexes_t *indexes_p, char *fpath, queue_id_t queue_id) {
//	printf_ddd("Debug3: indexes_removefromqueue(indexes_p, \"%s\", %i).\n", fpath, queue_id);

	g_hash_table_remove(indexes_p->fpath2ei_coll_ht[queue_id], fpath);

	printf_ddd("Debug3: indexes_removefromqueue(indexes_p, \"%s\", %i). It's now %i events collected in queue %i.\n", fpath, queue_id, g_hash_table_size(indexes_p->fpath2ei_coll_ht[queue_id]), queue_id);
	return 0;
}

static inline int indexes_addexclude(indexes_t *indexes_p, char *fpath, queue_id_t queue_id) {
	g_hash_table_replace(indexes_p->exc_fpath_coll_ht[queue_id], fpath, GINT_TO_POINTER(1));

	printf_ddd("Debug3: indexes_addexclude(indexes_p, \"%s\", %i). It's now %i events collected in queue %i.\n", fpath, queue_id, g_hash_table_size(indexes_p->exc_fpath_coll_ht[queue_id]), queue_id);
	return 0;
}

static inline int indexes_addexclude_aggr(indexes_t *indexes_p, char *fpath) {
	g_hash_table_replace(indexes_p->exc_fpath_ht, fpath, GINT_TO_POINTER(1));

	printf_ddd("Debug3: indexes_addexclude_aggr(indexes_p, \"%s\").\n", fpath);
	return 0;
}

static inline int indexes_outaggr_add(indexes_t *indexes_p, char *outline) {
	g_hash_table_replace(indexes_p->out_lines_aggr_ht, outline, GINT_TO_POINTER(1));

	printf_ddd("Debug3: indexes_outaggr_aggr(indexes_p, \"%s\").\n", outline);
	return 0;
}

static threadsinfo_t *thread_getinfo() {	// TODO: optimize this
	static threadsinfo_t threadsinfo={{{{0}}},{{{0}}},0};
	if(!threadsinfo.mutex_init) {
		int i=0;
		while(i < PTHREAD_MUTEX_MAX) {
			if(pthread_mutex_init(&threadsinfo.mutex[i], NULL)) {
				printf_e("Error: Cannot pthread_mutex_init(): %s (errno: %i).\n", strerror(errno), errno);
				return NULL;
			}
			if(pthread_cond_init (&threadsinfo.cond [i], NULL)) {
				printf_e("Error: Cannot pthread_cond_init(): %s (errno: %i).\n", strerror(errno), errno);
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
		printf_ddd("Debug3: threadsinfo_p->threads[%i].state == %i;\tthreadsinfo_p->threads[%i].pthread == %p;\tthreadsinfo_p->threads[%i].expiretime == %i\n", 
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

	printf_ddd("Debug3: thread_nextexpiretime(): nextexpiretime == %i\n", nextexpiretime);
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
		thread_num   = threadinfo_p->thread_num;
	} else {
		if(threadsinfo_p->used >= threadsinfo_p->allocated) {
			threadsinfo_p->allocated += ALLOC_PORTION;
			printf_dd("Debug2: Reallocated memory for threadsinfo -> %i.\n", threadsinfo_p->allocated);
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


	printf_dd("Debug2: thread_new -> thread_num: %i; used: %i\n", thread_num, threadsinfo_p->used);
	return threadinfo_p;
}

int thread_del_bynum(int thread_num) {
	printf_dd("Debug2: thread_del_bynum(%i)\n", thread_num);
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
		printf_ddd("Debug3: thread_del_bynum(%i): there're %i threads left (#0).\n", thread_num, threadsinfo_p->used - threadsinfo_p->stacklen);
		return 0;
	}
	
	threadinfo_t *t = &threadsinfo_p->threads[threadsinfo_p->used-1];
	if(t->state == STATE_EXIT) {
		threadsinfo_p->used--;
		printf_ddd("Debug3: thread_del_bynum(): %i [%p] -> %i [%p]; left: %i\n", 
			threadsinfo_p->used, t->pthread, thread_num, threadinfo_p->pthread, threadsinfo_p->used - threadsinfo_p->stacklen);
		memcpy(threadinfo_p, t, sizeof(*threadinfo_p));
	} else {
#ifdef PARANOID
		if(threadsinfo_p->stacklen >= threadsinfo_p->allocated) {
			printf_e("Error: thread_del_bynum(): Threads metadata structures pointers stack overflowed!");
			return EINVAL;
		}
#endif
		threadsinfo_p->threadsstack[threadsinfo_p->stacklen++] = threadinfo_p;
	}

	printf_ddd("Debug3: thread_del_bynum(%i): there're %i threads left (#1).\n", thread_num, threadsinfo_p->used - threadsinfo_p->stacklen);
	return 0;
}

int thread_gc(options_t *options_p) {
	int thread_num;
	time_t tm = time(NULL);
	printf_ddd("Debug3: thread_gc(): tm == %i; thread %p\n", tm, pthread_self());
	if(!options_p->flags[PTHREAD])
		return 0;

	threadsinfo_t *threadsinfo_p = thread_getinfo();
	if(threadsinfo_p == NULL)
		return errno;

	printf_dd("Debug2: thread_gc(): There're %i threads.\n", threadsinfo_p->used);
	thread_num=-1;
	while(++thread_num < threadsinfo_p->used) {
		int err;
		threadinfo_t *threadinfo_p = &threadsinfo_p->threads[thread_num];

		printf_ddd("Debug3: thread_gc(): Trying thread #%i (==%i) (state: %i; expire at: %i, now: %i, exitcode: %i, errcode: %i; i_p: %p; p: %p).\n", 
			thread_num, threadinfo_p->thread_num, threadinfo_p->state, threadinfo_p->expiretime, tm, threadinfo_p->exitcode, 
			threadinfo_p->errcode, threadinfo_p, threadinfo_p->pthread);

		if(threadinfo_p->state == STATE_EXIT)
			continue;

		if(threadinfo_p->expiretime && (threadinfo_p->expiretime <= tm)) {
			if(pthread_tryjoin_np(threadinfo_p->pthread, NULL)) {	// TODO: check this pthread_tryjoin_np() on error returnings
				printf_e("Debug3: thread_gc(): Thread #%i is alive too long: %lu <= %lu (started at %lu)\n", thread_num, threadinfo_p->expiretime, tm, threadinfo_p->starttime);
				return ETIME;
			}
		}

#ifndef VERYPARANOID
		if(threadinfo_p->state != STATE_TERM) {
			printf_ddd("Debug3: thread_gc(): Thread #%i is busy, skipping (#0).\n", thread_num);
			continue;
		}
#endif


		printf_ddd("Debug3: thread_gc(): Trying to join thread #%i: %p\n", thread_num, threadinfo_p->pthread);

#ifndef VERYPARANOID
		switch((err=pthread_join(threadinfo_p->pthread, NULL))) {
#else
		switch((err=pthread_tryjoin_np(threadinfo_p->pthread, NULL))) {
			case EBUSY:
				printf_ddd("Debug3: thread_gc(): Thread #%i is busy, skipping (#1).\n", thread_num);
				continue;
#endif
			case EDEADLK:
			case EINVAL:
			case 0:
				printf_ddd("Debug3: thread_gc(): Thread #%i is finished with exitcode %i (errcode %i), deleting. threadinfo_p == %p\n",
					thread_num, threadinfo_p->exitcode, threadinfo_p->errcode, threadinfo_p);
				break;
			default:
				printf_e("Error: Got error while pthread_join() or pthread_tryjoin_np(): %s (errno: %i).\n", strerror(err), err);
				return errno;

		}

		if(threadinfo_p->errcode) {
			printf_e("Error: Got error from thread #%i: errcode %i.\n", thread_num, threadinfo_p->errcode);
			thread_del_bynum(thread_num);
			return threadinfo_p->errcode;
		}

		if(thread_del_bynum(thread_num))
			return errno;
	}

	printf_ddd("Debug3: thread_gc(): There're %i threads left.\n", threadsinfo_p->used - threadsinfo_p->stacklen);
	return 0;
}

int thread_cleanup(options_t *options_p) {
	printf_ddd("Debug3: thread_cleanup(). Thread %p\n", pthread_self());
	threadsinfo_t *threadsinfo_p = thread_getinfo();
	if(threadsinfo_p == NULL)
		return errno;

	// Waiting for threads:
	printf_d("Debug: There're %i opened threads. Waiting.\n", threadsinfo_p->used);
	while(threadsinfo_p->used) {
//		int err;
		threadinfo_t *threadinfo_p = &threadsinfo_p->threads[--threadsinfo_p->used];
		if(threadinfo_p->state == STATE_EXIT)
			continue;
		//pthread_kill(threadinfo_p->pthread, SIGTERM);
		printf_d("Debug: killing pid %i with SIGTERM\n", threadinfo_p->child_pid);
		kill(threadinfo_p->child_pid, SIGTERM);
		pthread_join(threadinfo_p->pthread, NULL);
		printf_dd("Debug2: thread #%i exitcode: %i\n", threadsinfo_p->used, threadinfo_p->exitcode);
/*
		if(threadinfo_p->callback)
			if((err=threadinfo_p->callback(options_p, threadinfo_p->argv)))
				printf_e("Warning: Got error from callback function: %s (errno: %i).\n", strerror(err), err);
*/
		char **ptr = threadinfo_p->argv;
		while(*ptr)
			free(*(ptr++));
		free(threadinfo_p->argv);
	}
	printf_ddd("Debug3: thread_cleanup(): All threads are closed.\n");

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

	printf_ddd("Debug3: thread_cleanup(): done.\n");
	return 0;
}

int *state_p = NULL;
int exitcode = 0;

int exec_argv(char **argv, int *child_pid DEBUGV(, int _rand)) {
	printf_ddd("Debug3: exec_argv(): Thread %p.\n", pthread_self());
	pid_t pid;
	int status;

	// Forking
	pid = fork();
	switch(pid) {
		case -1: 
			printf_e("Error: Cannot fork(): %s (errno: %i).\n", strerror(errno), errno);
			return errno;
		case  0:
			execvp(argv[0], (char *const *)argv);
			return errno;
	}
//	printf_ddd("Debug3: exec_argv(): After fork thread %p"DEBUGV(" (%i)")".\n", pthread_self() DEBUGV(, _rand));

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

//	printf_ddd("Debug3: exec_argv(): Pre-wait thread %p"DEBUGV(" (%i)")".\n", pthread_self() DEBUGV(, _rand));
	if(waitpid(pid, &status, 0) != pid) {
		printf_e("Error: Cannot waitid(): %s (errno: %i).\n", strerror(errno), errno);
		return errno;
	}
//	printf_ddd("Debug3: exec_argv(): After-wait thread %p"DEBUGV(" (%i)")".\n", pthread_self() DEBUGV(, _rand));

#ifdef VERYPARANOID
	pthread_sigmask(SIG_SETMASK, &sigset_old, NULL);
#endif

	// Return
	int exitcode = WEXITSTATUS(status);
	printf_ddd("Debug3: exec_argv(): execution completed with exitcode %i. Thread %p"DEBUGV(" (%i)")".\n", exitcode, pthread_self() DEBUGV(, _rand));

	return exitcode;
}

static inline int thread_exit(threadinfo_t *threadinfo_p, int exitcode DEBUGV(, int _rand)) {
	int err;
	threadinfo_p->exitcode = exitcode;

#if _DEBUG | VERYPARANOID
	if(threadinfo_p->pthread != pthread_self()) {
		printf_e("Error: thread_exit(): pthread id mismatch! (i_p->p) %p != (p) %p"DEBUGV("; rand == %i")"\n", threadinfo_p->pthread, pthread_self() DEBUGV(, _rand));
		return EINVAL;
	}
#endif

	if((err=exitcode_process(threadinfo_p->options_p, threadinfo_p->exitcode))) {
		printf_e("Error: thread_exit(): Bad exitcode %i (errcode %i)\n", exitcode, err);
		threadinfo_p->errcode = err;
	}

	if((threadinfo_p->callback) && !(err)) {
		if(threadinfo_p->options_p->flags[DEBUG]>2) {
			printf_ddd("Debug3: thread_exit(): thread %p, argv: \n", threadinfo_p->pthread);
			char **argv = threadinfo_p->argv;
			while(*argv) {
				printf_ddd("\t%p == %s\n", *argv, *argv);
				argv++;
			}
		}
		if((err=threadinfo_p->callback(threadinfo_p->options_p, threadinfo_p->argv))) {
			printf_e("Error: Got error from callback function: %s (errno: %i).\n", strerror(err), err);
			threadinfo_p->errcode = err;
		}
	}

	// Notifying the parent-thread, that it's time to collect garbage threads
	threadinfo_p->state    = STATE_TERM;
	printf_ddd("Debug3: thread_exit(): thread %p is sending signal to sighandler to call GC\n", threadinfo_p->pthread);
	return pthread_kill(pthread_sighandler, SIGUSR_PTHREAD_GC);
}

static inline void so_call_sync_finished(int n, api_eventinfo_t *ei) {
	int i = 0;
	api_eventinfo_t *ei_i = ei;
	while(i < n) {
#ifdef PARANOID
		if(ei_i->path == NULL) {
			printf_e("Warning: so_call_sync_finished(): ei_i->path == NULL\n");
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
	printf_ddd("Debug3: so_call_exec_thread(): thread_num == %i; threadinfo_p == %p; i_p->pthread %p; thread %p\n", 
			threadinfo_p->thread_num, threadinfo_p, threadinfo_p->pthread, pthread_self());

	options_t *options_p	= threadinfo_p->options_p;
	int n			= threadinfo_p->n;
	api_eventinfo_t *ei	= threadinfo_p->ei;

	int ret = options_p->handler_funct.sync(n, ei);
	so_call_sync_finished(n, ei);

	int err;
	if((err=thread_exit(threadinfo_p, ret DEBUGV(, 0)))) {
		exitcode = err;	// This's global variable "exitcode"
		pthread_kill(pthread_sighandler, SIGTERM);
	}

	return ret;
}

static inline int so_call_sync(options_t *options_p, indexes_t *indexes_p, int n, api_eventinfo_t *ei) {
	printf_dd("Debug2: so_call_exec(): n == %i\n", n);

	if(!options_p->flags[PTHREAD]) {
		int ret = options_p->handler_funct.sync(n, ei);
		so_call_sync_finished(n, ei);
		return ret;
	}

	threadinfo_t *threadinfo_p = thread_new();
	if(threadinfo_p == NULL)
		return errno;

	threadinfo_p->callback    = NULL;
	threadinfo_p->argv        = NULL;
	threadinfo_p->options_p   = options_p;
	threadinfo_p->starttime	  = time(NULL);
	threadinfo_p->fpath2ei_ht = g_hash_table_dup(indexes_p->fpath2ei_ht, g_str_hash, g_str_equal, free, free, (gpointer(*)(gpointer))strdup, eidup);
	threadinfo_p->n           = n;
	threadinfo_p->ei          = ei;

	if(options_p->synctimeout)
		threadinfo_p->expiretime = threadinfo_p->starttime + options_p->synctimeout;

	if(pthread_create(&threadinfo_p->pthread, NULL, (void *(*)(void *))so_call_sync_thread, threadinfo_p)) {
		printf_e("Error: Cannot pthread_create(): %s (errno: %i).\n", strerror(errno), errno);
		return errno;
	}
	printf_ddd("Debug3: sync_exec_thread(): thread %p\n", threadinfo_p->pthread);
	return 0;

}


// === SYNC_EXEC() === {

#define SYNC_EXEC(...) (options_p->flags[PTHREAD]?sync_exec_thread:sync_exec)(__VA_ARGS__)


#define _sync_exec_getargv(argv, firstarg, COPYARG) {\
	va_list arglist;\
	va_start(arglist, firstarg);\
\
	int i = 0;\
	do {\
		char *arg;\
		if(i >= MAXARGUMENTS) {\
			printf_e("Error: Too many arguments (%i >= %i).\n", i, MAXARGUMENTS);\
			return ENOMEM;\
		}\
		arg = (char *)va_arg(arglist, const char *const);\
		argv[i] = arg!=NULL ? COPYARG : NULL;\
\
		printf_dd("Debug2: argv[%i] = %s\n", i, argv[i]);\
	} while(argv[i++] != NULL);\
	va_end(arglist);\
}

char *sync_path_abs2rel(options_t *options_p, const char *path_abs, size_t path_abs_len, size_t *path_rel_len_p, char *path_rel_oldptr) {
	if(path_abs == NULL)
		return NULL;

	if(path_abs_len == -1)
		path_abs_len = strlen(path_abs);

	size_t path_rel_len;
	char  *path_rel;

	signed long path_rel_len_signed = path_abs_len - (options_p->watchdirlen+1);

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

	memcpy(path_rel, &path_abs[options_p->watchdirlen+1], path_rel_len+1);

#ifdef VERYPARANOID
	// Removing "/" on the end
	printf_ddd("Debug3: sync_path_abs2rel(): \"%s\" (len: %i) --%i--> \"%s\" (len: %i) + ", 
		path_abs, path_abs_len, path_rel[path_rel_len - 1] == '/',
		options_p->watchdirwslash, options_p->watchdirlen+1);
	if(path_rel[path_rel_len - 1] == '/')
		path_rel[--path_rel_len] = 0x00;
	printf_ddd("\"%s\" (len: %i)\n", path_rel, path_rel_len);
#endif

	if(path_rel_len_p != NULL)
		*path_rel_len_p = path_rel_len;

	return path_rel;
}

static inline int sync_exec(options_t *options_p, indexes_t *indexes_p, thread_callbackfunct_t callback, ...) {
	printf_dd("Debug2: sync_exec()\n");

	char **argv = (char **)xcalloc(sizeof(char *), MAXARGUMENTS);
	memset(argv, 0, sizeof(char *)*MAXARGUMENTS);

	_sync_exec_getargv(argv, callback, arg);

	alarm(options_p->synctimeout);
	int exitcode = exec_argv(argv, NULL DEBUGV(, 0));
	alarm(0);

	int ret;
	if((ret=exitcode_process(options_p, exitcode))) {
		printf_e("Error: sync_exec(): Bad exitcode %i\n", exitcode);
		goto l_sync_exec_end;
	}

	if(callback != NULL) {
		ret = callback(options_p, argv);
		if(ret) {
			printf_e("Error: Got error while callback(): %s (errno: %i).\n", strerror(ret), ret);
			goto l_sync_exec_end;
		}
	}

l_sync_exec_end:
	free(argv);
	return ret;
}

int __sync_exec_thread(threadinfo_t *threadinfo_p) {
	char **argv			= threadinfo_p->argv;
#ifdef _DEBUG
	int _rand=rand();
#endif

	printf_ddd("Debug3: __sync_exec_thread(): thread_num == %i; threadinfo_p == %p; i_p->pthread %p; thread %p"DEBUGV("; rand == %i")"\n", 
			threadinfo_p->thread_num, threadinfo_p, threadinfo_p->pthread, pthread_self() DEBUGV(, _rand));

	int exec_exitcode = exec_argv(argv, &threadinfo_p->child_pid DEBUGV(, _rand));

	g_hash_table_destroy(threadinfo_p->fpath2ei_ht);

	int err;
	if((err=thread_exit(threadinfo_p, exec_exitcode DEBUGV(, _rand)))) {
		exitcode = err;	// This's global variable "exitcode"
		pthread_kill(pthread_sighandler, SIGTERM);
	}

	printf_ddd("Debug3: __sync_exec_thread(): thread_num == %i; threadinfo_p == %p; i_p->pthread %p; thread %p"DEBUGV("; rand == %i")"; errcode %i\n", 
			threadinfo_p->thread_num, threadinfo_p, threadinfo_p->pthread, pthread_self(), DEBUGV(_rand,) threadinfo_p->errcode);
	return exec_exitcode;
}

static inline int sync_exec_thread(options_t *options_p, indexes_t *indexes_p, thread_callbackfunct_t callback, ...) {
	printf_dd("Debug2: sync_exec_thread()\n");

	char **argv = (char **)xcalloc(sizeof(char *), MAXARGUMENTS);
	memset(argv, 0, sizeof(char *)*MAXARGUMENTS);

	_sync_exec_getargv(argv, callback, strdup(arg));

	threadinfo_t *threadinfo_p = thread_new();
	if(threadinfo_p == NULL)
		return errno;

	threadinfo_p->callback    = callback;
	threadinfo_p->argv        = argv;
	threadinfo_p->options_p   = options_p;
	threadinfo_p->starttime	  = time(NULL);
	threadinfo_p->fpath2ei_ht = g_hash_table_dup(indexes_p->fpath2ei_ht, g_str_hash, g_str_equal, free, free, (gpointer(*)(gpointer))strdup, eidup);

	if(options_p->synctimeout)
		threadinfo_p->expiretime = threadinfo_p->starttime + options_p->synctimeout;

	if(pthread_create(&threadinfo_p->pthread, NULL, (void *(*)(void *))__sync_exec_thread, threadinfo_p)) {
		printf_e("Error: Cannot pthread_create(): %s (errno: %i).\n", strerror(errno), errno);
		return errno;
	}
	printf_ddd("Debug3: sync_exec_thread(): thread %p\n", threadinfo_p->pthread);
	return 0;
}

// } === SYNC_EXEC() ===

static int sync_queuesync(const char *fpath_rel, eventinfo_t *evinfo, options_t *options_p, indexes_t *indexes_p, queue_id_t queue_id) {

	printf_ddd("Debug3: sync_queuesync(\"%s\", ...): fsize == %lu; tres == %lu, queue_id == \n", fpath_rel, evinfo->fsize, options_p->bfilethreshold, queue_id);
	if(queue_id == QUEUE_AUTO)
		queue_id = (evinfo->fsize > options_p->bfilethreshold) ? QUEUE_BIGFILE : QUEUE_NORMAL;

	queueinfo_t *queueinfo = &options_p->_queues[queue_id];

	if(!queueinfo->stime)
		queueinfo->stime = time(NULL);

//	char *fpath_rel = sync_path_abs2rel(options_p, fpath, -1, NULL, NULL);

	// Filename can contain "\n" character that conflicts with event-row separator of list-files.
	if(strchr(fpath_rel, '\n')) {
		// At the moment, we will just ignore events of such files :(
		printf_ddd("Debug3: sync_queuesync(): There's \"\\n\" character in path \"%s\". Ignoring it :(. Feedback to: https://github.com/xaionaro/clsync/issues/12\n", fpath_rel);
		return 0;
	}

	eventinfo_t *evinfo_dup = (eventinfo_t *)xmalloc(sizeof(*evinfo_dup));
	memcpy(evinfo_dup, evinfo, sizeof(*evinfo_dup));

#ifdef CLUSTER_SUPPORT
	if(options_p->cluster_iface)
		cluster_capture(fpath_rel);
#endif

	return indexes_queueevent(indexes_p, strdup(fpath_rel), evinfo_dup, queue_id);
}

int sync_initialsync_walk(options_t *options_p, const char *dirpath, indexes_t *indexes_p, queue_id_t queue_id, initsync_t initsync) {
	int ret = 0;
	const char *rootpaths[] = {dirpath, NULL};
	eventinfo_t evinfo;
	FTS *tree;
	rule_t *rules_p = options_p->rules;
	printf_dd("Debug2: sync_initialsync_walk(options_p, \"%s\", indexes_p, %i, %i).\n", dirpath, queue_id, initsync);

	char skip_rules = (initsync==INITSYNC_FULL) && options_p->flags[INITFULL];

	char rsync_and_prefer_excludes = options_p->flags[RSYNC] && !options_p->flags[RSYNC_PREFERINCLUDE];

	if((!options_p->flags[RSYNC_PREFERINCLUDE]) && skip_rules)
		return 0;

	tree = fts_open((char *const *)&rootpaths, FTS_NOCHDIR|FTS_PHYSICAL, NULL);

	if(tree == NULL) {
		printf_e("Error: Cannot fts_open() on \"%s\": %s (errno: %i).\n", dirpath, strerror(errno), errno);
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
				break;
			// Error cases:
			case FTS_ERR:
			case FTS_NS:
			case FTS_NSOK:
			case FTS_DNR:
			case FTS_DC:
				if(errno == ENOENT) {
					printf_d("Debug: Got error while fts_read(): %s (errno: %i; fts_info: %i).\n", strerror(errno), errno, node->fts_info);
					continue;
				} else {
					printf_e("Error: Got error while fts_read(): %s (errno: %i; fts_info: %i).\n", strerror(errno), errno, node->fts_info);
					ret = errno;
					goto l_sync_initialsync_walk_end;
				}
			default:

				printf_e("Error: Got unknown fts_info vlaue while fts_read(): %i.\n", node->fts_info);
				ret = EINVAL;
				goto l_sync_initialsync_walk_end;
		}
		path_rel = sync_path_abs2rel(options_p, node->fts_path, -1, &path_rel_len, path_rel);

		printf_ddd("Debug3: sync_initialsync_walk(): Pointing to \"%s\" (node->fts_info == %i)\n", path_rel, node->fts_info);

		if(!skip_rules) {
			ruleaction_t perm = rules_getperm(path_rel, node->fts_statp->st_mode, rules_p, RA_WALK|RA_MONITOR);

			if(!(perm&RA_WALK)) {
				printf_ddd("Debug3: sync_initialsync_walk(): Rejecting to walk into \"%s\".\n", path_rel);
				fts_set(tree, node, FTS_SKIP);
			}

			if(!(perm&RA_MONITOR)) {
				printf_ddd("Debug3: sync_initialsync_walk(): Excluding \"%s\".\n", path_rel);
				if(rsync_and_prefer_excludes) {
					if(queue_id == QUEUE_AUTO) {
						int i=0;
						while(i<QUEUE_MAX)
							indexes_addexclude(indexes_p, strdup(path_rel), i++);
					} else
						indexes_addexclude(indexes_p, strdup(path_rel), queue_id);
				}
				continue;
			}
		}

		evinfo.fsize = node->fts_statp->st_size;
		switch(options_p->notifyengine) {
#ifdef FANOTIFY_SUPPORT
			case NE_FANOTIFY:
				break;
#endif
			case NE_INOTIFY:
				evinfo.evmask = IN_CREATE_SELF;
				break;
		}

		if(!rsync_and_prefer_excludes) {
			printf_ddd("Debug2: sync_initialsync_walk(): queueing \"%s\" (depth: %i) with int-flags %p\n", node->fts_path, node->fts_level, (void *)(unsigned long)evinfo.flags);
			int _ret = sync_queuesync(path_rel, &evinfo, options_p, indexes_p, queue_id);

			if(_ret) {
				printf_e("Error: Got error while queueing \"%s\": %s (errno: %i).\n", node->fts_path, strerror(errno), errno);
				ret = errno;
				goto l_sync_initialsync_walk_end;
			}
		}
	}
	if(errno) {
		printf_e("Error: Got error while fts_read() and related routines: %s (errno: %i).\n", strerror(errno), errno);
		ret = errno;
		goto l_sync_initialsync_walk_end;
	}

	if(fts_close(tree)) {
		printf_e("Error: Got error while fts_close(): %s (errno: %i).\n", strerror(errno), errno);
		ret = errno;
		goto l_sync_initialsync_walk_end;
	}

l_sync_initialsync_walk_end:
	if(path_rel != NULL)
		free(path_rel);
	return ret;
}

int sync_initialsync(const char *path, options_t *options_p, indexes_t *indexes_p, initsync_t initsync) {
	printf_ddd("Debug3: sync_initialsync(\"%s\", options_p, indexes_p, %i)\n", path, initsync);

#ifdef CLUSTER_SUPPORT
	if(initsync == INITSYNC_FULL) {
		if(options_p->cluster_iface)
			return cluster_initialsync();
	}
#endif

	queue_id_t queue_id = (initsync==INITSYNC_FULL) ? QUEUE_INSTANT : QUEUE_NORMAL;

	// non-RSYNC case:
	if(!options_p->flags[RSYNC]) {
		printf_ddd("Debug3: sync_initialsync(): syncing \"%s\"\n", path);
/*
		if(options_p->flags[PTHREAD])
			return sync_exec_thread(options_p, NULL, options_p->handlerfpath, "initialsync", options_p->label, path, NULL);
		else
			return sync_exec       (options_p, NULL, options_p->handlerfpath, "initialsync", options_p->label, path, NULL);*/

		if(options_p->flags[ENABLEINITIALSYNC]) {
			if(options_p->flags[SYNCHANDLERSO]) {
				api_eventinfo_t *ei = (api_eventinfo_t *)xmalloc(sizeof(*ei));
#ifdef PARANIOD
				memset(ei, 0, sizeof(*ei));
#endif

				ei->evmask    = IN_CREATE|IN_ISDIR;
				ei->flags     = EVIF_RECURSIVELY;
				ei->path_len  = strlen(path);
				ei->path      = strdup(path);

				return so_call_sync(options_p, indexes_p, 1, ei);
			} else {
				return SYNC_EXEC(
						options_p,
						indexes_p,
						NULL,
						options_p->handlerfpath, 
						"initialsync",
						options_p->label,
						path,
						NULL
					);
			}
		}
#ifdef DOXYGEN
		sync_exec(NULL, NULL); sync_exec_thread(NULL, NULL);
#endif

		int ret = sync_initialsync_walk(options_p, path, indexes_p, queue_id, initsync);
		if(ret)
			printf_e("Error: sync_initialsync(): Cannot get synclist: %s (errno: %i)\n", strerror(ret), ret);

		return ret;
	}

	// RSYNC case:

	if(!options_p->flags[RSYNC_PREFERINCLUDE]) {
		queueinfo_t *queueinfo = &options_p->_queues[queue_id];

		if(!queueinfo->stime)
			queueinfo->stime = time(NULL); // Useful for debugging


		eventinfo_t *evinfo = (eventinfo_t *)xmalloc(sizeof(*evinfo));
		memset(evinfo, 0, sizeof(*evinfo));
		evinfo->flags |= EVIF_RECURSIVELY;

		// Searching for excludes
		int ret = sync_initialsync_walk(options_p, path, indexes_p, queue_id, initsync);
		if(ret) {
			printf_e("Error: sync_initialsync(): Cannot get exclude what to exclude: %s (errno: %i)\n", strerror(ret), ret);
			return ret;
		}

		printf_ddd("Debug3: sync_initialsync(): queueing \"%s\" with int-flags %p\n", path, (void *)(unsigned long)evinfo->flags);

		char *path_rel = sync_path_abs2rel(options_p, path, -1, NULL, NULL);

		return indexes_queueevent(indexes_p, path_rel, evinfo, queue_id);
	}

	// Searching for includes
	return sync_initialsync_walk(options_p, path, indexes_p, queue_id, initsync);
}

int sync_notify_mark(int notify_d, options_t *options_p, const char *accpath, const char *path, size_t pathlen, indexes_t *indexes_p) {
	printf_ddd("Debug3: sync_notify_mark(..., \"%s\", %i,...)\n", path, pathlen);
	int wd = indexes_fpath2wd(indexes_p, path);
	if(wd != -1) {
		printf_d("Debug: \"%s\" is already marked (wd: %i). Skipping.\n", path, wd);
		return wd;
	}

	switch(options_p->notifyengine) {
#ifdef FANOTIFY_SUPPORT
		case NE_FANOTIFY: {
			int fanotify_d = notify_d;

			if((wd = fanotify_mark(fanotify_d, FAN_MARK_ADD | FAN_MARK_DONT_FOLLOW,
				FANOTIFY_MARKMASK, AT_FDCWD, accpath)) == -1)
			{
				if(errno == ENOENT)
					return -2;

				printf_e("Error: Cannot fanotify_mark() on \"%s\": %s (errno: %i).\n", 
					path, strerror(errno), errno);
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

				printf_e("Error: Cannot inotify_add_watch() on \"%s\": %s (errno: %i).\n", 
					path, strerror(errno), errno);
				return -1;
			}
			break;
		}
		default: {
			printf_e("Error: unknown notify-engine: %i\n", options_p->notifyengine);
			errno = EINVAL;
			return -1;
		}
	}
	indexes_add_wd(indexes_p, wd, path, pathlen);

	return wd;
}

#ifdef CLUSTER_SUPPORT
static inline int sync_mark_walk_cluster_modtime_update(options_t *options_p, const char *path, short int dirlevel, mode_t st_mode) {
	if(options_p->cluster_iface) {
		int ret=cluster_modtime_update(path, dirlevel, st_mode);
		if(ret) printf_e("Error: sync_mark_walk() cannot cluster_modtime_update(): %s (errno %i)\n", strerror(ret), ret);
		return ret;
	}
	return 0;
}
#endif

int sync_mark_walk(int notify_d, options_t *options_p, const char *dirpath, indexes_t *indexes_p) {
	int ret = 0;
	const char *rootpaths[] = {dirpath, NULL};
	FTS *tree;
	rule_t *rules_p = options_p->rules;
	printf_dd("Debug2: sync_mark_walk(%i, options_p, \"%s\", indexes_p).\n", notify_d, dirpath);
	printf_funct my_printf_e = STATE_STARTING(state_p) ? printf_e : _printf_dd;

	tree = fts_open((char *const *)&rootpaths, FTS_NOCHDIR|FTS_PHYSICAL|FTS_NOSTAT, NULL);

	if(tree == NULL) {
		my_printf_e("Error: Cannot fts_open() on \"%s\": %s (errno: %i).\n", dirpath, strerror(errno), errno);
		return errno;
	}

	FTSENT *node;
	char  *path_rel		= NULL;
	size_t path_rel_len	= 0;

	while((node = fts_read(tree))) {
#ifdef CLUSTER_SUPPORT
		int ret;
#endif
		printf_dd("Debug3: walking: \"%s\" (depth %u): fts_info == %i\n", node->fts_path, node->fts_level, node->fts_info);

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
				if((ret=sync_mark_walk_cluster_modtime_update(options_p, node->fts_path, node->fts_level, S_IFREG)))
					goto l_sync_mark_walk_end;
#endif
				continue;
			// To mark:
			case FTS_D:
			case FTS_DOT:
#ifdef CLUSTER_SUPPORT
				if((ret=sync_mark_walk_cluster_modtime_update(options_p, node->fts_path, node->fts_level, S_IFDIR)))
					goto l_sync_mark_walk_end;
#endif
				break;
			// Error cases:
			case FTS_ERR:
			case FTS_NS:
			case FTS_DNR:
			case FTS_DC:
				if(errno == ENOENT) {
					printf_d("Debug: Got error while fts_read(): %s (errno: %i; fts_info: %i).\n", strerror(errno), errno, node->fts_info);
					continue;
				} else {
					my_printf_e("Error: Got error while fts_read(): %s (errno: %i; fts_info: %i).\n", strerror(errno), errno, node->fts_info);
					ret = errno;
					goto l_sync_mark_walk_end;
				}
			default:
				my_printf_e("Error: Got unknown fts_info vlaue while fts_read(): %i.\n", node->fts_info);
				ret = EINVAL;
				goto l_sync_mark_walk_end;
		}

		path_rel = sync_path_abs2rel(options_p, node->fts_path, -1, &path_rel_len, path_rel);
		ruleaction_t perm = rules_search_getperm(path_rel, S_IFDIR, rules_p, RA_WALK, NULL);

		if(!(perm&RA_WALK)) {
			fts_set(tree, node, FTS_SKIP);
			continue;
		}

		printf_dd("Debug2: marking \"%s\" (depth %u)\n", node->fts_path, node->fts_level);
		int wd = sync_notify_mark(notify_d, options_p, node->fts_accpath, node->fts_path, node->fts_pathlen, indexes_p);
		if(wd == -1) {
			my_printf_e("Error: Got error while notify-marking \"%s\": %s (errno: %i).\n", node->fts_path, strerror(errno), errno);
			ret = errno;
			goto l_sync_mark_walk_end;
		}
		printf_dd("Debug2: watching descriptor is %i.\n", wd);
	}
	if(errno) {
		my_printf_e("Error: Got error while fts_read() and related routines: %s (errno: %i).\n", strerror(errno), errno);
		ret = errno;
		goto l_sync_mark_walk_end;
	}

	if(fts_close(tree)) {
		my_printf_e("Error: Got error while fts_close(): %s (errno: %i).\n", strerror(errno), errno);
		ret = errno;
		goto l_sync_mark_walk_end;
	}

l_sync_mark_walk_end:
	if(path_rel != NULL)
		free(path_rel);
	return ret;
}

int sync_notify_init(options_t *options_p) {
	switch(options_p->notifyengine) {
#ifdef FANOTIFY_SUPPORT
		case NE_FANOTIFY: {
			int fanotify_d = fanotify_init(FANOTIFY_FLAGS, FANOTIFY_EVFLAGS);
			if(fanotify_d == -1) {
				printf_e("Error: cannot fanotify_init(%i, %i): %s (errno: %i).\n", FANOTIFY_FLAGS, FANOTIFY_EVFLAGS, strerror(errno), errno);
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
				printf_e("Error: cannot inotify_init(%i): %s (errno: %i).\n", INOTIFY_FLAGS, strerror(errno), errno);
				return -1;
			}

			return inotify_d;
		}
	}
	printf_e("Error: unknown notify-engine: %i\n", options_p->notifyengine);
	errno = EINVAL;
	return -1;
}

static inline int sync_dosync_exec(options_t *options_p, indexes_t *indexes_p, const char *evmask_str, const char *fpath) {
/*
	if(options_p->flags[PTHREAD])
		return sync_exec_thread(options_p, NULL, options_p->handlerfpath, "sync", options_p->label, evmask_str, fpath, NULL);
	else
		return sync_exec       (options_p, NULL, options_p->handlerfpath, "sync", options_p->label, evmask_str, fpath, NULL);*/
	return SYNC_EXEC(options_p, indexes_p, NULL, options_p->handlerfpath, "sync", options_p->label, evmask_str, fpath, NULL);

#ifdef DOXYGEN
	sync_exec(NULL, NULL); sync_exec_thread(NULL, NULL);
#endif

}

static int sync_dosync(const char *fpath, uint32_t evmask, options_t *options_p, indexes_t *indexes_p) {
	int ret;

#ifdef CLUSTER_SUPPORT
	ret = cluster_lock(fpath);
	if(ret) return ret;
#endif

	char *evmask_str = xmalloc(1<<8);
	sprintf(evmask_str, "%u", evmask);
	ret = sync_dosync_exec(options_p, indexes_p, evmask_str, fpath);
	free(evmask_str);

#ifdef CLUSTER_SUPPORT
	ret = cluster_unlock_all();
#endif

	return ret;
}

void _sync_idle_dosync_collectedexcludes(gpointer fpath_gp, gpointer dummy, gpointer arg_gp) {
	char *fpath		  = (char *)fpath_gp;
	indexes_t *indexes_p 	  = ((struct dosync_arg *)arg_gp)->indexes_p;

	printf_ddd("Debug3: _sync_idle_dosync_collectedexcludes(): \"%s\".\n", fpath);

	indexes_addexclude_aggr(indexes_p, strdup(fpath));

	return;
}

void _sync_idle_dosync_collectedevents(gpointer fpath_gp, gpointer evinfo_gp, gpointer arg_gp) {
	char *fpath		  = (char *)fpath_gp;
	eventinfo_t *evinfo	  = (eventinfo_t *)evinfo_gp;
	int *evcount_p		  =&((struct dosync_arg *)arg_gp)->evcount;
//	FILE *outf		  = ((struct dosync_arg *)arg_gp)->outf;
	options_t *options_p 	  = ((struct dosync_arg *)arg_gp)->options_p;
	indexes_t *indexes_p 	  = ((struct dosync_arg *)arg_gp)->indexes_p;
	queue_id_t queue_id	  = (queue_id_t)((struct dosync_arg *)arg_gp)->data;

	printf_ddd("Debug3: _sync_idle_dosync_collectedevents(): queue_id == %i.\n", queue_id);

	if((options_p->listoutdir == NULL) && (!options_p->flags[SYNCHANDLERSO])) {
		printf_ddd("Debug3: _sync_idle_dosync_collectedevents(): calling sync_dosync()\n");
		int ret;
		if((ret=sync_dosync(fpath, evinfo->evmask, options_p, indexes_p))) {
			printf_e("Error: unable to sync \"%s\" (evmask %i): %s (errno: %i).\n", fpath, evinfo->evmask, strerror(ret), ret);
			exit(ret);	// TODO: remove this from here
		}
	}

	int isnew = 0;
	eventinfo_t *evinfo_idx = indexes_fpath2ei(indexes_p, fpath);

	int _queue_id = 0;
	while(_queue_id < QUEUE_MAX) {
		if(_queue_id == queue_id) {
			_queue_id++;
			continue;
		}
		indexes_removefromqueue(indexes_p, fpath, _queue_id);
		if(!g_hash_table_size(indexes_p->fpath2ei_coll_ht[_queue_id]))
			options_p->_queues[_queue_id].stime = 0;
		_queue_id++;
	}

	if(evinfo_idx == NULL) {
		evinfo_idx = (eventinfo_t *)xmalloc(sizeof(*evinfo_idx));
		memset(evinfo_idx, 0, sizeof(*evinfo_idx));
		isnew++;
		(*evcount_p)++;
	}
	evinfo_idx->evmask |= evinfo->evmask;
	evinfo_idx->flags  |= evinfo->flags;

	if(isnew)
		indexes_fpath2ei_add(indexes_p, strdup(fpath), evinfo_idx);
	else
		free(fpath);

	return;
}

int sync_idle_dosync_collectedevents_cleanup(options_t *options_p, char **argv) {
	if(options_p->flags[DONTUNLINK]) 
		return 0;

	printf_ddd("Debug3: sync_idle_dosync_collectedevents_cleanup(): thread %p\n", pthread_self());

	if(options_p->flags[RSYNC] >= 2) {
		int ret0, ret1;
		if(argv[5] == NULL) {
			printf_e("Error: Unexpected *argv[] end.");
			return EINVAL;
		}

		printf_ddd("Debug3: unlink()-ing \"%s\"\n", argv[5]);
		ret0 = unlink(argv[5]);

		if(options_p->flags[RSYNC_PREFERINCLUDE])
			return ret0;

		if(argv[7] == NULL) {
			printf_e("Error: Unexpected *argv[] end.");
			return EINVAL;
		}

		printf_ddd("Debug3: unlink()-ing \"%s\"\n", argv[7]);
		ret1 = unlink(argv[7]);

		return ret0 == 0 ? ret1 : ret0;
	}

	if(argv[3] == NULL) {
		printf_e("Error: Unexpected *argv[] end.");
		return EINVAL;
	}

	int ret0;
	printf_ddd("Debug3: unlink()-ing \"%s\"\n", argv[3]);
	ret0 = unlink(argv[3]);

	if(options_p->flags[RSYNC]) {
		int ret1;

		// There's no exclude file-list if "--rsyncpreferinclude" is enabled, so return
		if(options_p->flags[RSYNC_PREFERINCLUDE])
			return ret0;

		if(argv[4] == NULL) 
			return ret0;

		if(*argv[4] == 0x00)
			return ret0;

		printf_ddd("Debug3: unlink()-ing \"%s\"\n", argv[4]);
		ret1 = unlink(argv[4]);	// remove exclude list, too

		return ret0 == 0 ? ret1 : ret0;
	}

	return ret0;
}

int sync_idle_dosync_collectedevents_aggrqueue(queue_id_t queue_id, options_t *options_p, indexes_t *indexes_p, struct dosync_arg *dosync_arg) {
//	char *buf, *fpath;
	time_t tm = time(NULL);

	queueinfo_t *queueinfo = &options_p->_queues[queue_id];

	if((queueinfo->stime + queueinfo->collectdelay > tm) && (queueinfo->collectdelay != COLLECTDELAY_INSTANT)) {
		printf_ddd("Debug3: sync_idle_dosync_collectedevents_procqueue(%i, ...): too early (%i + %i > %i).\n", queue_id, queueinfo->stime, queueinfo->collectdelay, tm);
		return 0;
	}
	queueinfo->stime = 0;

	int evcount_real = g_hash_table_size(indexes_p->fpath2ei_coll_ht[queue_id]);

	printf_ddd("Debug3: sync_idle_dosync_collectedevents_procqueue(%i, ...): evcount_real == %i\n", queue_id, evcount_real);

	if(evcount_real<=0) {
		printf_ddd("Debug3: sync_idle_dosync_collectedevents_procqueue(%i, ...): no events, return 0.\n", queue_id);
		return 0;
	}

	g_hash_table_foreach(indexes_p->fpath2ei_coll_ht[queue_id], _sync_idle_dosync_collectedevents, dosync_arg);
	g_hash_table_remove_all(indexes_p->fpath2ei_coll_ht[queue_id]);

	if(!options_p->flags[RSYNC_PREFERINCLUDE]) {
		g_hash_table_foreach(indexes_p->exc_fpath_coll_ht[queue_id], _sync_idle_dosync_collectedexcludes, dosync_arg);
		g_hash_table_remove_all(indexes_p->exc_fpath_coll_ht[queue_id]);
	}

	return 0;
}

int sync_idle_dosync_collectedevents_uniqfname(options_t *options_p, char *fpath, char *name) {
	pid_t pid = getpid();
	time_t tm = time(NULL);
	struct stat64 stat64;

	int counter = 0;
	do {
		snprintf(fpath, PATH_MAX, "%s/.clsync-%s.%u.%lu.%lu.%u", options_p->listoutdir, name, pid, (long)pthread_self(), (unsigned long)tm, rand());	// To be unique
		lstat64(fpath, &stat64);
		if(counter++ > COUNTER_LIMIT) {
			printf_e("Error: Cannot file unused filename for list-file. The last try was \"%s\".\n", fpath);
			return ELOOP;
		}
	} while(errno != ENOENT);	// TODO: find another way to check if the object exists
	errno=0;

	return 0;
}

int sync_idle_dosync_collectedevents_listcreate(struct dosync_arg *dosync_arg_p, char *name) {
	printf_ddd("Debug3: Creating %s file\n", name);
	char *fpath = dosync_arg_p->outf_path;
	options_t *options_p = dosync_arg_p->options_p;

	int ret;
	if((ret=sync_idle_dosync_collectedevents_uniqfname(options_p, fpath, name))) {
		printf_e("Error: sync_idle_dosync_collectedevents_listcreate: Cannot get unique file name.\n");
		return ret;
	}

	dosync_arg_p->outf = fopen(fpath, "w");

	if(dosync_arg_p->outf == NULL) {
		printf_e("Error: Cannot open \"%s\" as file for writing: %s (errno: %i).\n", fpath, strerror(errno), errno);
		return errno;
	}

	setbuffer(dosync_arg_p->outf, dosync_arg_p->buf, BUFSIZ);
	printf_ddd("Debug3: Created list-file \"%s\"\n", fpath);
	dosync_arg_p->linescount = 0;

	return 0;
}

gboolean sync_idle_dosync_collectedevents_aggrout(gpointer outline_gp, gpointer evinfo_gp, gpointer arg_gp) {
	struct dosync_arg *dosync_arg_p = (struct dosync_arg *)arg_gp;
	char *outline		  = (char *)outline_gp;
	FILE *outf		  = dosync_arg_p->outf;
//	options_t *options_p 	  = dosync_arg_p->options_p;
//	indexes_t *indexes_p	  = dosync_arg_p->indexes_p;
	printf_ddd("Debug3: sync_idle_dosync_collectedevents_aggrout(): \"%s\"\n", outline);

	fprintf(outf, "%s\n", outline);

	return TRUE;
}

gboolean sync_idle_dosync_collectedevents_rsync_exclistpush(gpointer fpath_gp, gpointer evinfo_gp, gpointer arg_gp) {
	struct dosync_arg *dosync_arg_p = (struct dosync_arg *)arg_gp;
	char *fpath		  = (char *)fpath_gp;
	FILE *excf		  = dosync_arg_p->outf;
//	options_t *options_p 	  = dosync_arg_p->options_p;
//	indexes_t *indexes_p	  = dosync_arg_p->indexes_p;
	printf_ddd("Debug3: sync_idle_dosync_collectedevents_rsync_exclistpush(): \"%s\"\n", fpath);

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

	printf_ddd("Debug3: Adding to exclude-file: \"%s\"\n", fpathwslash);
	fprintf(excf, "%s\n", fpathwslash);

	return TRUE;
}

int sync_idle_dosync_collectedevents_commitpart(struct dosync_arg *dosync_arg_p) {
	options_t *options_p = dosync_arg_p->options_p;
	indexes_t *indexes_p = dosync_arg_p->indexes_p;

	printf_ddd("Debug3: Committing the file (flags[RSYNC] == %i; flags[SYNCHANDLERSO] == %i)\n", options_p->flags[RSYNC], options_p->flags[SYNCHANDLERSO]);

	if(!options_p->flags[SYNCHANDLERSO]) {
		fclose(dosync_arg_p->outf);
		dosync_arg_p->outf = NULL;
	}

	if(dosync_arg_p->evcount > 0) {
/*
		if(options_p->flags[PTHREAD])
			return sync_exec_thread(options_p,
						sync_idle_dosync_collectedevents_cleanup,
						options_p->handlerfpath,
						options_p->flags[RSYNC]?"rsynclist":"synclist",
						options_p->label,
						dosync_arg_p->outf_path,
						*(dosync_arg_p->outf_path)?dosync_arg_p->outf_path:NULL,
						NULL);
		else
			return sync_exec       (options_p,
						sync_idle_dosync_collectedevents_cleanup,
						options_p->handlerfpath,
						options_p->flags[RSYNC]?"rsynclist":"synclist", 
						options_p->label,
						dosync_arg_p->outf_path,
						*(dosync_arg_p->outf_path)?dosync_arg_p->outf_path:NULL,
						NULL);*/
		printf_ddd("Debug3: %s [%s] (%p) -> %s [%s]\n", options_p->watchdir, options_p->watchdirwslash, options_p->watchdirwslash, 
								options_p->destdir?options_p->destdir:"", options_p->destdirwslash?options_p->destdirwslash:"");

		if(options_p->flags[SYNCHANDLERSO]) {
			api_eventinfo_t *ei = dosync_arg_p->api_ei;
			return so_call_sync(options_p, indexes_p, dosync_arg_p->evcount, ei);
		}

		if(options_p->flags[RSYNC] >= 2)
			return SYNC_EXEC(options_p, indexes_p,
				sync_idle_dosync_collectedevents_cleanup,
				options_p->handlerfpath,
				"--inplace",
				"-aH", 
				"--delete-before",
				*(dosync_arg_p->excf_path) ? "--exclude-from"		: "--include-from",
				*(dosync_arg_p->excf_path) ? dosync_arg_p->excf_path	: dosync_arg_p->outf_path,
				*(dosync_arg_p->excf_path) ? "--include-from"		: "--exclude=*",
				*(dosync_arg_p->excf_path) ? dosync_arg_p->outf_path	: options_p->watchdirwslash,
				*(dosync_arg_p->excf_path) ? "--exclude=*"		: options_p->destdirwslash,
				*(dosync_arg_p->excf_path) ? options_p->watchdirwslash	: NULL,
				*(dosync_arg_p->excf_path) ? options_p->destdirwslash	: NULL,
				NULL);

		return SYNC_EXEC(options_p, indexes_p,
			sync_idle_dosync_collectedevents_cleanup,
			options_p->handlerfpath,
			options_p->flags[RSYNC]?"rsynclist":"synclist", 
			options_p->label,
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
	options_t *options_p 	   =  dosync_arg_p->options_p;
	int *linescount_p	   = &dosync_arg_p->linescount;
	indexes_t *indexes_p 	   =  dosync_arg_p->indexes_p;
	api_eventinfo_t **api_ei_p = &dosync_arg_p->api_ei;
	int *api_ei_count_p 	   = &dosync_arg_p->api_ei_count;
	printf_ddd("Debug3: sync_idle_dosync_collectedevents_listpush(): \"%s\" with int-flags %p\n", fpath, (void *)(unsigned long)evinfo->flags);

	// so-module case:
	if(options_p->flags[SYNCHANDLERSO]) {
		api_eventinfo_t *ei = &(*api_ei_p)[(*api_ei_count_p)++];
		ei->evmask   = evinfo->evmask;
		ei->flags    = evinfo->flags;
		ei->path_len = strlen(fpath);
		ei->path     = strdup(fpath);
		return;
	}

	if(!options_p->flags[RSYNC]) {
		// non-RSYNC case
		if(options_p->flags[SYNCLISTSIMPLIFY])
			fprintf(outf, "%s\n", fpath);
		else 
			fprintf(outf, "sync %s %i %s\n", options_p->label, evinfo->evmask, fpath);
		return;
	}

	// RSYNC case
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

	if(options_p->rsyncinclimit && (*linescount_p >= options_p->rsyncinclimit)) {
		int ret;

		// TODO: optimize this out {
		char newexc_path[PATH_MAX+1];
		if((ret=sync_idle_dosync_collectedevents_uniqfname(options_p, newexc_path, "exclist"))) {
			printf_e("Error: sync_idle_dosync_collectedevents_listcreate: Cannot get unique file name.\n");
			exit(ret);
		}
		if((ret=fileutils_copy(dosync_arg_p->excf_path, newexc_path))) {
			printf_e("Error: sync_idle_dosync_collectedevents_listcreate: Cannot copy file \"%s\" to \"%s\".\n", dosync_arg_p->excf_path, newexc_path);
			exit(ret);
		}
		// }
		// That's required to copy excludes' list file for every rsync execution.
		// The problem appears do to unlink()-ing the excludes' list file on callback function 
		// "sync_idle_dosync_collectedevents_cleanup()" of every execution.

		if((ret=sync_idle_dosync_collectedevents_commitpart(dosync_arg_p))) {
			printf_e("Error: sync_idle_dosync_collectedevents_listpush(): Cannot commit list-file \"%s\": %s (errno: %i)\n", dosync_arg_p->outf_path, strerror(ret), ret);
			exit(ret);	// TODO: replace with kill(0, ...);
		}

		strcpy(dosync_arg_p->excf_path, newexc_path);		// TODO: optimize this out

		if((ret=sync_idle_dosync_collectedevents_listcreate(dosync_arg_p, "list"))) {
			printf_e("Error: sync_idle_dosync_collectedevents_listpush(): Cannot create new list-file: %s (errno: %i)\n", strerror(ret), ret);
			exit(ret);	// TODO: replace with kill(0, ...);
		}
		outf = dosync_arg_p->outf;
	}

	char *end=fpathwslash;

	if(evinfo->flags & EVIF_RECURSIVELY) {
		printf_ddd("Debug3: sync_idle_dosync_collectedevents_listpush(): Recursively \"%s\": Adding to rsynclist: \"%s/***\".\n", fpathwslash, fpathwslash);
		fprintf(outf, "%s/***\n", fpathwslash);
		(*linescount_p)++;
	}


	while(end != NULL) {
		if(*fpathwslash == 0x00)
			break;
		printf_ddd("Debug3: sync_idle_dosync_collectedevents_listpush(): Non-recursively \"%s\": Adding to rsynclist: \"%s\".\n", fpathwslash, fpathwslash);
		indexes_outaggr_add(indexes_p, strdup(fpathwslash));
		(*linescount_p)++;
		end = strrchr(fpathwslash, '/');
		if(end == NULL)
			break;
		if(end - fpathwslash <= 0)
			break;

		*end = 0x00;
	};

	return;
}



int sync_idle_dosync_collectedevents(options_t *options_p, indexes_t *indexes_p) {
	printf_ddd("Debug3: sync_idle_dosync_collectedevents()\n");
	struct dosync_arg dosync_arg = {0};

	dosync_arg.options_p 	= options_p;
	dosync_arg.indexes_p	= indexes_p;

	char isrsyncpreferexclude = options_p->flags[RSYNC] && (!options_p->flags[RSYNC_PREFERINCLUDE]);

#ifdef PARANOID
	if(options_p->listoutdir != NULL) {
		g_hash_table_remove_all(indexes_p->fpath2ei_ht);
		if(isrsyncpreferexclude)
			g_hash_table_remove_all(indexes_p->exc_fpath_ht);
	}
#endif

	// Setting the time to sync not before it:
	options_p->synctime = time(NULL) + options_p->syncdelay;
	printf_ddd("Debug3: Next sync will be not before: %u\n", options_p->synctime);

	int queue_id=0;
	while(queue_id < QUEUE_MAX) {
		int ret;
		queue_id_t *queue_id_p = (queue_id_t *)&dosync_arg.data;
		*queue_id_p = queue_id;
		ret = sync_idle_dosync_collectedevents_aggrqueue(queue_id, options_p, indexes_p, &dosync_arg);
		if(ret) {
			printf_e("Error: Got error while processing queue #%i\n: %s (errno: %i).\n", queue_id, strerror(ret), ret);
			g_hash_table_remove_all(indexes_p->fpath2ei_ht);
			if(isrsyncpreferexclude)
				g_hash_table_remove_all(indexes_p->exc_fpath_ht);
			return ret;
		}

		queue_id++;
	}

	if(!dosync_arg.evcount) {
		printf_ddd("Debug3: sync_idle_dosync_collectedevents(): Summary events' count is zero. Return 0.\n");
		return 0;
	}


	if(options_p->flags[SYNCHANDLERSO]) {
		//dosync_arg.evcount = g_hash_table_size(indexes_p->fpath2ei_ht);
		printf_ddd("Debug3: sync_idle_dosync_collectedevents(): There's %i events. Processing.\n", dosync_arg.evcount);
		dosync_arg.api_ei = (api_eventinfo_t *)xmalloc(dosync_arg.evcount * sizeof(*dosync_arg.api_ei));
	}

	if((options_p->listoutdir != NULL) || (options_p->flags[SYNCHANDLERSO])) {
		int ret;

		if(!options_p->flags[SYNCHANDLERSO]) {
			*(dosync_arg.excf_path) = 0x00;
			if(isrsyncpreferexclude) {
				if((ret=sync_idle_dosync_collectedevents_listcreate(&dosync_arg, "exclist"))) {
					printf_e("Error: Cannot create list-file: %s (errno: %i)\n", strerror(ret), ret);
					return ret;
				}

#ifdef PARANOID
				g_hash_table_remove_all(indexes_p->out_lines_aggr_ht);
#endif
				g_hash_table_foreach_remove(indexes_p->exc_fpath_ht, sync_idle_dosync_collectedevents_rsync_exclistpush, &dosync_arg);
				g_hash_table_foreach_remove(indexes_p->out_lines_aggr_ht, sync_idle_dosync_collectedevents_aggrout, &dosync_arg);
				fclose(dosync_arg.outf);
				strcpy(dosync_arg.excf_path, dosync_arg.outf_path);	// TODO: remove this strcpy()
			}

			if((ret=sync_idle_dosync_collectedevents_listcreate(&dosync_arg, "list"))) {
				printf_e("Error: Cannot create list-file: %s (errno: %i)\n", strerror(ret), ret);
				return ret;
			}
		}

#ifdef PARANOID
		g_hash_table_remove_all(indexes_p->out_lines_aggr_ht);
#endif

		g_hash_table_foreach(indexes_p->fpath2ei_ht, sync_idle_dosync_collectedevents_listpush, &dosync_arg);
		if(options_p->flags[RSYNC])
			g_hash_table_foreach_remove(indexes_p->out_lines_aggr_ht, sync_idle_dosync_collectedevents_aggrout, &dosync_arg);

		if((ret=sync_idle_dosync_collectedevents_commitpart(&dosync_arg))) {
			printf_e("Error: Cannot submit to sync the list \"%s\": %s (errno: %i)\n", dosync_arg.outf_path, strerror(ret), ret);
			// TODO: free dosync_arg.api_ei on case of error
			g_hash_table_remove_all(indexes_p->fpath2ei_ht);
			return ret;
		}

		g_hash_table_remove_all(indexes_p->fpath2ei_ht);
	}

	return 0;
}

int sync_idle(int notify_d, options_t *options_p, indexes_t *indexes_p) {
	int ret=thread_gc(options_p);
	if(ret) return ret;

	printf_ddd("Debug3: sync_idle(): calling sync_idle_dosync_collectedevents()\n");

#ifdef CLUSTER_SUPPORT
	ret = cluster_lock_byindexes();
	if(ret) return ret;
#endif

	ret = sync_idle_dosync_collectedevents(options_p, indexes_p);
	if(ret) return ret;

#ifdef CLUSTER_SUPPORT
	ret = cluster_unlock_all();
	if(ret) return ret;
#endif

	return 0;
}

#ifdef FANOTIFY_SUPPORT
int sync_fanotify_loop(int fanotify_d, options_t *options_p, indexes_t *indexes_p) {
	struct fanotify_event_metadata buf[BUFSIZ/sizeof(struct fanotify_event_metadata) + 1];
	int state = STATE_RUNNING;
	state_p = &state;

	while(state != STATE_EXIT) {
		struct fanotify_event_metadata *metadata;
		size_t len = read(fanotify_d, (void *)buf, sizeof(buf)-sizeof(*buf));
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
					sync_queuesync(fpath_rel, 0, options_p, indexes_p, QUEUE_AUTO);
					printf_dd("Debug2: Event %i on \"%s\".\n", metadata->mask, fpath);
					free(fpath);
				}
			}
			close(metadata->fd);
			metadata = FAN_EVENT_NEXT(metadata, len);
		}
		int ret;
		if((ret=sync_idle(fanotify_d, options_p, indexes_p))) {
			printf_e("Error: got error while sync_idle(): %s (errno: %i).\n", strerror(ret), ret);
			return ret;
		}
	}
	return 0;
}
#endif

int sync_inotify_wait(int inotify_d, options_t *options_p, indexes_t *indexes_p) {
	static struct timeval tv;
	time_t tm = time(NULL);
	long delay = ((unsigned long)~0 >> 1);
	threadsinfo_t *threadsinfo_p = thread_getinfo();

	pthread_cond_broadcast(&threadsinfo_p->cond[PTHREAD_MUTEX_STATE]);
	pthread_mutex_unlock(&threadsinfo_p->mutex[PTHREAD_MUTEX_STATE]);

	printf_ddd("Debug3: sync_inotify_wait()\n");

	fd_set rfds;
	FD_ZERO(&rfds);
	FD_SET(inotify_d, &rfds);

	long queue_id = 0;
	while(queue_id < QUEUE_MAX) {
		queueinfo_t *queueinfo = &options_p->_queues[queue_id++];

		if(!queueinfo->stime)
			continue;

		if(queueinfo->collectdelay == COLLECTDELAY_INSTANT) {
			printf_ddd("Debug3: sync_inotify_wait(): There're events in instant queue (#%i), don't waiting.\n", queue_id-1);
			return 0;
		}

		int qdelay = queueinfo->stime + queueinfo->collectdelay - tm;
		printf_ddd("Debug3: sync_inotify_wait(): queue #%i: %i %i %i -> %i\n", queue_id-1, queueinfo->stime, queueinfo->collectdelay, tm, qdelay);
		if(qdelay < -(long)options_p->syncdelay)
			qdelay = -(long)options_p->syncdelay;

		delay = MIN(delay, qdelay);
	}

	long synctime_delay = ((long)options_p->synctime) - ((long)tm);
	synctime_delay = synctime_delay > 0 ? synctime_delay : 0;

	printf_ddd("Debug3: delay = MAX(%li, %li)\n", delay, synctime_delay);
	delay = MAX(delay, synctime_delay);
	delay = delay > 0 ? delay : 0;

	if(options_p->flags[PTHREAD]) {
		time_t _thread_nextexpiretime = thread_nextexpiretime();
		printf_ddd("Debug3: thread_nextexpiretime == %i\n", _thread_nextexpiretime);
		if(_thread_nextexpiretime) {
			long thread_expiredelay = (long)thread_nextexpiretime() - (long)tm + 1; // +1 is to make "tm>threadinfo_p->expiretime" after select() definitely TRUE
			printf_ddd("Debug3: thread_expiredelay == %i\n", thread_expiredelay);
			thread_expiredelay = thread_expiredelay > 0 ? thread_expiredelay : 0;
			printf_ddd("Debug3: delay = MIN(%li, %li)\n", delay, thread_expiredelay);
			delay = MIN(delay, thread_expiredelay);
		}
	}

	if((!delay) || (*state_p != STATE_RUNNING))
		return 0;

	printf_ddd("Debug3: sync_inotify_wait(): sleeping for %li second(s).\n", SLEEP_SECONDS);
	sleep(SLEEP_SECONDS);
	delay = ((long)delay)>SLEEP_SECONDS ? delay-SLEEP_SECONDS : 0;

	tv.tv_sec  = delay;
	tv.tv_usec = 0;

	pthread_mutex_lock(&threadsinfo_p->mutex[PTHREAD_MUTEX_STATE]);

	if(*state_p != STATE_RUNNING)
		return 0;

	printf_ddd("Debug3: sync_inotify_wait(): select with timeout %li secs.\n", tv.tv_sec);
	int ret = select(inotify_d+1, &rfds, NULL, NULL, &tv);

	if((ret == -1) && (errno == EINTR)) {
		errno = 0;
		return 0;
	}

	return ret;
}

void sync_inotify_handle_dosync(gpointer fpath_gp, gpointer evinfo_gp, gpointer arg_gp) {
	char *fpath_rel		  = (char *)fpath_gp;
	eventinfo_t *evinfo	  = (eventinfo_t *)evinfo_gp;
	options_t *options_p 	  = ((struct dosync_arg *)arg_gp)->options_p;
	indexes_t *indexes_p 	  = ((struct dosync_arg *)arg_gp)->indexes_p;

	sync_queuesync(fpath_rel, evinfo, options_p, indexes_p, QUEUE_AUTO);

	return;
}

#define SYNC_INOTIFY_HANDLE_CONTINUE {\
	ptr += sizeof(struct inotify_event) + event->len;\
	count++;\
	continue;\
}

int sync_inotify_handle(int inotify_d, options_t *options_p, indexes_t *indexes_p) {
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
			printf_e("Error: Got error while reading events from inotify with read(): %s (errno: %i).\n", strerror(errno), errno);
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
				printf_dd("Debug2: Cleaning up info about watch descriptor %i.\n", event->wd);
				indexes_remove_bywd(indexes_p, event->wd);
				SYNC_INOTIFY_HANDLE_CONTINUE;
			}

			// Getting path

			char *fpath = indexes_wd2fpath(indexes_p, event->wd);

			if(fpath == NULL) {
				printf_dd("Debug2: Event %p on stale watch (wd: %i).\n", (void *)(long)event->mask, event->wd);
				SYNC_INOTIFY_HANDLE_CONTINUE;
			}
			printf_dd("Debug2: Event %p on \"%s\" (wd: %i; fpath: \"%s\").\n", (void *)(long)event->mask, event->len>0?event->name:"", event->wd, fpath);

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
				printf_dd("Debug2: Cannot lstat(\"%s\", lstat): %s (errno: %i). Seems, that the object disappeared.\n", path_full, strerror(errno), errno);
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

			path_rel = sync_path_abs2rel(options_p, path_full, -1, &path_rel_len, path_rel);
			ruleaction_t perm = rules_getperm(path_rel, st_mode, options_p->rules, RA_WALK|RA_MONITOR);

			if(!(perm&(RA_MONITOR|RA_WALK))) {
				SYNC_INOTIFY_HANDLE_CONTINUE;
			}

			// Handling different cases

			if(event->mask & IN_ISDIR) {
				if(event->mask & (IN_CREATE|IN_MOVED_TO)) {			// Appeared
					// If new dir is created

					int ret;

					if(perm & RA_WALK) {
						ret = sync_mark_walk(inotify_d, options_p, path_full, indexes_p);
						if(ret) {
							printf_d("Debug: Seems, that directory \"%s\" disappeared, while trying to mark it.\n", path_full);
							SYNC_INOTIFY_HANDLE_CONTINUE;
						}

						ret = sync_initialsync(path_full, options_p, indexes_p, INITSYNC_SUBDIR);
						if(ret) {
							printf_e("Error: Got error from sync_initialsync(): %s (errno %i)\n", strerror(ret), ret);
							errno = ret;
							count=-1;
							goto l_sync_inotify_handle_end;
						}
					}

					SYNC_INOTIFY_HANDLE_CONTINUE;
				} else 
				if(event->mask & (IN_DELETE|IN_MOVED_FROM)) {	// Disappered
					printf_dd("Debug2: Disappeared \"%s\".\n", path_full);
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
				evinfo->fsize  = st_size;
				evinfo->wd     = event->wd;
				isnew++;
				printf_ddd("Debug3: sync_inotify_handle(): new event: fsize == %i; wd == %i\n", evinfo->fsize, evinfo->wd);
			}
			evinfo->evmask |= event->mask;

			if(isnew)
				indexes_fpath2ei_add(indexes_p, strdup(path_rel), evinfo);

			SYNC_INOTIFY_HANDLE_CONTINUE;
		}

		// Globally queueing captured events

		struct dosync_arg dosync_arg;
		dosync_arg.options_p 	= options_p;
		dosync_arg.indexes_p	= indexes_p;

		printf_ddd("Debug3: sync_inotify_handle(): collected %i events per this time.\n", g_hash_table_size(indexes_p->fpath2ei_ht));

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
	if((ret=sync_idle(inotify_d, options_p, indexes_p))) {\
		printf_e("Error: got error while sync_idle(): %s (errno: %i).\n", strerror(ret), ret);\
		return ret;\
	}\
}

#define SYNC_INOTIFY_LOOP_CONTINUE_UNLOCK {\
	pthread_cond_broadcast(&threadsinfo_p->cond[PTHREAD_MUTEX_STATE]);\
	pthread_mutex_unlock(&threadsinfo_p->mutex[PTHREAD_MUTEX_STATE]);\
	continue;\
}

int sync_inotify_loop(int inotify_d, options_t *options_p, indexes_t *indexes_p) {
	int state = STATE_INITSYNC;
	int ret;
	state_p = &state;

	while(state != STATE_EXIT) {
		int events;

		threadsinfo_t *threadsinfo_p = thread_getinfo();
		pthread_mutex_lock(&threadsinfo_p->mutex[PTHREAD_MUTEX_STATE]);
		printf_ddd("Debug3: sync_inotify_loop(): current state is %i\n", state);
		events = 0;
		switch(state) {
			case STATE_PTHREAD_GC:
				if(thread_gc(options_p)) {
					state=STATE_EXIT;
					break;
				}
				state = STATE_RUNNING;
				SYNC_INOTIFY_LOOP_CONTINUE_UNLOCK;
			case STATE_INITSYNC:
				pthread_cond_broadcast(&threadsinfo_p->cond[PTHREAD_MUTEX_STATE]);
				pthread_mutex_unlock(&threadsinfo_p->mutex[PTHREAD_MUTEX_STATE]);
				ret = sync_initialsync(options_p->watchdir, options_p, indexes_p, INITSYNC_FULL);
				if(ret) return ret;
				state = STATE_RUNNING;
				continue;
			case STATE_RUNNING:
				events = sync_inotify_wait(inotify_d, options_p, indexes_p); 
				if(state != STATE_RUNNING)
					SYNC_INOTIFY_LOOP_CONTINUE_UNLOCK;
				break;
			case STATE_REHASH:
				printf_d("Debug: sync_inotify_loop(): rehashing.\n");
				main_rehash(options_p);
				state = STATE_RUNNING;
				SYNC_INOTIFY_LOOP_CONTINUE_UNLOCK;
			case STATE_TERM:
				state = STATE_EXIT;
			case STATE_EXIT:
				SYNC_INOTIFY_LOOP_CONTINUE_UNLOCK;
		}
		pthread_cond_broadcast(&threadsinfo_p->cond[PTHREAD_MUTEX_STATE]);
		pthread_mutex_unlock(&threadsinfo_p->mutex[PTHREAD_MUTEX_STATE]);

		if(events == 0) {
			printf_dd("Debug2: sync_inotify_wait(%i, options_p, indexes_p) timed-out.\n", inotify_d);
			SYNC_INOTIFY_LOOP_IDLE;
			continue;	// Timeout
		}
		if(events  < 0) {
			printf_e("Error: Got error while waiting for event from inotify with select(): %s (errno: %i).\n", strerror(errno), errno);
			return errno;
		}

		int count=sync_inotify_handle(inotify_d, options_p, indexes_p);
		if(count  <= 0) {
			printf_e("Error: Cannot handle with inotify events: %s (errno: %i).\n", strerror(errno), errno);
			return errno;
		}
//		SYNC_INOTIFY_LOOP_IDLE;

	}

	SYNC_INOTIFY_LOOP_IDLE;
	return exitcode;

#ifdef DOXYGEN
	sync_idle(0, NULL, NULL);
#endif
}

int sync_notify_loop(int notify_d, options_t *options_p, indexes_t *indexes_p) {
	switch(options_p->notifyengine) {
#ifdef FANOTIFY_SUPPORT
		case NE_FANOTIFY:
			return sync_fanotify_loop(notify_d, options_p, indexes_p);
#endif
		case NE_INOTIFY:
			return sync_inotify_loop (notify_d, options_p, indexes_p);
	}
	printf_e("Error: unknown notify-engine: %i\n", options_p->notifyengine);
	errno = EINVAL;
	return -1;
}

void sync_sig_int(int signal) {
	printf_dd("Debug2: sync_sig_int(%i): Thread %p\n", signal, pthread_self());
	return;
}

int sync_switch_state(pthread_t pthread_parent, int newstate) {
	if(state_p == NULL) {
		printf_ddd("Debug3: sync_switch_state(%p, %i), but state_p == NULL\n", pthread_parent, newstate);
		return 0;
	}

	printf_ddd("Debug3: sync_switch_state(%p, %i)\n", pthread_parent, newstate);

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

			printf_ddd("Debug3: sync_switch_state(): pthread_cond_timedwait() until %li.%li\n", time_timeout.tv_sec, time_timeout.tv_nsec);
			if(pthread_cond_timedwait(pthread_cond_state, pthread_mutex_state, &time_timeout) != ETIMEDOUT)
				break;
			printf_ddd("Debug3: sending signal to interrupt blocking operations like select()-s and so on\n");
			pthread_kill(pthread_parent, SIGUSR_BLOPINT);
#ifdef VERYPARANOID
			int i=0;
			if(++i > KILL_TIMEOUT) {
				printf_e("Error: sync_switch_state(): Seems we got a deadlock.");
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
	printf_ddd("Debug3: sync_switch_state(): pthread_mutex_unlock(). New state is %i.\n", *state_p);

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
//	options_t *options_p     = sighandler_arg_p->options_p;
//	indexes_t *indexes_p     = sighandler_arg_p->indexes_p;
	pthread_t pthread_parent = sighandler_arg_p->pthread_parent;
	sigset_t *sigset_p	 = sighandler_arg_p->sigset_p;
	int *exitcode_p		 = sighandler_arg_p->exitcode_p;

	sync_sighandler_exitcode_p = exitcode_p;

	while(1) {
		printf_ddd("Debug3: sync_sighandler(): waiting for signal\n");
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
					printf_e("Warning: Got signal %i, but the main loop is not started, yet. Ignoring the signal.\n", signal);
					break;
			}
			continue;
		}

		printf_ddd("Debug3: sync_sighandler(): got signal %i. *state_p == %i.\n", signal, *state_p);

		if(ret) {
			// TODO: handle an error here
		}

		switch(signal) {
			case SIGALRM:
				*exitcode_p = ETIME;
			case SIGTERM:
			case SIGINT:
				sync_switch_state(pthread_parent, STATE_TERM);
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
				printf_e("Error: Unknown signal: %i. Exit.\n", signal);
				sync_switch_state(pthread_parent, STATE_TERM);
				break;
		}

		if((*state_p == STATE_TERM) || (*state_p == STATE_EXIT)) {
			break;
		}
	}

	return 0;
}

int sync_term(int exitcode) {
	*sync_sighandler_exitcode_p = exitcode;
	return pthread_kill(pthread_sighandler, SIGTERM);
}

int sync_run(options_t *options_p) {
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

//	sighandler_arg.options_p        =  options_p;
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

	indexes_t indexes = {NULL};
	indexes.wd2fpath_ht      = g_hash_table_new_full(g_direct_hash,	g_direct_equal,	0,    0);
	indexes.fpath2wd_ht      = g_hash_table_new_full(g_str_hash,	g_str_equal,	free, 0);
	indexes.fpath2ei_ht      = g_hash_table_new_full(g_str_hash,	g_str_equal,	free, free);
	indexes.exc_fpath_ht     = g_hash_table_new_full(g_str_hash,	g_str_equal,	free, 0);
	indexes.out_lines_aggr_ht= g_hash_table_new_full(g_str_hash,	g_str_equal,	free, 0);
	i=0;
	while(i<QUEUE_MAX) {
		indexes.fpath2ei_coll_ht[i]  = g_hash_table_new_full(g_str_hash,    g_str_equal,    free, free);
		indexes.exc_fpath_coll_ht[i] = g_hash_table_new_full(g_str_hash,    g_str_equal,    free, 0);
		i++;
	}

	// Loading dynamical libraries
	if(options_p->flags[SYNCHANDLERSO]) {
                /* security checks before dlopen */
                struct stat so_stat;
                if (stat(options_p->handlerfpath, &so_stat) == -1) {
                    printf_e("Can't stat shared object file \"%s\": %s\n", options_p->handlerfpath, strerror(errno));
                    return errno;
                }
                // allow normal files only (stat will follow symlinks)
                if (!S_ISREG(so_stat.st_mode)) {
                    printf_e("Shared object \"%s\" must be a regular file (or symlink to a regular file).\n",
                        options_p->handlerfpath, so_stat.st_uid);
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
                        printf_e("Can't stat clsync binary file \"%s\": %s\n", cl_str, strerror(errno));
                    }
                    if (ret == -1 || so_stat.st_uid != cl_stat.st_uid) {
                        printf_e("Wrong owner for shared object \"%s\": %i\n"
                                 "Only root, clsync file owner and user started the program are allowed.\n",
                            options_p->handlerfpath, so_stat.st_uid);
                        return EPERM;
                    }
                }
                // do not allow special bits and g+w,o+w
                if (so_stat.st_mode & (S_ISUID | S_ISGID | S_ISVTX | S_IWGRP | S_IWOTH)) {
                    printf_e("Wrong shared object \"%s\" permissions: %#lo\n"
                             "Special bits, group and world writable are not allowed.\n",
                        options_p->handlerfpath, so_stat.st_mode & 07777);
                    return EPERM;
                }

		void *synchandler_handle = dlopen(options_p->handlerfpath, RTLD_NOW|RTLD_LOCAL);
		if(synchandler_handle == NULL) {
			printf_e("Error: sync_run(): Cannot load shared object file \"%s\": %s\n", options_p->handlerfpath, dlerror());
			return -1;
		}
		options_p->handler_handle = synchandler_handle;
		options_p->handler_funct.init   = (api_funct_init)  dlsym(options_p->handler_handle, API_PREFIX"init");
		options_p->handler_funct.sync   = (api_funct_sync)  dlsym(options_p->handler_handle, API_PREFIX"sync");
		if(options_p->handler_funct.sync == NULL) {
			char *dlerror_str = dlerror();
			printf_e("Error: sync_run(): Cannot resolve symbol "API_PREFIX"sync in shared object \"%s\": %s\n",
				options_p->handlerfpath, dlerror_str != NULL ? dlerror_str : "No error description returned.");
		}
		options_p->handler_funct.deinit = (api_funct_deinit)dlsym(options_p->handler_handle, API_PREFIX"deinit");

		if(options_p->handler_funct.init != NULL)
			if((ret = options_p->handler_funct.init(options_p, &indexes))) {
				printf_e("Error: sync_run(): Cannot init sync-handler module: %s (errno: %i).\n", strerror(ret), ret);
				return ret;
			}
	}

#ifdef CLUSTER_SUPPORT
	// Initializing cluster subsystem

	if(options_p->cluster_iface != NULL) {
		ret = cluster_init(options_p, &indexes);
		if(ret) {
			printf_e("Error: Cannot initialize cluster subsystem: %s (errno %i).\n", strerror(ret), ret);
			cluster_deinit();
			return ret;
		}
	}
#endif

	// Initializing rand-generator if it's required

	if(options_p->listoutdir)
		srand(time(NULL));

	// Initializing FS monitor kernel subsystem in this userspace application

	int notify_d = sync_notify_init(options_p);
	if(notify_d == -1) return errno;

	// Marking file tree for FS monitor
	ret = sync_mark_walk(notify_d, options_p, options_p->watchdir, &indexes);
	if(ret) return ret;

	// "Infinite" loop of processling the events
	ret = sync_notify_loop(notify_d, options_p, &indexes);
	if(ret) return ret;

	// TODO: Do cleanup of watching points
	pthread_kill(pthread_sighandler, SIGTERM);
	pthread_join(pthread_sighandler, NULL);

	thread_cleanup(options_p);

	printf_ddd("sync_run(): Closing notify_d\n");
	close(notify_d);

	// Closing shared libraries
	if(options_p->flags[SYNCHANDLERSO]) {
		int _ret;
		if(options_p->handler_funct.deinit != NULL)
			if((_ret = options_p->handler_funct.deinit())) {
				printf_e("Error: sync_run(): Cannot deinit sync-handler module: %s (errno: %i).\n", strerror(ret), ret);
				if(!ret) ret = _ret;
			}

		if(dlclose(options_p->handler_handle)) {
			printf_e("Error: sync_run(): Cannot unload shared object file \"%s\": %s\n",
				options_p->handlerfpath, dlerror());
			if(!ret) ret = -1;
		}
	}

	// Removing hash-tables
	printf_ddd("sync_run(): Closing hash tables\n");
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
	if(options_p->cluster_iface != NULL) {
		int _ret;
		_ret = cluster_deinit();
		if(_ret) {
			printf_e("Error: Cannot deinitialize cluster subsystem: %s (errno: %i).\n", strerror(_ret), _ret);
			ret = _ret;
		}
	}
#endif

#ifdef VERYPARANOID
	// One second for another threads
	sleep(1);
#endif
	return ret;
}

