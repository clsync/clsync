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
#include "main.h"
#include "output.h"
#include "fileutils.h"
#include "malloc.h"
#include "sync.h"


// Checks file path by rules' expressions (from file)
// Return: action for the "file path"

static ruleaction_t rules_check(const char *fpath, mode_t st_mode, rule_t *rules_p) {
	ruleaction_t action = RULE_END;
	printf_ddd("Debug3: rules_check(\"%s\", %p, rules_p)\n", fpath, (void *)(unsigned long)st_mode);

	int i = 0;
	rule_t *rule_p = rules_p;
	mode_t ftype = st_mode & S_IFMT;
	while(rule_p->action != RULE_END) {
		printf_ddd("Debug3: rules_check(): %i->%i: type compare: %p, %p -> %p\n", i, rule_p->action, (void *)(unsigned long)ftype, (void *)(unsigned long)rule_p->objtype, !(rule_p->objtype && (rule_p->objtype != ftype)));

		if(rule_p->objtype && (rule_p->objtype != ftype)) {
			rule_p = &rules_p[++i];
			continue;
		}

		if(!regexec(&rule_p->expr, fpath, 0, NULL, 0))
			break;

		rule_p = &rules_p[++i];

	}

	action = rule_p->action;
	if(action == RULE_END)
		action = RULE_DEFAULT;

	printf_dd("Debug2: matched to rule #%u for \"%s\":\t%i -> %i.\n", rule_p->action==RULE_END?-1:i, fpath, rule_p->action, action);

	return action;
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
	static threadsinfo_t threadsinfo={0};
#ifdef PTHREAD_MUTEX
	if(!threadsinfo._mutex_init) {
		if(pthread_mutex_init(&threadsinfo._mutex, NULL)) {
			printf_e("Error: Cannot pthread_mutex_init(): %s (errno: %i).\n", strerror(errno), errno);
			return NULL;
		}
		threadsinfo._mutex_init++;
	}
//	pthread_mutex_lock(&threadsinfo._mutex);
#endif
	return &threadsinfo;
}

threadinfo_t *thread_new() {
	threadsinfo_t *threadsinfo_p = thread_getinfo();
	if(threadsinfo_p == NULL)
		return NULL;

	if(threadsinfo_p->used >= threadsinfo_p->allocated) {
		threadsinfo_p->allocated += ALLOC_PORTION;
		printf_dd("Debug2: Reallocated memory for threadsinfo -> %i.\n", threadsinfo_p->allocated);
		threadsinfo_p->threads = (threadinfo_t *)xrealloc((char *)threadsinfo_p->threads, sizeof(*threadsinfo_p->threads)*(threadsinfo_p->allocated));
	}

	int thread_num = threadsinfo_p->used++;
	threadinfo_t *threadinfo_p = &threadsinfo_p->threads[thread_num];

#ifdef PARANOID
	memset(threadinfo_p, 0, sizeof(&threadinfo_p));
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

	char **ptr = threadinfo_p->argv;
	if(ptr != NULL) {
		while(*ptr)
			free(*(ptr++));
		free(threadinfo_p->argv);
	}

	threadsinfo_p->used--;
	if(thread_num != threadsinfo_p->used) {
		printf_ddd("Debug3: thread_del_bynum(): %i -> %i; left: %i\n", threadsinfo_p->used, thread_num, threadsinfo_p->used);
		memcpy(threadinfo_p, &threadsinfo_p->threads[threadsinfo_p->used], sizeof(*threadinfo_p));
	}

	printf_ddd("Debug3: thread_del_bynum(%i): there're %i threads left.\n", thread_num, threadsinfo_p->used);
	return 0;
}

int thread_gc(options_t *options_p) {
	int thread_num;
	threadsinfo_t *threadsinfo_p = thread_getinfo();
	if(threadsinfo_p == NULL)
		return errno;

	printf_dd("Debug2: thread_gc(): There're %i threads.\n", threadsinfo_p->used);
	thread_num=-1;
	while(++thread_num < threadsinfo_p->used) {
		int err;
		threadinfo_t *threadinfo_p = &threadsinfo_p->threads[thread_num];

		printf_ddd("Debug3: thread_gc(): Trying thread #%i.\n", thread_num);

#ifndef PARANOID
		if(threadinfo_p->state != STATE_TERM) {
			printf_ddd("Debug3: thread_gc(): Thread #%i is busy, skipping.\n", thread_num);
//			thread_num++;
			continue;
		}
		
		printf_ddd("Debug3: thread_gc(): Thread #%i is finished with exitcode %i, deleting.\n", thread_num, threadinfo_p->exitcode);
		switch((err=pthread_join(threadinfo_p->pthread, (void **)&threadinfo_p->exitcode))) {
#else
		switch((err=pthread_tryjoin_np(threadinfo_p->pthread, (void **)&threadinfo_p->exitcode))) {
			case EBUSY:
				printf_ddd("Debug3: thread_gc(): Thread #%i is busy, skipping.\n", thread_num);
//				thread_num++;
				continue;
#endif
			case 0:
				printf_ddd("Debug3: thread_gc(): Thread #%i is finished with exitcode %i, deleting.\n", thread_num, threadinfo_p->exitcode);
				break;
			default:
				printf_e("Error: Got error while pthread_join() or pthread_tryjoin_np(): %s (errno: %i).\n", strerror(err), err);
				return errno;

		}

		if(threadinfo_p->exitcode) {
			printf_e("Error: Got error from __sync_exec(): %s (errno: %i).\n", strerror(threadinfo_p->exitcode), threadinfo_p->exitcode);
			return threadinfo_p->exitcode;
		}

		if(threadinfo_p->callback)
			if((err=threadinfo_p->callback(options_p, threadinfo_p->argv))) {
				printf_e("Error: Got error from callback function: %s (errno: %i).\n", strerror(err), err);
				return err;
			}

		if(thread_del_bynum(thread_num))
			return errno;
	}

	printf_ddd("Debug3: thread_gc(): There're %i threads left.\n", threadsinfo_p->used);
	return 0;
}

int thread_cleanup(options_t *options_p) {
	printf_ddd("Debug3: thread_cleanup()\n");
	threadsinfo_t *threadsinfo_p = thread_getinfo();
	if(threadsinfo_p == NULL)
		return errno;

	// Waiting for threads:
	printf_d("Debug: There're %i opened threads. Waiting.\n", threadsinfo_p->used);
	while(threadsinfo_p->used) {
		int err;
		threadinfo_t *threadinfo_p = &threadsinfo_p->threads[--threadsinfo_p->used];
		pthread_join(threadinfo_p->pthread, (void **)&threadinfo_p->exitcode);
		printf_dd("Debug2: thread #%i exitcode: %i\n", threadsinfo_p->used, threadinfo_p->exitcode);
		if(threadinfo_p->callback)
			if((err=threadinfo_p->callback(options_p, threadinfo_p->argv)))
				printf_e("Warning: Got error from callback function: %s (errno: %i).\n", strerror(err), err);

		char **ptr = threadinfo_p->argv;
		while(*ptr)
			free(*(ptr++));
		free(threadinfo_p->argv);
	}
	printf_ddd("Debug3: thread_cleanup(): All threads are closed.\n");

	// Freeing
	if(threadsinfo_p->allocated)
		free(threadsinfo_p->threads);

#ifdef PTHREAD_MUTEX
	if(threadsinfo_p->_mutex_init)
		pthread_mutex_destroy(&threadsinfo_p->_mutex);
#endif

#ifdef PARANOID
	// Reseting
	memset(threadsinfo_p, 0, sizeof(*threadsinfo_p));	// Just in case;
#endif

	printf_ddd("Debug3: thread_cleanup(): done.\n");
	return 0;
}

int *state_p = NULL;
/*
static inline int __sync_exec_exit(int exitcode) {
	if(pthread_self() && exitcode)
		exit(exitcode);

	return exitcode;
}*/
int __sync_exec(char **argv) {
	int ret = 0;

	pid_t pid;
	int status;

	pid = fork();
	switch(pid) {
		case -1: 
			printf_e("Error: Cannot fork(): %s (errno: %i).\n", strerror(errno), errno);
			return errno;
		case  0:
			execvp(argv[0], (char *const *)argv);
			return errno;
	}

	if(waitpid(pid, &status, 0) != pid) {
		printf_e("Error: Cannot waitid(): %s (errno: %i).\n", strerror(errno), errno);
		return errno;
	}

	int exitcode = WEXITSTATUS(status);

	if(exitcode) {
		printf_e("Error: Got non-zero exitcode while running \"%s\", exitcode is %i.\n", argv[0], exitcode);
		return exitcode;
	}

	return ret;
}


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

#define SYNC_EXEC(...) (options_p->flags[PTHREAD]?sync_exec_thread:sync_exec)(__VA_ARGS__)

static inline int sync_exec(options_t *options_p, thread_callbackfunct_t callback, ...) {
	printf_dd("Debug2: sync_exec()\n");

	char **argv = (char **)xcalloc(sizeof(char *), MAXARGUMENTS);
	memset(argv, 0, sizeof(char *)*MAXARGUMENTS);

	_sync_exec_getargv(argv, callback, arg);

	int ret = __sync_exec(argv);
	if(ret) {
		printf_e("Error: Got error while __sync_exec(): %s (errno: %i).\n", strerror(ret), ret);
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

static inline int thread_exit(threadinfo_t *threadinfo_p, int exitcode) {
	threadinfo_p->state    = STATE_TERM;
	threadinfo_p->exitcode = exitcode;

	// Notifying the parent-thread, that it's type to collect garbage threads
	return kill(getpid(), SIGUSR_PTHREAD_GC);
}

int __sync_exec_thread(threadinfo_t *threadinfo_p) {
	char **argv			= threadinfo_p->argv;

	int ret = __sync_exec(argv);

	thread_exit(threadinfo_p, ret);

	return ret;
}

static inline int sync_exec_thread(options_t *options_p, thread_callbackfunct_t callback, ...) {
	printf_dd("Debug2: sync_exec_thread()\n");

	char **argv = (char **)xcalloc(sizeof(char *), MAXARGUMENTS);
	memset(argv, 0, sizeof(char *)*MAXARGUMENTS);

	_sync_exec_getargv(argv, callback, strdup(arg));

	threadinfo_t *threadinfo_p = thread_new();
	if(threadinfo_p == NULL)
		return errno;

	threadinfo_p->callback = callback;
	threadinfo_p->argv     = argv;

	if(pthread_create(&threadinfo_p->pthread, NULL, (void *(*)(void *))__sync_exec_thread, threadinfo_p)) {
		printf_e("Error: Cannot pthread_create(): %s (errno: %i).\n", strerror(errno), errno);
		return errno;
	}
	return 0;
}

static int sync_queuesync(const char *fpath, eventinfo_t *evinfo, options_t *options_p, indexes_t *indexes_p, queue_id_t queue_id) {

	printf_ddd("Debug3: sync_queuesync(\"%s\", ...): fsize == %lu; tres == %lu, queue_id == \n", fpath, evinfo->fsize, options_p->bfilethreshold, queue_id);
	if(queue_id == QUEUE_AUTO)
		queue_id = (evinfo->fsize > options_p->bfilethreshold) ? QUEUE_BIGFILE : QUEUE_NORMAL;

	queueinfo_t *queueinfo = &options_p->_queues[queue_id];

	if(!queueinfo->stime)
		queueinfo->stime = time(NULL);

	eventinfo_t *evinfo_dup = (eventinfo_t *)xmalloc(sizeof(*evinfo_dup));
	memcpy(evinfo_dup, evinfo, sizeof(*evinfo_dup));

	return indexes_queueevent(indexes_p, strdup(fpath), evinfo_dup, queue_id);
}

int sync_initialsync_rsync_walk(options_t *options_p, const char *dirpath, indexes_t *indexes_p, queue_id_t queue_id) {
	const char *rootpaths[] = {dirpath, NULL};
	eventinfo_t evinfo;
	FTS *tree;
	rule_t *rules_p = options_p->rules;
	printf_dd("Debug2: sync_initialsync_rsync_walk(options_p, \"%s\", indexes_p, %i).\n", dirpath, queue_id);
//	queueinfo_t *queueinfo = &options_p->_queues[QUEUE_INSTANT];

	tree = fts_open((char *const *)&rootpaths, FTS_NOCHDIR|FTS_PHYSICAL, NULL);

	if(tree == NULL) {
		printf_e("Error: Cannot fts_open() on \"%s\": %s (errno: %i).\n", dirpath, strerror(errno), errno);
		return errno;
	}

	memset(&evinfo, 0, sizeof(evinfo));

	FTSENT *node;
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
					return errno;
				}
			default:

				printf_e("Error: Got unknown fts_info vlaue while fts_read(): %i.\n", node->fts_info);
				return EINVAL;
		}

		ruleaction_t action = rules_check(node->fts_path, node->fts_statp->st_mode, rules_p);

		if(action == RULE_REJECT) {
			fts_set(tree, node, FTS_SKIP);
			if(!options_p->flags[RSYNC_PREFERINCLUDE]) {
				if(queue_id == QUEUE_AUTO) {
					int i=0;
					while(i<QUEUE_MAX)
						indexes_addexclude(indexes_p, strdup(node->fts_path), i++);
				} else
					indexes_addexclude(indexes_p, strdup(node->fts_path), queue_id);
			}
			continue;
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

		if(options_p->flags[RSYNC_PREFERINCLUDE]) {
			printf_ddd("Debug2: sync_initialsync_rsync_walk(): queueing \"%s\" (depth: %i) with int-flags %p\n", node->fts_path, node->fts_level, (void *)(unsigned long)evinfo.flags);
			int ret = sync_queuesync(node->fts_path, &evinfo, options_p, indexes_p, queue_id);

			if(ret) {
				printf_e("Error: Got error while queueing \"%s\": %s (errno: %i).\n", node->fts_path, strerror(errno), errno);
				return errno;
			}
		}
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

int sync_initialsync(const char *path, options_t *options_p, indexes_t *indexes_p, initsync_t initsync) {
	printf_ddd("Debug3: sync_initialsync(\"%s\", options_p, indexes_p, %i)\n", path, initsync);

	if(!options_p->flags[RSYNC]) {
		// non-RSYNC case:
		printf_ddd("Debug3: sync_initialsync(): syncing \"%s\"\n", path);
/*
		if(options_p->flags[PTHREAD])
			return sync_exec_thread(options_p, NULL, options_p->actfpath, "initialsync", options_p->label, path, NULL);
		else
			return sync_exec       (options_p, NULL, options_p->actfpath, "initialsync", options_p->label, path, NULL);*/

		return SYNC_EXEC(options_p, NULL, options_p->actfpath, "initialsync", options_p->label, path, NULL);

#ifdef DOXYGEN
		sync_exec(NULL, NULL); sync_exec_thread(NULL, NULL);
#endif
	}

	// RSYNC case:
//	queue_id_t queue_id = initsync==INITSYNC_FIRST ? QUEUE_INSTANT : QUEUE_AUTO;
	queue_id_t queue_id = initsync==INITSYNC_FIRST ? QUEUE_INSTANT : QUEUE_NORMAL;

	if(!options_p->flags[RSYNC_PREFERINCLUDE]) {
		queueinfo_t *queueinfo = &options_p->_queues[queue_id];

		if(!queueinfo->stime)
			queueinfo->stime = time(NULL); // Useful for debugging


		eventinfo_t *evinfo = (eventinfo_t *)xmalloc(sizeof(*evinfo));
		memset(evinfo, 0, sizeof(*evinfo));
		evinfo->flags |= EVIF_RECURSIVELY;

		// Searching for excludes
		int ret = sync_initialsync_rsync_walk(options_p, path, indexes_p, queue_id);
		if(ret) {
			printf_e("Error: Cannot get exclude what to exclude: %s (errno: %i)\n", strerror(ret), ret);
			return ret;
		}

		printf_ddd("Debug3: sync_initialsync(): queueing \"%s\" with int-flags %p\n", path, (void *)(unsigned long)evinfo->flags);

		

		return indexes_queueevent(indexes_p, strdup(path), evinfo, queue_id);
	}

	// Searching for includes
	return sync_initialsync_rsync_walk(options_p, path, indexes_p, queue_id);
}

int sync_notify_mark(int notify_d, options_t *options_p, const char *accpath, const char *path, size_t pathlen, indexes_t *indexes_p) {
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

int sync_mark_walk(int notify_d, options_t *options_p, const char *dirpath, indexes_t *indexes_p, initsync_t initsync) {
	const char *rootpaths[] = {dirpath, NULL};
	FTS *tree;
	rule_t *rules_p = options_p->rules;
	printf_dd("Debug2: sync_mark_walk(%i, options_p, \"%s\", indexes_p, %i).\n", notify_d, dirpath, initsync);
	printf_funct my_printf_e = (initsync == INITSYNC_FIRST) ? printf_e : _printf_dd;

	tree = fts_open((char *const *)&rootpaths, FTS_NOCHDIR|FTS_PHYSICAL, NULL);

	if(tree == NULL) {
		my_printf_e("Error: Cannot fts_open() on \"%s\": %s (errno: %i).\n", dirpath, strerror(errno), errno);
		return errno;
	}

	FTSENT *node;
	while((node = fts_read(tree))) {
		switch(node->fts_info) {
			// Duplicates:
			case FTS_DP:
			case FTS_DEFAULT:
			case FTS_SL:
			case FTS_SLNONE:
			case FTS_F:
				continue;
			// To mark:
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
					my_printf_e("Error: Got error while fts_read(): %s (errno: %i; fts_info: %i).\n", strerror(errno), errno, node->fts_info);
					return errno;
				}
			default:
				my_printf_e("Error: Got unknown fts_info vlaue while fts_read(): %i.\n", node->fts_info);
				return EINVAL;
		}

		ruleaction_t action = rules_check(node->fts_path, node->fts_statp->st_mode, rules_p);

		if(action == RULE_REJECT) {
			fts_set(tree, node, FTS_SKIP);
			continue;
		}

		printf_dd("Debug2: marking \"%s\" (depth %u)\n", node->fts_path, node->fts_level);
		int wd = sync_notify_mark(notify_d, options_p, node->fts_accpath, node->fts_path, node->fts_pathlen, indexes_p);
		if(wd == -1) {
			my_printf_e("Error: Got error while notify-marking \"%s\": %s (errno: %i).\n", node->fts_path, strerror(errno), errno);
			return errno;
		}
		printf_dd("Debug2: watching descriptor is %i.\n", wd);
	}
	if(errno) {
		my_printf_e("Error: Got error while fts_read() and related routines: %s (errno: %i).\n", strerror(errno), errno);
		return errno;
	}

	if(fts_close(tree)) {
		my_printf_e("Error: Got error while fts_close(): %s (errno: %i).\n", strerror(errno), errno);
		return errno;
	}

	if(sync_initialsync(dirpath, options_p, indexes_p, initsync))
		return -1;

	return 0;
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

static inline int sync_dosync_exec(options_t *options_p, const char *evmask_str, const char *fpath) {
/*
	if(options_p->flags[PTHREAD])
		return sync_exec_thread(options_p, NULL, options_p->actfpath, "sync", options_p->label, evmask_str, fpath, NULL);
	else
		return sync_exec       (options_p, NULL, options_p->actfpath, "sync", options_p->label, evmask_str, fpath, NULL);*/
	return SYNC_EXEC(options_p, NULL, options_p->actfpath, "sync", options_p->label, evmask_str, fpath, NULL);

#ifdef DOXYGEN
	sync_exec(NULL, NULL); sync_exec_thread(NULL, NULL);
#endif

}

static int sync_dosync(const char *fpath, uint32_t evmask, options_t *options_p, indexes_t *indexes_p) {
	int ret;
	char *evmask_str = xmalloc(1<<8);
	sprintf(evmask_str, "%u", evmask);

	ret = sync_dosync_exec(options_p, evmask_str, fpath);

	free(evmask_str);

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

	if(options_p->listoutdir == NULL) {
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
		snprintf(fpath, PATH_MAX, "%s/.clsync-%s.%u.%lu.%u", options_p->listoutdir, name, pid, (unsigned long)tm, rand());	// To be unique
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
	options_t *options_p 	  = dosync_arg_p->options_p;
//	indexes_t *indexes_p	  = dosync_arg_p->indexes_p;
	printf_ddd("Debug3: sync_idle_dosync_collectedevents_rsync_exclistpush(): \"%s\"\n", fpath);

	// RSYNC case
	size_t fpathlen = strlen(fpath);
	char *fpath_rel_p = xmalloc(fpathlen+1);
	char *fpath_rel = fpath_rel_p;

	memcpy(fpath_rel, &fpath[options_p->watchdirlen], fpathlen+1 - options_p->watchdirlen);

	printf_ddd("Debug3: Adding to exclude-file: \"%s\"\n", fpath_rel);
	fprintf(excf, "%s\n", fpath_rel);

	return TRUE;
}

int sync_idle_dosync_collectedevents_commitpart(struct dosync_arg *dosync_arg_p) {
	printf_ddd("Debug3: Committing the file\n");
	options_t *options_p = dosync_arg_p->options_p;
	fclose(dosync_arg_p->outf);
	dosync_arg_p->outf = NULL;

	if(dosync_arg_p->evcount > 0) {
/*
		if(options_p->flags[PTHREAD])
			return sync_exec_thread(options_p,
						sync_idle_dosync_collectedevents_cleanup,
						options_p->actfpath,
						options_p->flags[RSYNC]?"rsynclist":"synclist",
						options_p->label,
						dosync_arg_p->outf_path,
						*(dosync_arg_p->outf_path)?dosync_arg_p->outf_path:NULL,
						NULL);
		else
			return sync_exec       (options_p,
						sync_idle_dosync_collectedevents_cleanup,
						options_p->actfpath,
						options_p->flags[RSYNC]?"rsynclist":"synclist", 
						options_p->label,
						dosync_arg_p->outf_path,
						*(dosync_arg_p->outf_path)?dosync_arg_p->outf_path:NULL,
						NULL);*/
		return SYNC_EXEC(options_p,
			sync_idle_dosync_collectedevents_cleanup,
			options_p->actfpath,
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

gboolean sync_idle_dosync_collectedevents_listpush(gpointer fpath_gp, gpointer evinfo_gp, gpointer arg_gp) {
	struct dosync_arg *dosync_arg_p = (struct dosync_arg *)arg_gp;
	char *fpath		  = (char *)fpath_gp;
	eventinfo_t *evinfo	  = (eventinfo_t *)evinfo_gp;
//	int *evcount_p		  =&dosync_arg_p->evcount;
	FILE *outf		  = dosync_arg_p->outf;
	options_t *options_p 	  = dosync_arg_p->options_p;
	int *linescount_p	  =&dosync_arg_p->linescount;
	indexes_t *indexes_p 	  = dosync_arg_p->indexes_p;
	printf_ddd("Debug3: sync_idle_dosync_collectedevents_listpush(): \"%s\" with int-flags %p\n", fpath, (void *)(unsigned long)evinfo->flags);

	if(!options_p->flags[RSYNC]) {
		// non-RSYNC case

		fprintf(outf, "sync %s %i %s\n", options_p->label, evinfo->evmask, fpath);
		return TRUE;
	}

	// RSYNC case
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

	size_t fpathlen = strlen(fpath);
	char *fpath_rel_p = xmalloc(fpathlen+1);
	char *fpath_rel = fpath_rel_p;

	memcpy(fpath_rel, &fpath[options_p->watchdirlen], fpathlen+1 - options_p->watchdirlen);

	char *end=fpath_rel;

	if(evinfo->flags & EVIF_RECURSIVELY) {
		printf_ddd("Debug3: sync_idle_dosync_collectedevents_listpush(): Recursively \"%s\": Adding to rsynclist: \"%s/***\".\n", fpath, fpath_rel);
		fprintf(outf, "%s/***\n", fpath_rel);
		(*linescount_p)++;
	}


	while(end != NULL) {
		if(*fpath_rel == 0x00)
			break;
		printf_ddd("Debug3: sync_idle_dosync_collectedevents_listpush(): Non-recursively \"%s\": Adding to rsynclist: \"%s\".\n", fpath, fpath_rel);
		indexes_outaggr_add(indexes_p, strdup(fpath_rel_p));
//		fprintf(outf, "%s\n", fpath_rel);
		(*linescount_p)++;
		end = strrchr(fpath_rel, '/');
		if(end == NULL)
			break;
		if(end - fpath_rel <= 0)
			break;

		*end = 0x00;
	};

	free(fpath_rel_p);
	return TRUE;
}



int sync_idle_dosync_collectedevents(options_t *options_p, indexes_t *indexes_p) {
	struct dosync_arg dosync_arg;
	dosync_arg.evcount	= 0;
	dosync_arg.options_p 	= options_p;
	dosync_arg.indexes_p	= indexes_p;
	dosync_arg.outf		= NULL;

	char isrsyncpreferexclude = options_p->flags[RSYNC] && (!options_p->flags[RSYNC_PREFERINCLUDE]);

#ifdef PARANOID
	if(options_p->listoutdir != NULL) {
		g_hash_table_remove_all(indexes_p->fpath2ei_ht);
		if(isrsyncpreferexclude)
			g_hash_table_remove_all(indexes_p->exc_fpath_ht);
	}
#endif

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

	if(options_p->listoutdir != NULL) {
		int ret;

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

#ifdef PARANOID
		g_hash_table_remove_all(indexes_p->out_lines_aggr_ht);
#endif
		g_hash_table_foreach_remove(indexes_p->fpath2ei_ht, sync_idle_dosync_collectedevents_listpush, &dosync_arg);
		g_hash_table_foreach_remove(indexes_p->out_lines_aggr_ht, sync_idle_dosync_collectedevents_aggrout, &dosync_arg);

		if((ret=sync_idle_dosync_collectedevents_commitpart(&dosync_arg))) {
			printf_e("Error: Cannot submit to sync the list \"%s\": %s (errno: %i)\n", dosync_arg.outf_path, strerror(ret), ret);
			return ret;
		}
	}

	return 0;
}

int sync_idle(int notify_d, options_t *options_p, indexes_t *indexes_p) {

#ifdef PARANOID
	int ret=thread_gc(options_p);
	if(ret) return ret;
#endif

	printf_ddd("Debug3: sync_idle(): calling sync_idle_dosync_collectedevents()\n");

	// TODO: make a separate thread on sync_idle_dosync_collectedevents();
	sync_idle_dosync_collectedevents(options_p, indexes_p);
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
					sync_queuesync(fpath, 0, options_p, indexes_p, QUEUE_AUTO);
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
	static struct timeval tv={0};
	time_t tm = time(NULL);
	long mindelayleft = ((unsigned long)~0 >> 1);

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
		if(qdelay < -(long)options_p->commondelay)
			qdelay = -(long)options_p->commondelay;

		mindelayleft = MIN(mindelayleft, qdelay);
	}

	if(mindelayleft == ((unsigned long)~0 >> 1))
		tv.tv_sec = mindelayleft;
	else
		tv.tv_sec = mindelayleft + options_p->commondelay;

	printf_ddd("Debug3: sync_inotify_wait(): select with timeout %li secs.\n", tv.tv_sec);
	return select(FD_SETSIZE, &rfds, NULL, NULL, &tv);
}

void sync_inotify_handle_dosync(gpointer fpath_gp, gpointer evinfo_gp, gpointer arg_gp) {
	char *fpath		  = (char *)fpath_gp;
	eventinfo_t *evinfo	  = (eventinfo_t *)evinfo_gp;
	options_t *options_p 	  = ((struct dosync_arg *)arg_gp)->options_p;
	indexes_t *indexes_p 	  = ((struct dosync_arg *)arg_gp)->indexes_p;

	sync_queuesync(fpath, evinfo, options_p, indexes_p, QUEUE_AUTO);

	return;
}

#define SYNC_INOTIFY_HANDLE_CONTINUE {\
	ptr += sizeof(struct inotify_event) + event->len;\
	count++;\
	continue;\
}

int sync_inotify_handle(int inotify_d, options_t *options_p, indexes_t *indexes_p) {
	char buf[BUFSIZ + 1];
	size_t r = read(inotify_d, buf, BUFSIZ);
	if(r <= 0) {
		printf_e("Error: Got error while reading events from inotify with read(): %s (errno: %i).\n", strerror(errno), errno);
		return -1;
	}

#ifdef PARANOID
	g_hash_table_remove_all(indexes_p->fpath2ei_ht);
#endif

	int count = 0;
	char *ptr =  buf;
	char *end = &buf[r];
	while(ptr < end) {
		struct inotify_event *event = (struct inotify_event *)ptr;
		if(event->mask & IN_IGNORED) {
			printf_dd("Debug2: Cleaning up info about watch descriptor %i.\n", event->wd);
			indexes_remove_bywd(indexes_p, event->wd);
			SYNC_INOTIFY_HANDLE_CONTINUE;
		}

		char *fpath = indexes_wd2fpath(indexes_p, event->wd);

		if(fpath == NULL) {
			printf_dd("Debug2: Event %p on stale watch (wd: %i).\n", (void *)(long)event->mask, event->wd);
			SYNC_INOTIFY_HANDLE_CONTINUE;
		}
		printf_dd("Debug2: Event %p on \"%s\" (wd: %i; fpath: \"%s\").\n", (void *)(long)event->mask, event->len>0?event->name:"", event->wd, fpath);

		char *fpathfull = xmalloc(strlen(fpath) + event->len + 2);
		if(event->len>0)
			sprintf(fpathfull, "%s/%s", fpath, event->name);
		else
			sprintf(fpathfull, "%s", fpath);

		struct stat64 lstat;
		mode_t st_mode;
		size_t st_size;
		if(lstat64(fpathfull, &lstat)) {
			printf_dd("Debug2: Cannot lstat(\"%s\", lstat): %s (errno: %i). Seems, that the object disappeared.\n", fpathfull, strerror(errno), errno);
			if(event->mask & IN_ISDIR)
				st_mode = S_IFDIR;
			else
				st_mode = S_IFREG;
			st_size = 0;
		} else {
			st_mode = lstat.st_mode;
			st_size = lstat.st_size;
		}

		ruleaction_t ruleaction = rules_check(fpathfull, st_mode, options_p->rules);

		if(ruleaction == RULE_REJECT) {
			free(fpathfull);
			SYNC_INOTIFY_HANDLE_CONTINUE;
		}

		if(event->mask & IN_ISDIR) {
			if(event->mask & (IN_CREATE|IN_MOVED_TO)) {			// Appeared
				int ret = sync_mark_walk(inotify_d, options_p, fpathfull, indexes_p, INITSYNC_NORMAL);
				if(ret)
					printf_d("Debug: Seems, that directory \"%s\" disappeared, while trying to mark it.\n", fpathfull);
				free(fpathfull);
				SYNC_INOTIFY_HANDLE_CONTINUE;
			} else 
			if(event->mask & (IN_DELETE|IN_MOVED_FROM)) {	// Disappered
				printf_dd("Debug2: Disappeared \"%s\".\n", fpathfull);
			}
		}

		int isnew = 0;
		eventinfo_t *evinfo = indexes_fpath2ei(indexes_p, fpathfull);
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
			indexes_fpath2ei_add(indexes_p, fpathfull, evinfo);
		else
			free(fpathfull);

		SYNC_INOTIFY_HANDLE_CONTINUE;
	}

	struct dosync_arg dosync_arg;
	dosync_arg.options_p 	= options_p;
	dosync_arg.indexes_p	= indexes_p;

	printf_ddd("Debug3: sync_inotify_handle(): collected %i events per this time.\n", g_hash_table_size(indexes_p->fpath2ei_ht));

	g_hash_table_foreach(indexes_p->fpath2ei_ht, sync_inotify_handle_dosync, &dosync_arg);
	g_hash_table_remove_all(indexes_p->fpath2ei_ht);

	return count;
}

#define SYNC_INOTIFY_LOOP_IDLE {\
	int ret;\
	if((ret=sync_idle(inotify_d, options_p, indexes_p))) {\
		printf_e("Error: got error while sync_idle(): %s (errno: %i).\n", strerror(ret), ret);\
		return ret;\
	}\
}

int sync_inotify_loop(int inotify_d, options_t *options_p, indexes_t *indexes_p) {
	int state=1;
	state_p = &state;

	while(state != STATE_EXIT) {
		int events = sync_inotify_wait(inotify_d, options_p, indexes_p);
		switch(state) {
			case STATE_PTHREAD_GC:
				thread_gc(options_p);
				state = STATE_RUNNING;
				continue;
			case STATE_RUNNING:
				break;
			case STATE_REHASH:
				printf_d("Debug: sync_inotify_loop(): rehashing.\n");
				main_rehash(options_p);
				state = STATE_RUNNING;
				continue;
			case STATE_TERM:
				state = STATE_EXIT;
			case STATE_EXIT:
				continue;
		}

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
	return 0;

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

void sync_sig_pthread_gc(int signal) {
	if(state_p)
		*state_p = STATE_PTHREAD_GC;

	return;
}

void sync_sig_rehash(int signal) {
	if(state_p)
		*state_p = STATE_REHASH;

	return;
}

void sync_sig_term(int signal) {
	if(state_p)
		*state_p = STATE_TERM;

	return;
}

int sync_run(options_t *options_p) {
	int ret, i;
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

	if(options_p->listoutdir)
		srand(time(NULL));

	int notify_d = sync_notify_init(options_p);
	if(notify_d == -1) return errno;

	ret = sync_mark_walk(notify_d, options_p, options_p->watchdir, &indexes, INITSYNC_FIRST);
	if(ret) return ret;

	signal(SIGHUP,	sync_sig_rehash);
	signal(SIGTERM,	sync_sig_term);
	signal(SIGINT,	sync_sig_term);

	signal(SIGUSR_PTHREAD_GC, sync_sig_pthread_gc);

	ret = sync_notify_loop(notify_d, options_p, &indexes);
	if(ret) return ret;

	// TODO: Do cleanup of watching points

	thread_cleanup(options_p);

	printf_ddd("sync_run(): Closing notify_d\n");
	close(notify_d);

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

	return 0;
}

