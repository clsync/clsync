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
#include "output.h"
#include "fileutils.h"
#include "malloc.h"


// This function checks file path by rules' expressions (from file)
// Return: action for the "file path"

static ruleaction_t rules_check(const char *fpath, mode_t st_mode, rule_t *rules_p) {
	ruleaction_t action = RULE_END;

	int i = 0;
	rule_t *rule_p = rules_p;
	mode_t ftype = st_mode & S_IFMT;
	while(rule_p->action != RULE_END) {

		if(rule_p->objtype && (rule_p->objtype != ftype)) {
			rule_p = &rules_p[i++];
			continue;
		}

		if(!regexec(&rule_p->expr, fpath, 0, NULL, 0))
			break;

		rule_p = &rules_p[i++];

	}

	action = rule_p->action;
	if(action == RULE_END)
		action = RULE_DEFAULT;

	printf_dd("Debug2: matched to rule #%u for \"%s\":\t%i -> %i.\n", rule_p->action==RULE_END?-1:i, fpath, rule_p->action, action);

	return action;
}

// This function removes necessary rows from hash_tables if some watching descriptor closed
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

// This function add necessary rows to hash_tables if some watching descriptor opened
// Return: 0 on success, non-zero on fail

static inline int indexes_add_wd(indexes_t *indexes_p, int wd, const char *fpath_const, size_t fpathlen) {
	printf_ddd("Debug3: indexes_add_wd(indexes_p, %i, \"%s\", %i)\n", wd, fpath_const, fpathlen);

	char *fpath = xmalloc(fpathlen+1);
	memcpy(fpath, fpath_const, fpathlen+1);
	g_hash_table_insert(indexes_p->wd2fpath_ht, GINT_TO_POINTER(wd), fpath);
	g_hash_table_insert(indexes_p->fpath2wd_ht, fpath, GINT_TO_POINTER(wd));

	return 0;
}

// This function is lookup file path by watching descriptor from hash_tables
// Return: file path on success, NULL on fail

static inline char *indexes_wd2fpath(indexes_t *indexes_p, int wd) {
	return g_hash_table_lookup(indexes_p->wd2fpath_ht, GINT_TO_POINTER(wd));
}

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

static threadsinfo_t *_sync_exec_getthreadsinfo() {	// TODO: optimize this
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

threadinfo_t *_sync_exec_newthread() {
	threadsinfo_t *threadsinfo_p = _sync_exec_getthreadsinfo();
	if(threadsinfo_p == NULL)
		return NULL;

	if(threadsinfo_p->used >= threadsinfo_p->allocated) {
		threadsinfo_p->allocated += ALLOC_PORTION;
		printf_dd("Debug2: Reallocated memory for threadsinfo -> %i.\n", threadsinfo_p->allocated);
		threadsinfo_p->threads = (threadinfo_t *)xrealloc((char *)threadsinfo_p->threads, sizeof(*threadsinfo_p->threads)*(threadsinfo_p->allocated));
	}

	printf_dd("Debug2: _sync_exec_newthread -> thread_num: %i; used: %i\n", threadsinfo_p->used, threadsinfo_p->used+1);
	return &threadsinfo_p->threads[threadsinfo_p->used++];
}

int _sync_exec_delthread_bynum(int thread_num) {
	printf_dd("Debug2: _sync_exec_delthread(%i)\n", thread_num);
	threadsinfo_t *threadsinfo_p = _sync_exec_getthreadsinfo();
	if(threadsinfo_p == NULL)
		return errno;

	if(thread_num >= threadsinfo_p->used)
		return EINVAL;

	threadsinfo_p->used--;
	if(thread_num != threadsinfo_p->used) {
		printf_ddd("Debug3: _sync_exec_delthread(): %i -> %i; left: %i\n", threadsinfo_p->used, thread_num, threadsinfo_p->used);
		memcpy(&threadsinfo_p->threads[thread_num], &threadsinfo_p->threads[threadsinfo_p->used], sizeof(*threadsinfo_p->threads));
	}

	return 0;
}

int _sync_exec_threads_gc() {
	threadsinfo_t *threadsinfo_p = _sync_exec_getthreadsinfo();
	if(threadsinfo_p == NULL)
		return errno;
	
	printf_dd("Debug2: _sync_exec_threads_gc(): There're %i threads.\n", threadsinfo_p->used);
	int thread_num=0;
	int thread_num_r;	// TODO: find-out why is thread_num_r required.
				// I have to do "thread_num = thread_num_r" after pthread_tryjoin_np(),
				// otherwise "thread_num" is becoming "zero", again :(
	while(thread_num < threadsinfo_p->used) {
		int ret=0;
		threadinfo_t *threadinfo_p = &threadsinfo_p->threads[thread_num];

		thread_num_r=thread_num;
		printf_ddd("Debug3: _sync_exec_threads_gc(): Trying thread #%i (thread_num_r: %i).\n", thread_num, thread_num_r);
		int err;
		switch((err=pthread_tryjoin_np(threadinfo_p->pthread, (void **)&ret))) {
			case 0:
				thread_num = thread_num_r;
				printf_ddd("Debug3: _sync_exec_threads_gc(): Thread #%i is finished with exitcode %i, deleting (thread_num_r: %i).\n", thread_num, ret, thread_num_r);
				break;
			case EBUSY:
				printf_ddd("Debug3: _sync_exec_threads_gc(): Thread #%i is busy, skipping.\n", thread_num);
				thread_num++;
				continue;
			default:
				printf_e("Error: Got error while pthread_tryjoin_np(): %s (errno: %i).\n", strerror(err), err);
				return errno;

		}

		if(ret) {
			printf_e("Error: Got error from __sync_exec(): %s (errno: %i).\n", strerror(ret), ret);
			return ret;
		}

		if(threadinfo_p->callback)
			if((err=threadinfo_p->callback(threadinfo_p->argv))) {
				printf_e("Error: Got error from callback function: %s (errno: %i).\n", strerror(err), err);
				return err;
			}

		char **ptr = threadinfo_p->argv;
		while(*ptr)
			free(*(ptr++));
		free(threadinfo_p->argv);

		if(_sync_exec_delthread_bynum(thread_num))
			return errno;
	}

	return 0;
}

int _sync_exec_idle() {
	return _sync_exec_threads_gc();
}

int _sync_exec_cleanup() {
	threadsinfo_t *threadsinfo_p = _sync_exec_getthreadsinfo();
	if(threadsinfo_p == NULL)
		return errno;

	// Waiting for threads:
	printf_d("Debug: There're %i opened threads. Waiting.\n", threadsinfo_p->used);
	while(threadsinfo_p->used) {
		int ret, err;
		threadinfo_t *threadinfo_p = &threadsinfo_p->threads[--threadsinfo_p->used];
		pthread_join(threadinfo_p->pthread, (void **)&ret);
		if(threadinfo_p->callback)
			if((err=threadinfo_p->callback(threadinfo_p->argv)))
				printf_e("Warning: Got error from callback function: %s (errno: %i).\n", strerror(err), err);

		char **ptr = threadinfo_p->argv;
		while(*ptr)
			free(*(ptr++));
		free(threadinfo_p->argv);
	}

	// Freeing
	if(threadsinfo_p->allocated)
		free(threadsinfo_p->threads);

#ifdef PTHREAD_MUTEX
	if(threadsinfo_p->_mutex_init)
		pthread_mutex_destroy(&threadsinfo_p->_mutex);
#endif

	// Reseting
	memset(threadsinfo_p, 0, sizeof(*threadsinfo_p));	// Just in case;

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

// TODO: remove "dummy" argument if possible
#define sync_exec(...) _sync_exec(0, __VA_ARGS__)
static inline int _sync_exec(int dummy, ...) {
	printf_dd("Debug2: _sync_exec()\n");

	char **argv = (char **)xcalloc(sizeof(char *), MAXARGUMENTS);
	memset(argv, 0, sizeof(char *)*MAXARGUMENTS);

	_sync_exec_getargv(argv, dummy, arg);

	return __sync_exec(argv);
}

// TODO: remove "dummy" argument if possible
static inline int sync_exec_thread(thread_callbackfunct_t callback, ...) {
	printf_dd("Debug2: _sync_exec_thread()\n");

	char **argv = (char **)xcalloc(sizeof(char *), MAXARGUMENTS);
	memset(argv, 0, sizeof(char *)*MAXARGUMENTS);

	_sync_exec_getargv(argv, callback, strdup(arg));

	threadinfo_t *threadinfo_p = _sync_exec_newthread();
	if(threadinfo_p == NULL)
		return errno;

	threadinfo_p->callback = callback;
	threadinfo_p->argv     = argv;
	if(pthread_create(&threadinfo_p->pthread, NULL, (void *(*)(void *))__sync_exec, argv)) {
		printf_e("Error: Cannot pthread_create(): %s (errno: %i).\n", strerror(errno), errno);
		return errno;
	}
	return 0;
}

int sync_initialsync(const char *path, options_t *options_p) {
	if(options_p->flags[PTHREAD])
		return sync_exec_thread(NULL, options_p->actfpath, "initialsync", path, NULL);
	else
		return sync_exec       (      options_p->actfpath, "initialsync", path, NULL);
}

int sync_notify_mark(int notify_d, options_t *options_p, const char *accpath, const char *path, size_t pathlen, indexes_t *indexes_p, initsync_t initsync) {
	int wd = indexes_fpath2wd(indexes_p, path);
	if(wd != -1) {
		printf_d("Debug: \"%s\" is already marked (wd: %i). Skipping.\n", path, wd);
		return wd;
	}

	switch(options_p->notifyengine) {
		case NE_FANOTIFY: {
			int fanotify_d = notify_d;

			if((wd = fanotify_mark(fanotify_d, FAN_MARK_ADD | FAN_MARK_DONT_FOLLOW,
				FANOTIFY_MARKMASK, AT_FDCWD, accpath)) == -1)
			{
				printf_e("Error: Cannot fanotify_mark() on \"%s\": %s (errno: %i).\n", 
					path, strerror(errno), errno);
				return -1;
			}
			break;
		}
		case NE_INOTIFY: {
			int inotify_d = notify_d;

			if((wd = inotify_add_watch(inotify_d, accpath, INOTIFY_MARKMASK)) == -1) {
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

	if(initsync == INITSYNC_DO)
		if(sync_initialsync(path, options_p))
			return -1;

	return wd;
}

int sync_walk_notifymark(int notify_d, options_t *options_p, const char *dirpath, rule_t *rules_p, indexes_t *indexes_p, printf_funct _printf_e) {
	const char *rootpaths[] = {dirpath, NULL};
	FTS *tree;
	printf_dd("Debug2: sync_walk_notifymark(%i, options_p, \"%s\", rules_p, _printf_e).\n", notify_d, dirpath);

	tree = fts_open((char *const *)&rootpaths, FTS_NOCHDIR|FTS_PHYSICAL, NULL);

	if(tree == NULL) {
		if(_printf_e)
			_printf_e("Error: Cannot fts_open() on \"%s\": %s (errno: %i).\n", dirpath, strerror(errno), errno);
		return errno;
	}

	initsync_t initsync = INITSYNC_DO;

	FTSENT *node;
	while((node = fts_read(tree))) {
		switch(node->fts_info) {
			case FTS_DP:	// Duplicates:
			case FTS_DEFAULT:
			case FTS_SL:
			case FTS_SLNONE:
			case FTS_F:
				continue;
			case FTS_D:	// To sync:
			case FTS_DOT:
				break;
			case FTS_ERR:	// Error cases:
			case FTS_NS:
			case FTS_NSOK:
			case FTS_DNR:
			case FTS_DC:
				if(_printf_e) {
					if(errno == ENOENT)
						printf_e("Warning: Got error while fts_read(): %s (errno: %i; fts_info: %i).\n", strerror(errno), errno, node->fts_info);
					else
						printf_e("Error: Got error while fts_read(): %s (errno: %i; fts_info: %i).\n", strerror(errno), errno, node->fts_info);
				}
				return errno;
			default:
				if(_printf_e)
					printf_e("Error: Got unknown fts_info vlaue while fts_read(): %i.\n", node->fts_info);
				return EINVAL;
		}

		ruleaction_t action = rules_check(node->fts_path, node->fts_statp->st_mode, rules_p);

		if(action == RULE_REJECT) {
			fts_set(tree, node, FTS_SKIP);
			continue;
		}

		printf_dd("Debug2: marking \"%s\" (depth %u)\n", node->fts_path, node->fts_level);
		int wd = sync_notify_mark(notify_d, options_p, node->fts_accpath, node->fts_path, node->fts_pathlen, indexes_p, node->fts_statp->st_mode&S_IFDIR ? initsync : INITSYNC_SKIP);
		if(node->fts_statp->st_mode&S_IFDIR)
			initsync = INITSYNC_SKIP;

		if(wd < 0) {
			if(_printf_e)
				printf_e("Error: Got error while notify-marking \"%s\": %s (errno: %i).\n", node->fts_path, strerror(errno), errno);
			return errno;
		}
		printf_dd("Debug2: watching descriptor is %i.\n", wd);
	}
	if(errno) {
		if(_printf_e)
			printf_e("Error: Got error while fts_read() and related routines: %s (errno: %i).\n", strerror(errno), errno);
		return errno;
	}

	if(fts_close(tree)) {
		if(_printf_e)
			printf_e("Error: Got error while fts_close(): %s (errno: %i).\n", strerror(errno), errno);
		return errno;
	}

	return 0;
}

int sync_notify_init(options_t *options_p) {
	switch(options_p->notifyengine) {
		case NE_FANOTIFY: {
			int fanotify_d = fanotify_init(FANOTIFY_FLAGS, FANOTIFY_EVFLAGS);
			if(fanotify_d == -1) {
				printf_e("Error: cannot fanotify_init(%i, %i): %s (errno: %i).\n", FANOTIFY_FLAGS, FANOTIFY_EVFLAGS, strerror(errno), errno);
				return -1;
			}

			return fanotify_d;
		}
		case NE_INOTIFY: {
			int inotify_d = inotify_init1(INOTIFY_FLAGS);
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
	if(options_p->flags[PTHREAD])
		return sync_exec_thread(NULL, options_p->actfpath, "sync", options_p->label, evmask_str, fpath, NULL);
	else
		return sync_exec       (      options_p->actfpath, "sync", options_p->label, evmask_str, fpath, NULL);
}

static int sync_dosync(const char *fpath, uint32_t evmask, options_t *options_p, indexes_t *indexes_p) {
	int ret;
	char *evmask_str = xmalloc(1<<8);
	sprintf(evmask_str, "%u", evmask);

	ret = sync_dosync_exec(options_p, evmask_str, fpath);

	free(evmask_str);

	return ret;
}

static int sync_queuesync(const char *fpath, eventinfo_t *evinfo, options_t *options_p, indexes_t *indexes_p) {
	queue_id_t queue_id = QUEUE_NORMAL;

	printf_ddd("Debug3: sync_queuesync(\"%s\", ...): %i %i\n", fpath, evinfo->fsize, options_p->bfilethreshold);
	if(evinfo->fsize > options_p->bfilethreshold)
		queue_id = QUEUE_BIGFILE;

	queueinfo_t *queueinfo = &options_p->_queues[queue_id];

	if(!queueinfo->stime)
		queueinfo->stime = time(NULL);

	eventinfo_t *evinfo_dup = (eventinfo_t *)xmalloc(sizeof(*evinfo_dup));
	memcpy(evinfo_dup, evinfo, sizeof(*evinfo_dup));

	return indexes_queueevent(indexes_p, strdup(fpath), evinfo_dup, queue_id);
}

void _sync_idle_dosync_collectedevents(gpointer fpath_gp, gpointer evmask_gp, gpointer arg_gp) {
	char *fpath		  = (char *)fpath_gp;
	uint32_t evmask		  = (uint32_t)GPOINTER_TO_INT(evmask_gp);
	int *evcount_p		  =&((struct dosync_arg *)arg_gp)->evcount;
	FILE *outf		  = ((struct dosync_arg *)arg_gp)->outf;
	options_t *options_p 	  = ((struct dosync_arg *)arg_gp)->options_p;
	indexes_t *indexes_p 	  = ((struct dosync_arg *)arg_gp)->indexes_p;

	if(options_p->listoutdir == NULL) {
		printf_ddd("Debug3: _sync_idle_dosync_collectedevents(): calling sync_dosync()\n");
		int ret;
		if((ret=sync_dosync(fpath, evmask, options_p, indexes_p))) {
			printf_e("Error: unable to sync \"%s\" (evmask %i): %s (errno: %i).\n", fpath, evmask, strerror(ret), ret);
			exit(ret);	// TODO: remove this from here
		}
	}

	fprintf(outf, "sync %s %i %s\n", options_p->label, evmask, fpath);

	(*evcount_p)++;

	return;
}

int sync_idle_dosync_collectedevents_cleanup(char **argv) {
	if(argv[3] == NULL) {
		printf_e("Error: Unexpected *argv[] end.");
		return EINVAL;
	}

	printf_ddd("Debug3: unlink()-ing \"%s\"\n", argv[3]);
	return unlink(argv[3]);
}

int sync_idle_dosync_collectedevents_procqueue(queue_id_t queue_id, options_t *options_p, indexes_t *indexes_p, time_t tm, struct dosync_arg *dosync_arg) {
	char *buf, *fpath;

	queueinfo_t *queueinfo = &options_p->_queues[queue_id];

	if(queueinfo->stime + queueinfo->collectdelay > tm) {
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

	if((options_p->listoutdir != NULL) && (dosync_arg->outf == NULL)) {
		buf   = alloca(BUFSIZ+1);
		fpath = alloca(PATH_MAX+1);

		int counter = 0;
		struct stat64 stat64;
		pid_t pid = getpid();
		do {
			snprintf(fpath, PATH_MAX, "%s/.clsync-list.%u.%lu.%u", options_p->listoutdir, pid, (unsigned long)tm, rand());	// To be uniquea
			lstat64(fpath, &stat64);
			if(counter++ > COUNTER_LIMIT) {
				printf_e("Error: Cannot file unused filename for list-file. The last try was \"%s\".\n", fpath);
				return ELOOP;
			}
		} while(errno != ENOENT);	// TODO: find another way to check if the object exists
		errno=0;
		dosync_arg->outf = fopen(fpath, "w");

		if(dosync_arg->outf == NULL) {
			printf_e("Error: Cannot open \"%s\" as file for writing: %s (errno: %i).\n", fpath, strerror(errno), errno);
			return errno;
		}

		setbuffer(dosync_arg->outf, buf, BUFSIZ);
		printf_ddd("Debug3: Created list-file \"%s\"\n", fpath);
	}

	g_hash_table_foreach(indexes_p->fpath2ei_coll_ht[queue_id], _sync_idle_dosync_collectedevents, dosync_arg);
	g_hash_table_remove_all(indexes_p->fpath2ei_coll_ht[queue_id]);

	if(options_p->listoutdir != NULL) {
		fclose(dosync_arg->outf);

		if(dosync_arg->evcount > 0) {
			if(options_p->flags[PTHREAD])
				return sync_exec_thread(sync_idle_dosync_collectedevents_cleanup, 
							options_p->actfpath, "synclist", options_p->label, fpath, NULL);
			else
				return sync_exec       (options_p->actfpath, "synclist", options_p->label, fpath, NULL);
		}
	}

	return 0;
}

int sync_idle_dosync_collectedevents(options_t *options_p, indexes_t *indexes_p) {
	struct dosync_arg dosync_arg;
	dosync_arg.evcount	= 0;
	dosync_arg.options_p 	= options_p;
	dosync_arg.indexes_p	= indexes_p;
	dosync_arg.outf		= NULL;
	time_t tm = time(NULL);

	int queue_id=0;
	while(queue_id < QUEUE_MAX) {
		int ret;
		ret = sync_idle_dosync_collectedevents_procqueue(queue_id, options_p, indexes_p, tm, &dosync_arg);
		if(ret) {
			printf_e("Error: Got error while processing queue #%i\n: %s (errno: %i).\n", queue_id, strerror(ret), ret);
			return ret;
		}

		queue_id++;
	}

	return 0;
}

int sync_idle(int notify_d, options_t *options_p, rule_t *rules_p, indexes_t *indexes_p) {
	int ret;

	ret=_sync_exec_idle();
	if(ret) return ret;

	sync_idle_dosync_collectedevents(options_p, indexes_p);
	return 0;
}

int sync_fanotify_loop(int fanotify_d, options_t *options_p, rule_t *rules_p, indexes_t *indexes_p) {
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
					sync_queuesync(fpath, 0, options_p, indexes_p);
					printf_dd("Debug2: Event %i on \"%s\".\n", metadata->mask, fpath);
					free(fpath);
				}
			}
			close(metadata->fd);
			metadata = FAN_EVENT_NEXT(metadata, len);
		}
		int ret;
		if((ret=sync_idle(fanotify_d, options_p, rules_p, indexes_p))) {
			printf_e("Error: got error while sync_idle(): %s (errno: %i).\n", strerror(ret), ret);
			return ret;
		}
	}
	return 0;
}

static inline int sync_inotify_wait(int inotify_d) {
	fd_set rfds;
	FD_ZERO(&rfds);
	FD_SET(inotify_d, &rfds);
	return select(FD_SETSIZE, &rfds, NULL, NULL, NULL);
}

void sync_inotify_handle_dosync(gpointer fpath_gp, gpointer evinfo_gp, gpointer arg_gp) {
	char *fpath		  = (char *)fpath_gp;
	eventinfo_t *evinfo	  = (eventinfo_t *)evinfo_gp;
	options_t *options_p 	  = ((struct dosync_arg *)arg_gp)->options_p;
	indexes_t *indexes_p 	  = ((struct dosync_arg *)arg_gp)->indexes_p;

	sync_queuesync(fpath, evinfo, options_p, indexes_p);

	return;
}

#define SYNC_INOTIFY_HANDLE_CONTINUE {\
	ptr += sizeof(struct inotify_event) + event->len;\
	count++;\
	continue;\
}

int sync_inotify_handle(int inotify_d, options_t *options_p, rule_t *rules_p, indexes_t *indexes_p) {
	char buf[BUFSIZ + 1];
	size_t r = read(inotify_d, buf, BUFSIZ);
	if(r <= 0) {
		printf_e("Error: Got error while reading events from inotify with read(): %s (errno: %i).\n", strerror(errno), errno);
		return -1;
	}

	g_hash_table_remove_all(indexes_p->fpath2ei_ht);	// Just in case.

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
		if(lstat64(fpathfull, &lstat)) {
			printf_dd("Debug2: Cannot lstat(\"%s\", lstat): %s (errno: %i). Seems, that the object disappeared.\n", fpathfull, strerror(errno), errno);
			if(event->mask & IN_ISDIR)
				st_mode = S_IFDIR;
			else
				st_mode = S_IFREG;
		} else
			st_mode = lstat.st_mode;

		ruleaction_t ruleaction = rules_check(fpathfull, st_mode, rules_p);

		if(ruleaction == RULE_REJECT)
			SYNC_INOTIFY_HANDLE_CONTINUE;

		if(event->mask & IN_ISDIR) {
			if(event->mask & (IN_CREATE|IN_MOVED_TO)) {			// Appeared
				int ret = sync_walk_notifymark(inotify_d, options_p, fpathfull, rules_p, indexes_p, _printf_dd);
				if(ret)
					printf_d("Debug: Seems, that directory \"%s\" disappeared, while trying to mark it.\n", fpathfull);
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
			evinfo->fsize  = lstat.st_size;
			evinfo->wd     = event->wd;
			isnew++;
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

int sync_inotify_loop(int inotify_d, options_t *options_p, rule_t *rules_p, indexes_t *indexes_p) {
	int state=1;
	state_p = &state;

	while(state != STATE_EXIT) {
		int events = sync_inotify_wait(inotify_d);
		switch(state) {
			case STATE_RUNNING:
				break;
			case STATE_REHASH:
				printf_e("Error: Rehash processing is not implemented, yet. Sorry :(.\n");
				state = STATE_RUNNING;
				continue;
			case STATE_TERM:
				state = STATE_EXIT;
			case STATE_EXIT:
				continue;
		}

		if(events == 0) {
			printf_dd("Debug2: sync_inotify_wait(%i) timed-out.\n", inotify_d);
			continue;	// Timeout
		}
		if(events  < 0) {
			printf_e("Error: Got error while waiting for event from inotify with select(): %s (errno: %i).\n", strerror(errno), errno);
			return errno;
		}

		int count=sync_inotify_handle(inotify_d, options_p, rules_p, indexes_p);
		if(count<=0) {
			printf_e("Error: Cannot handle with inotify events: %s (errno: %i).\n", strerror(errno), errno);
			return errno;
		}

		int ret;
		if((ret=sync_idle(inotify_d, options_p, rules_p, indexes_p))) {
			printf_e("Error: got error while sync_idle(): %s (errno: %i).\n", strerror(ret), ret);
			return ret;
		}
	}

	int ret;
	if((ret=sync_idle(inotify_d, options_p, rules_p, indexes_p))) {
		printf_e("Error: got error while sync_idle(): %s (errno: %i).\n", strerror(ret), ret);
		return ret;
	}
	return 0;
}

int sync_notify_loop(int notify_d, options_t *options_p, rule_t *rules_p, indexes_t *indexes_p) {
	switch(options_p->notifyengine) {
		case NE_FANOTIFY:
			return sync_fanotify_loop(notify_d, options_p, rules_p, indexes_p);
		case NE_INOTIFY:
			return sync_inotify_loop (notify_d, options_p, rules_p, indexes_p);
	}
	printf_e("Error: unknown notify-engine: %i\n", options_p->notifyengine);
	errno = EINVAL;
	return -1;
}

void sync_rehash(int signal) {
	if(state_p)
		*state_p = STATE_REHASH;
	return;
}

void sync_term(int signal) {
	if(state_p)
		*state_p = STATE_TERM;

	return;
}

int sync_run(options_t *options_p, rule_t *rules_p) {
	int ret, i;
	indexes_t indexes = {NULL};
	indexes.wd2fpath_ht      = g_hash_table_new_full(g_direct_hash, g_direct_equal, 0,    0);
	indexes.fpath2wd_ht      = g_hash_table_new_full(g_str_hash,    g_str_equal,    free, 0);
	indexes.fpath2ei_ht      = g_hash_table_new_full(g_str_hash,    g_str_equal,    free, free);
	i=0;
	while(i<QUEUE_MAX)
		indexes.fpath2ei_coll_ht[i++] = g_hash_table_new_full(g_str_hash,    g_str_equal,    free, free);

	if(options_p->listoutdir)
		srand(time(NULL));

	int notify_d = sync_notify_init(options_p);
	if(notify_d == -1) return errno;

	ret = sync_walk_notifymark(notify_d, options_p, options_p->watchdir, rules_p, &indexes, printf_e);
	if(ret) return ret;

	signal(SIGHUP,	sync_rehash);
	signal(SIGTERM,	sync_term);
	signal(SIGINT,	sync_term);

	ret = sync_notify_loop(notify_d, options_p, rules_p, &indexes);
	if(ret) return ret;

	// TODO: Do cleanup of watching points

	_sync_exec_cleanup();

	close(notify_d);
	g_hash_table_destroy(indexes.wd2fpath_ht);
	g_hash_table_destroy(indexes.fpath2wd_ht);
	g_hash_table_destroy(indexes.fpath2ei_ht);
	i=0;
	while(i<QUEUE_MAX)
		g_hash_table_destroy(indexes.fpath2ei_coll_ht[i++]);

	return 0;
}

