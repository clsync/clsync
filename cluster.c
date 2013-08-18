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

/*
    Hello, dear developer.

    Cluster technologies are almost always very difficult. So I'll try to
    fill this code with comments. Enjoy ;)

                                                           -- 0x8E30679C
 */


#include "common.h"
#include "cluster.h"
#include "sync.h"
#include "output.h"
#include "malloc.h"

// Global variables. They will be initialized in cluster_init()

options_t *options_p=NULL;
indexes_t *indexes_p=NULL;
pthread_t pthread_cluster;


extern int cluster_loop();
/**
 * @brief 			Initializes cluster subsystem
 * 
 * @param[in] 	_options_p 	Pointer to "options" variable, defined in main()
 * @param[in] 	_indexes_p	Pointer to "indexes" variable, defined in sync_run()
 *
 * @retval	zero 		Successfully initialized
 * @retval	non-zero 	Got error, while initializing
 * 
 */

int cluster_init(options_t *_options_p, indexes_t *_indexes_p) {
	int ret;

	// Preventing double initializing
	if(options_p != NULL) {
		printf_e("Error: cluster_init(): cluster subsystem is already initialized.\n");
		return EALREADY;
	}

	// Initializing global variables
	options_p = _options_p;
	indexes_p = _indexes_p;

	// Running thread, that will process incoming traffic from another nodes of the cluster.
	// The process is based on function cluster_loop()
	ret = pthread_create(&pthread_cluster, NULL, (void *(*)(void *))cluster_loop, NULL);

	return ret;
}

/**
 * @brief 			(syncop) Sends signal to thread that is processing incoming traffic from another nodes of the cluster [thread: cluster_loop()]
 * 
 * @param[in] 	signal 		Signal number
 *
 * @retval	zero 		Successfully initialized
 * @retval	non-zero 	Got error, while initializing
 * 
 */

inline int cluster_signal(int signal) {
	return pthread_kill(pthread_cluster, signal);
}


/**
 * @brief 			Antagonist of cluster_init() function. Kills cluster_loop()-thread.
 * 
 * @retval	zero 		Successfully initialized
 * @retval	non-zero 	Got error, while initializing
 * 
 */

int cluster_deinit() {
	cluster_signal(SIGTERM);

	return pthread_join(pthread_cluster, NULL);
}


/**
 * @brief 			(syncop) Forces anothes nodes to ignore events about the file or directory
 * 
 * @param[in] 	fpath 		Path to the file or directory
 * 
 * @retval	zero 		Successfully initialized
 * @retval	non-zero 	Got error, while initializing
 * 
 */

int cluster_lock(const char *fpath) {
	return 0;
}


/**
 * @brief 			(syncop) Forces anothes nodes to ignore events about all files and directories listed in queues of "indexes_p"
 * 
 * @retval	zero 		Successfully initialized
 * @retval	non-zero 	Got error, while initializing
 * 
 */

int cluster_lock_byindexes() {
	return 0;
}


/**
 * @brief 			(syncop) Returns events-handling on another nodes about all files and directories, locked by cluster_lock() and cluster_lock_byindexes() from this node
 * 
 * @retval	zero 		Successfully initialized
 * @retval	non-zero 	Got error, while initializing
 * 
 */

int cluster_unlock_all() {
	return 0;
}


#define CLUSTER_LOOP_CHECK(a) {\
	int ret = a;\
	if(ret) {\
		sync_term(ret);\
		return ret;\
	}\
}

/**
 * @brief 			Processes incoming traffic from another nodes in loop. cluster_init() function create a thread for this function.
 * 
 * @retval	zero 		Successfully initialized
 * @retval	non-zero 	Got error, while initializing
 * 
 */

int cluster_loop() {

	// Ignoring SIGINT signal

	sigset_t sigset_cluster;
	sigemptyset(&sigset_cluster);
	sigaddset(&sigset_cluster, SIGINT);
	CLUSTER_LOOP_CHECK(pthread_sigmask(SIG_BLOCK, &sigset_cluster, NULL));

	// Don't ignoring SIGTERM signal

	sigemptyset(&sigset_cluster);
	sigaddset(&sigset_cluster, SIGTERM);
	CLUSTER_LOOP_CHECK(pthread_sigmask(SIG_UNBLOCK, &sigset_cluster, NULL));

	// Starting the loop

	while(1) {
		// Breaking the loop, if there's SIGTERM signal for this thread
		if(sigpending(&sigset_cluster))
			if(sigismember(&sigset_cluster, SIGTERM))
				break;

		// LISTENING
	}

	return 0;
#ifdef DOXYGEN
	sync_term(0);
#endif
}


/**
 * @brief 			Updating information about modification time of a directory.
 * 
 * @param[in] 	dirpath		Path to the directory
 * 
 * @retval	zero 		Successfully initialized
 * @retval	non-zero 	Got error, while initializing
 * 
 */

int cluster_modtime_update(const char *dirpath) {
	
	return 0;
}


/**
 * @brief 			(syncop) Syncing file tree with another nodes with using of directories' modification time as a recent-detector.
 * 
 * @param[in] 	dirpath		Path to the directory
 * 
 * @retval	zero 		Successfully initialized
 * @retval	non-zero 	Got error, while initializing
 * 
 */

int cluster_initialsync() {
	return 0;
}


/**
 * @brief 			(syncop) "Captures" right to update the file or directory to another nodes. It just removes events about the file of directory from another nodes
 * 
 * @param[in] 	dirpath		Path to the directory
 * 
 * @retval	zero 		Successfully initialized
 * @retval	non-zero 	Got error, while initializing
 * 
 */

int cluster_capture(const char *path) {
	return 0;
}

