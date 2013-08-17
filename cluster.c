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
#include "cluster.h"
#include "sync.h"
#include "output.h"
#include "malloc.h"

options_t *options_p=NULL;
indexes_t *indexes_p=NULL;
pthread_t pthread_cluster;

extern int cluster_loop();

int cluster_init(options_t *_options_p, indexes_t *_indexes_p) {
	int ret;

	if(options_p != NULL) {
		printf_e("Error: cluster_init(): cluster subsystem is already initialized.\n");
		return EALREADY;
	}

	options_p = _options_p;
	indexes_p = _indexes_p;

	ret = pthread_create(&pthread_cluster, NULL, (void *(*)(void *))cluster_loop, NULL);

	return ret;
}

inline int cluster_signal(int signal) {
	return pthread_kill(pthread_cluster, signal);
}

int cluster_deinit() {
	cluster_signal(SIGTERM);

	return pthread_join(pthread_cluster, NULL);
}


int cluster_lock(const char *fpath) {
	return 0;
}

int cluster_lock_byindexes() {
	return 0;
}

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

int cluster_loop() {
	sigset_t sigset_cluster;
	sigemptyset(&sigset_cluster);
	sigaddset(&sigset_cluster, SIGINT);
	CLUSTER_LOOP_CHECK(pthread_sigmask(SIG_BLOCK, &sigset_cluster, NULL));

	sigemptyset(&sigset_cluster);
	sigaddset(&sigset_cluster, SIGTERM);
	CLUSTER_LOOP_CHECK(pthread_sigmask(SIG_UNBLOCK, &sigset_cluster, NULL));

	while(1) {
		if(sigpending(&sigset_cluster))
			if(sigismember(&sigset_cluster, SIGTERM))
				break;

		// LISTENING
	}

	return 0;
}


