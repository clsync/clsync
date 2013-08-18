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

int sock			= -1;

options_t  *options_p		= NULL;
indexes_t  *indexes_p		= NULL;
pthread_t   pthread_cluster;

nodeinfo_t nodeinfo[MAXNODES]   = {{0}};

nodeinfo_t *nodeinfo_my		= NULL;
uint8_t	node_id_my		= NODEID_NOID;
unsigned int cluster_timeout	= 0;


/**
 * @brief 			Sends message to another nodes of the cluster.
 * 
 * @param[in]	clustercmd_p	Command structure pointer.
 *
 * @retval	zero 		Successfully send.
 * @retval	non-zero 	Got error, while sending.
 * 
 */

int cluster_send(clustercmd_t *clustercmd_p) {
	// Paranoid routines

#ifdef PARANOID
	if(clustercmd_p->cmd_id != CLUSTERCMDID_PING) {
		if(clustercmd_p->node_id != node_id_my) {
#ifdef VERYPARANOID
			printf_e("Error: cluster_send(): clustercmd_p->node_id != node_id_my (%i != %i). Exit.\n", clustercmd_p->node_id, node_id_my);
			return EINVAL;
#else
			printf_e("Warning: cluster_send(): clustercmd_p->node_id != node_id_my (%i != %i). Correcting.\n", clustercmd_p->node_id, node_id_my);
			clustercmd_p->node_id = node_id_my;
#endif
		}
	}
#endif

	// CODE HERE


	return 0;
}

/**
 * @brief 			Receives message from another nodes of the cluster.
 * 
 * @param[out]	clustercmd_p	Command structure pointer.
 * @param[i/o]	timeout		Pointer to timeout (in milliseconds). Timeout is assumed zero if the pointer is NULL. After waiting the event timeout value will be decreased on wasted time.
 * 
 * @retval	1		If there's new message.
 * @retval	0		If there's no new messages.
 * @retval	-1		If got error while receiving. The error-code is placed into "errno".
 * 
 */

int cluster_recv(clustercmd_t *clustercmd_p, unsigned int *timeout_p) {
	int timeout;

	// Getting the timeout
	timeout = (timeout_p == NULL ? 0 : *timeout_p);


	// CODE HERE


	// Setting the timeout
	if(timeout_p != NULL)
		*timeout_p = timeout;

	// Paranoid routines

#ifdef PARANOID
	if(clustercmd_p->node_id == node_id_my) {
#ifdef VERYPARANOID
		printf_e("Error: cluster_recv(): clustercmd_p->node_id != node_id_my (%i != %i). Exit.\n", clustercmd_p->node_id, node_id_my);
		return EINVAL;
#else
		printf_e("Warning: cluster_recv(): clustercmd_p->node_id != node_id_my (%i != %i). Ignoring the command.\n", clustercmd_p->node_id, node_id_my);
		clustercmd_p = NULL;
		return 0;
#endif
	}
#endif
	return 0;
}

extern int cluster_loop();
/**
 * @brief 			Initializes cluster subsystem.
 * 
 * @param[in] 	_options_p 	Pointer to "options" variable, defined in main().
 * @param[in] 	_indexes_p	Pointer to "indexes" variable, defined in sync_run().
 *
 * @retval	zero 		Successfully initialized.
 * @retval	non-zero 	Got error, while initializing.
 * 
 */

int cluster_init(options_t *_options_p, indexes_t *_indexes_p) {
	int ret;

	// Preventing double initializing
	if(options_p != NULL) {
		printf_e("Error: cluster_init(): cluster subsystem is already initialized.\n");
		return EALREADY;
	}

	// Initializing network routines
	sock = socket(AF_INET, SOCK_DGRAM, 0);

	int reuse = 1;
	if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,(char *)&reuse, sizeof(reuse)) < 0) {
		printf_e("Error: cluster_init(): Got error while setsockopt(): %s (errno: %i)\n", strerror(errno), errno);
		return errno;
	}

	struct sockaddr_in sa = {0};

	sa.sin_family		= AF_INET;
	sa.sin_port 		= htons(options_p->cluster_mcastipport);
	sa.sin_addr.s_addr	= INADDR_ANY;

	// Initializing global variables, pt. 1
	options_p	= _options_p;
	indexes_p	= _indexes_p;

	cluster_timeout	= options_p->cluster_timeout * 1000;

	// Getting my ID in the cluster
	clustercmd_t clustercmd;

	//	Trying to preserve my node_id after restart. :)
	clustercmd.cmd_id   = CLUSTERCMDID_GETMYID;
	clustercmd.data_len = options_p->cluster_nodename_len;
	clustercmd.data_p   = options_p->cluster_nodename;
	cluster_send(&clustercmd);

	int updatets = 0;
	unsigned int timeout = cluster_timeout;
	while((ret=cluster_recv(&clustercmd, &timeout)) && (timeout>0)) {

		// 	Exit if error
		if(ret == -1) {
			printf_e("Error: cluster_init(): Got error while cluster_recv(): %s (%i).\n", strerror(errno), errno);
			return errno;
		}

		// 	Somebody tryes to give us the cue about our node_id? Skipping if not.
		if(clustercmd.cmd_id != CLUSTERCMDID_SETID)
			continue;

		// 	Is this the most recent information? Skipping if not.
		clustercmd_setiddata_t *setiddata = clustercmd.data_p;
		if(!(setiddata->updatets > updatets))
			continue;

		// 	Is the node name length in message equals to our node name length? Skipping if not.
		uint32_t recv_nodename_len;
		recv_nodename_len = clustercmd.data_len - sizeof(*setiddata) + sizeof(char *);
		if(recv_nodename_len != options_p->cluster_nodename_len)
			continue;

		// 	Is the node name equals to ours? Skipping if not.
		if(memcmp(setiddata->node_name, options_p->cluster_nodename, recv_nodename_len))
			continue;

		// 	Seems, that somebody knows our node id, remembering it.
		node_id_my = setiddata->node_id;
		updatets   = setiddata->updatets;
	}

	//	Getting free node_id if nobody said us the certain value (see above).
	if(node_id_my == NODEID_NOID) {
		int i=0;
		while(i<MAXNODES) {
			if(nodeinfo[i].status == NODESTATUS_DOESNTEXIST) {
				node_id_my = i;
				break;
			}
			i++;
		}
	}

	//	If there's no free id-s, then exit :(
	if(node_id_my == NODEID_NOID) {
		printf_e("Error: Cannot find free node ID. Seems, that all %i ID-s is already busy.\n");
		return ENOMEM;
	}

	clustercmd.cmd_id   = CLUSTERCMDID_REGISTER;
	clustercmd.data_len = 1;
	clustercmd.data_p   = &node_id_my;
	cluster_send(&clustercmd);

	// Initializing global variables, pt. 2
	nodeinfo_my = &nodeinfo[node_id_my];

	nodeinfo_my->modtime_ht = g_hash_table_new_full(g_str_hash,	g_str_equal,	free, 0);

	// Running thread, that will process background communicating routines with another nodes.
	// The process is based on function cluster_loop() [let's use shorthand "cluster_loop()-thread"]
	ret = pthread_create(&pthread_cluster, NULL, (void *(*)(void *))cluster_loop, NULL);

	return ret;
}

/**
 * @brief 			(syncop) Sends signal to cluster_loop()-thread
 * 
 * @param[in] 	signal 		Signal number
 *
 * @retval	zero 		Successfully initialized
 * @retval	non-zero 	Got error, while initializing
 * 
 */

static inline int cluster_signal(int signal) {
	return pthread_kill(pthread_cluster, signal);
}


/**
 * @brief 			Antagonist of cluster_init() function. Kills cluster_loop()-thread and cleaning up
 * 
 * @retval	zero 		Successfully initialized
 * @retval	non-zero 	Got error, while initializing
 * 
 */

int cluster_deinit() {
	int ret = 0;

	cluster_signal(SIGTERM);

	ret = pthread_join(pthread_cluster, NULL);

	g_hash_table_destroy(nodeinfo_my->modtime_ht);

	return ret;
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
 * @brief 			Processes background communicating routines with another nodes. cluster_init() function create a thread for this function.
 * 
 * @retval	zero 		Successfully initialized
 * @retval	non-zero 	Got error, while initializing
 * 
 */

int cluster_loop() {
	sigset_t sigset_cluster;

	// Ignoring SIGINT signal

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
	// "modtime" is incorrent name-part of function. Actually it updates "change time" (man 2 lstat64).
	int ret;

	// Getting directory information (including "change time" aka "st_ctime")
	struct stat64 stat64;
	ret=lstat64(dirpath, &stat64);
	if(ret) {
		printf_e("Error: cluster_modtime_update() cannot lstat64() on \"%s\": %s (errno: %i)\n", dirpath, strerror(errno), errno);
		return errno;
	}

	// Updating "st_ctime" information. g_hash_table_replace() will replace existent information about the directory or create it if it doesn't exist.
	g_hash_table_replace(nodeinfo_my->modtime_ht, strdup(dirpath), GINT_TO_POINTER(stat64.st_ctime));

	// Why I'm using "st_ctime" instead of "st_mtime"? Because "st_ctime" also updates on updating inode information.
	
	return 0;
}


/**
 * @brief 			(syncop) Exchanging with "modtime_ht"-s to be able to compare them.
 * 
 * @retval	zero 		Successfully initialized
 * @retval	non-zero 	Got error, while initializing
 * 
 */

int cluster_modtime_exchange() {

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
	cluster_modtime_exchange();

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

