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

    Also you can ask me directly by e-mail or IRC, if something seems too
    hard.

                                                           -- 0x8E30679C
 */

#ifdef CLUSTER_SUPPORT

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
uint8_t node_ids[MAXNODES]	= {0};
unsigned int cluster_timeout	= 0;
uint8_t node_count		= 0;
uint8_t node_online		= 0;

cluster_recvproc_funct_t recvproc_funct[COUNT_CLUSTERCMDID] = {NULL};

window_t window = {0};


/**
 * @brief 			Adds command (message) to window buffer
 * 
 * @param[in]	clustercmd_p	Pointer to cluster cmd to put into window
 * 
 * @retval	zero		Successful
 * @retval	non-zero	If got error while deleting the message. The error-code is placed into returned value.
 * 
 */

static inline int clustercmd_window_add(clustercmd_t *clustercmd_p) {
	/*
	struct window_occupied_sides {
		size_t	left;
		size_t	right;
	};
	typedef struct window_occupied_sides window_occupied_sides_t;
	struct window {
		unsigned int		  size;			// Allocated cells
		unsigned int		  packets;		// Packets are waiting for ACK-s
		unsigned int		  idstack_len;		// Count of stacked cells for future use
		unsigned int		 *idstack;		// Stack of cells for future use
		char			 *idstacked;		// Assoc-array of cells' id-s (aka window_id) to determine is the cell stacked
		unsigned int		  occupied_len;		// Count of cells with packets and stacked cells for future use
		unsigned int		 *occupied_id;		// Array of cells' id-s with packets and stacked cells for future use
		window_occupied_sides_t	 *occupied_sides;	// Array of structures with coordinates in buffer of occupied space by cell ida (aka window_id)
		GHashTable		 *serial2waitack_ht;	// Hash-table: clustercmd.h.serial ->  clustercmdwaitack
		size_t			  buf_size;		// Allocated space of the buffer
		char 			 *buf;			// Pointer to the buffer
	};
	struct clustercmdwaitack {
		unsigned int	window_id;
		char 		ack_from[MAXNODES];
		uint8_t 	ack_count;
		clustercmd_t 	cmd;
	};
	*/

	// Checking if there enough window cells allocated
	if(window.packets >= window.size) {
		window.size 		+= ALLOC_PORTION;

#		define CXREALLOC(a, size) \
			(typeof(a))xrealloc((char *)(a), (size_t)(size) * sizeof(*(a)))
	
		window.idstack	      = CXREALLOC(window.idstack,	 window.size);
		window.idstacked      = CXREALLOC(window.idstacked,	 window.size);
		window.occupied_id    = CXREALLOC(window.occupied_id,	 window.size);
		window.occupied_sides = CXREALLOC(window.occupied_sides, window.size);
#		undef CXREALLOC
	}

	// Calculating required memory space in buffer for the message
	size_t required_space = sizeof(clustercmdwaitackhdr_t) + sizeof(clustercmdhdr_t) + clustercmd_p->h.data_len;

	// Searching business boundaries in the window buffer
	size_t occupied_left = SIZE_MAX, occupied_right=0;
	int i;
	i = 0;
	while(i < window.packets) {
		unsigned int window_id;
		window_id  = window.occupied_id[i];

		occupied_left  = MIN(occupied_left,  window.occupied_sides[window_id].left);
		occupied_right = MAX(occupied_right, window.occupied_sides[window_id].right);
	}

	printf_ddd("Debug3: clustercmd_window_add(): w.size == %u, b_left == %u; b_right == %u; w.buf_size == %u; r_space == %u\n",
		window.size, occupied_left, occupied_right, window.buf_size, required_space);

	// Trying to find a space in the buffer to place message
	size_t buf_coordinate = SIZE_MAX;
	if(window.packets) {
		// Free space from left  (start of buffer)
		size_t free_left  = occupied_left;
		// Free space from right (end of buffer)
		size_t free_right = window.buf_size - occupied_right;

		if(free_left  > required_space)
			buf_coordinate = free_left - required_space;
		else
		if(free_right > required_space)
			buf_coordinate = occupied_right;
		else {	// Not enough space in the window buffer;
			window.buf_size += MAX(CLUSTER_WINDOW_BUFSIZE_PORTION, required_space);
			window.buf	 = xrealloc(window.buf, window.buf_size);
			buf_coordinate = occupied_right;
		}
		printf_ddd("Debug3: clustercmd_window_add(): f_left == %u; f_right == %u; b_coord == %u; w.buf_size == %u",
			free_left, free_right, buf_coordinate, window.buf_size);
	}

	if(window.idstack_len) {
		// Using stacked window_id
		unsigned int window_id;
		(void)window_id;	// Anti-warning
		window.occupied_sides[window_id].left  = buf_coordinate;
		window.occupied_sides[window_id].right = buf_coordinate + required_space;
	} else {
		// If there's no stacked window_id-s, creating new

		
	}

	window.packets++;

	

	g_hash_table_remove(window.serial2waitack_ht, GINT_TO_POINTER(clustercmd_p->h.serial));

	return 0;
}


/**
 * @brief 			Removes command (message) from window buffer
 * 
 * @param[in]	waitack_p	Pointer to waitack structure of the command (message)
 * 
 * @retval	zero		Successful
 * @retval	non-zero	If got error while deleting the message. The error-code is placed into returned value.
 * 
 */

static inline int clustercmd_window_del(clustercmdwaitack_t *waitack_p) {
#ifdef PARANOID
	if(!window.size) {
		printf_e("Error: clustercmd_window_del(): window is not allocated.");
		return EINVAL;
	}
	if(!window.packets) {
		printf_e("Error: clustercmd_window_del(): there already no packets in the window.");
		return EINVAL;
	}
#endif

	/*
	struct window {
		unsigned int	  size;
		unsigned int	  packets;
		unsigned int	  used;
		unsigned int	  idstack_len;
		unsigned int	 *idstack;
		char		 *idstacked;
		size_t		 *occupied[WINDOW_SIDES];
		GHashTable	 *serial2waitack_ht;
		size_t		  buf_size;
		char 		 *buf;
	};
	struct clustercmdwaitack {
		unsigned int	window_id;
		char 		ack_from[MAXNODES];
		uint8_t 	ack_count;
		clustercmd_t 	cmd;
	};
	*/

	unsigned int window_id = waitack_p->h.window_id;

	g_hash_table_remove(window.serial2waitack_ht, GINT_TO_POINTER(waitack_p->cmd.h.serial));
	window.packets--;

	if(window_id == (window.occupied_len-1)) {
		window.occupied_len--;
		while(window.idstacked[window.occupied_len-1]) {
			window.idstacked[--window.occupied_len] = 0;
			window.idstack_len--;
		}
		return 0;
	}

	window.idstack[window.idstack_len++] = window_id;

	return 0;
}


/**
 * @brief 			Calculates CRC32 for clustercmd
 * 
 * @param[in]	clustercmd_p	Pointer to clustercmd
 * 
 * @retval	uint32_t	CRC32 value of clustecmd
 * 
 */

int clustercmd_crc32_calc(clustercmd_t *clustercmd_p) {
	return 0;
}


/**
 * @brief 			Changes information about node's status in nodeinfo[] and updates connected information.
 * 
 * @param[in]	node_id		node_id of the node.
 * @param[in]	node_status	New node status.
 * 
 * @retval	zero		Successful
 * @retval	non-zero	If got error while changing the status. The error-code is placed into returned value.
 * 
 */

int node_status_change(uint8_t node_id, uint8_t node_status) {
	uint8_t node_status_old = nodeinfo[node_id].status;
	nodeinfo_t *nodeinfo_p = &nodeinfo[node_id];

	if((node_status == NODESTATUS_DOESNTEXIST) && (node_status_old != NODESTATUS_DOESNTEXIST)) {
		node_count--;

		node_ids[nodeinfo_p->num] = node_ids[node_count];
		g_hash_table_destroy(nodeinfo_p->modtime_ht);
#ifdef VERYPARANOID
		memset(nodeinfo_p, 0, sizeof(*nodeinfo_p));
#endif
		return 0;
	}

	if(node_status == node_status_old)
		return 0;


	switch(node_status_old) {
		case NODESTATUS_DOESNTEXIST:
			nodeinfo_p->id  = node_id;
			nodeinfo_p->num = node_count;
			node_ids[node_count] = node_id;

			node_count++;
#ifdef PARANOID
			if(node_status == NODESTATUS_OFFLINE)
				break;
#endif
		case NODESTATUS_OFFLINE:
			node_online++;
			break;
		default:
			if(node_status == NODESTATUS_OFFLINE)
				node_online--;
			break;
	}

	nodeinfo[node_id].status = node_status;

	return 0;
}


/**
 * @brief 			Sets message processing functions for cluster_recv_proc() function for specified command type
 * 
 * @param[in]	cmd_id		The command type
 * @param[in]	procfunct	The processing function for messages with specified cmd_id
 * 
 * @retval	zero		Successful
 * @retval	non-zero	If got error while setting processing function. The error-code is placed into returned value.
 * 
 */

static inline int cluster_recv_proc_set(clustercmd_id_t cmd_id, cluster_recvproc_funct_t procfunct) {
	recvproc_funct[cmd_id] = procfunct;

	return 0;
}


/**
 * @brief 			Receives message from another nodes of the cluster.
 * 
 * @param[i/o]	clustercmd_pp	Pointer to command structure pointer. It will be re-allocated every time when size is not enough.
 * @param[i/o]	size_p		Pointer to size of allocated memory for command structure (see related to clustercmd_pp). The value of size will be updated on re-allocs.
 * @param[i/o]	timeout_p	Pointer to timeout (in milliseconds). Timeout is assumed zero if the pointer is NULL. After waiting the event timeout value will be decreased on elapsed time.
 * 
 * @retval	1		If there's new message.
 * @retval	0		If there's no new messages.
 * @retval	-1		If got error while receiving. The error-code is placed into "errno".
 * 
 */

int cluster_recv(clustercmd_t **clustercmd_pp, size_t *size_p, unsigned int *timeout_p) {
	int timeout;
	size_t size;

#ifdef PARANOID
	// Checking arguments

	if((clustercmd_pp == NULL) || (size_p == NULL)) {
		printf_e("Error: cluster_recv() clustercmd_p or size_p is equals to NULL.\n");
		return EINVAL;
	}

	if((*clustercmd_pp != NULL) && (*size_p == 0)) {
		printf_e("Error: cluster_recv(): *clustercmd_pp != NULL && *size_p == 0.\n");
		return EINVAL;
	}

	if((*clustercmd_pp == NULL) && (*size_p != 0)) {
		printf_e("Error: cluster_recv(): *clustercmd_pp == NULL && *size_p != 0.\n");
		return EINVAL;
	}
#endif

	// Getting the timeout
	timeout = (timeout_p == NULL ? 0 : *timeout_p);

	// Getting size
	if(*size_p) {
		size = *size_p;
	} else {
		size = BUFSIZ;
		*clustercmd_pp = (clustercmd_t *)xmalloc(size);
	}

	// Getting clustercmd_p
	clustercmd_t *clustercmd_p = *clustercmd_pp;


	// CODE HERE
	if(clustercmd_p->h.src_node_id >= MAXNODES) {
		printf_e("Warning: cluster_recv(): Invalid h.src_node_id: %i >= "XTOSTR(MAXNODES)"\n", clustercmd_p->h.src_node_id);
	}
	if(clustercmd_p->h.dst_node_id >= MAXNODES) {
		printf_e("Warning: cluster_recv(): Invalid h.dst_node_id: %i >= "XTOSTR(MAXNODES)"\n", clustercmd_p->h.dst_node_id);
	}


	printf_ddd("Debug3: cluster_recv(): Received: {h.dst_node_id: %u, h.src_node_id: %u, cmd_id: %u, crc32: %u, data_len: %u}, timeout: %u -> %u\n",
		clustercmd_p->h.dst_node_id, clustercmd_p->h.src_node_id, clustercmd_p->h.cmd_id, clustercmd_p->h.crc32, clustercmd_p->h.data_len, *timeout_p, timeout);

	// Setting the timeout
	if(timeout_p != NULL)
		*timeout_p = timeout;

	// Setting the size
	*size_p = size;

	uint32_t crc32 = clustercmd_crc32_calc(clustercmd_p);
	if(crc32 != clustercmd_p->h.crc32) {
//		CLUSTER_ALLOCA(clustercmd_p, )

		printf_d("Debug: cluster_recv(): CRC32 mismatch: clustercmd_p->crc32 != clustercmd_crc32_calc(clustercmd_p): %p != %p.\n", (void*)(long)clustercmd_p->h.crc32, (void*)(long)crc32);
//		cluster_send
	}

	// Paranoid routines
	//	The message from us? Something wrong if it is.
#ifdef PARANOID
	if(clustercmd_p->h.src_node_id == node_id_my) {
#ifdef VERYPARANOID
		printf_e("Error: cluster_recv(): clustercmd_p->h.src_node_id == node_id_my (%i != %i). Exit.\n", clustercmd_p->h.src_node_id, node_id_my);
		return EINVAL;
#else
		printf_e("Warning: cluster_recv(): clustercmd_p->h.src_node_id == node_id_my (%i != %i). Ignoring the command.\n", clustercmd_p->h.src_node_id, node_id_my);
		clustercmd_p = NULL;
		return 0;
#endif
	}
#endif
	return 0;
}


/**
 * @brief 			(hsyncop) Reads messages for time "_timeout" and proceeding them to recvproc_funct[] functions
 * 
 * @param[in]	_timeout	How long to wait messages (totally)
 * 
 * @retval	zero		Successful
 * @retval	non-zero	If got error while reading or processing messages. The error-code is placed into returned value.
 * 
 */

int cluster_recv_proc(unsigned int _timeout) {
	int ret;
	clustercmd_t *clustercmd_p=NULL;
	size_t size=0;
	unsigned int timeout = _timeout;
	while((ret=cluster_recv(&clustercmd_p, &size, &timeout))) {
		// Exit if error
		if(ret == -1) {
			printf_e("Error: cluster_recv_proc(): Got error while cluster_recv(): %s (%i).\n", strerror(errno), errno);
			return errno;
		}

		// If we have appropriate callback function, then call it! :)
		if(recvproc_funct[clustercmd_p->h.cmd_id])
			if((ret=recvproc_funct[clustercmd_p->h.cmd_id](clustercmd_p))) {
				printf_e("Error: cluster_recv_proc(): Got error from recvproc_funct[%i]: %s (%i)\n", clustercmd_p->h.cmd_id, strerror(ret), ret);
				return ret;
			}
	}
	free(clustercmd_p);

	return 0;
}


/**
 * @brief 			recvproc-function for ACK-messages
 * 
 * @param[in] 	clustercmd_p 	Pointer to clustercmd
 * @param[in] 	arg_p		Pointer to argument
 *
 * @retval	zero 		Successfully initialized.
 * @retval	non-zero 	Got error, while initializing.
 * 
 */

static int cluster_recvproc_ack(clustercmd_t *clustercmd_p) {

	uint32_t cmd_serial_ack = clustercmd_p->data_ack.serial;

	clustercmdwaitack_t *waitack_p = (clustercmdwaitack_t *)g_hash_table_lookup(window.serial2waitack_ht, GINT_TO_POINTER(cmd_serial_ack));

	if(waitack_p == NULL)
		return 0;

	uint8_t node_id_from = clustercmd_p->h.src_node_id;

	if(! waitack_p->h.ack_from[node_id_from]) {
		waitack_p->h.ack_count++;
		waitack_p->h.ack_from[node_id_from]++;

		if(waitack_p->h.ack_count == node_count)
			clustercmd_window_del(waitack_p);
	}

	return 0;
}


/**
 * @brief 			Sets message processing functions for cluster_recv_proc() function for specified command type
 * 
 * @param[in]	cmd_id		The command type
 * @param[in]	procfunct	The processing function for messages with specified cmd_id
 * 
 * @retval	zero		Successful
 * @retval	non-zero	If got error while setting processing function. The error-code is placed into returned value.
 * 
 */

int cluster_recv_proc_init() {
	window.serial2waitack_ht = g_hash_table_new_full(g_direct_hash, g_direct_equal, 0, 0);

	cluster_recv_proc_set(CLUSTERCMDID_ACK, cluster_recvproc_ack);
	return 0;
}


/**
 * @brief 			Antagonist of cluster_recv_proc_init() function. Freeing everything what was allocated in cluster_recv_proc_init()
 * 
 * @retval	zero 		Successfully initialized
 * @retval	non-zero 	Got error, while initializing
 * 
 */

int cluster_recv_proc_deinit() {

	if(window.serial2waitack_ht != NULL)
		g_hash_table_destroy(window.serial2waitack_ht);

	if(window.buf_size) {
#ifdef PARANOID
		if(window.buf == NULL) {
			printf_e("Error: cluster_recv_proc_deinit(): window_buf_size != 0, but window_buf == NULL.\n");
		} else
#endif
		free(window.buf);
	}

	return 0;
}


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
	clustercmd_p->h.src_node_id = node_id_my;

	// CODE HERE

	printf_ddd("Debug3: cluster_send(): Sending: {h.dst_node_id: %u, h.src_node_id: %u, cmd_id: %u, crc32: %u, data_len: %u}\n",
		clustercmd_p->h.dst_node_id, clustercmd_p->h.src_node_id, clustercmd_p->h.cmd_id, clustercmd_p->h.crc32, clustercmd_p->h.data_len);

	return 0;
}


/**
 * @brief 			(syncop) Sends message to another nodes of the cluster and waits for ACK-answers. (with skipping all other packets)
 * 
 * @param[in]	clustercmd_p	Command structure pointer.
 *
 * @retval	zero 		Successfully send.
 * @retval	non-zero 	Got error, while sending.
 * 
 * /

int cluster_send_ack(clustercmd_t *clustercmd_p) {
	uint32_t cmd_serial = clustercmd_p->serial;

	// Sending the message
	int ret = cluster_send(clustercmd_p);
	if(ret) {
		printf_e("Error: cluster_send_ack(): Got error from cluster_send(): %s (errno %i).\n", strerror(ret), ret);
		return ret;
	}

	// Waiting for ACK-messages from all registered nodes
	{
		clustercmd_t *clustercmd_p=NULL;
		size_t size=0;
		unsigned int timeout = cluster_timeout;
		while((ret=cluster_recv(&clustercmd_p, &size, &timeout)) && (timeout>0)) {
			// 	Skipping not ACK-messages.
			CLUSTER_LOOP_EXPECTCMD(clustercmd_p, CLUSTERCMDID_ACK, ret);

			// 	Is this an acknowledge packet for us? Skipping if not.
			clustercmd_ack_t *data_ack_p = &clustercmd_p->data_ack;
			if(clustercmd_p->h.dst_node_id != node_id_my)
				continue;

			// 	Is this acknowledge packet about the commend we sent? Skipping if not.
			if(data_ack_p->serial != cmd_serial)
				continue;

			
		}
		free(clustercmd_p);
	}

	return 0;
}
*/

/**
 * @brief 			recvproc-function for setid-messages
 * 
 * @param[in] 	clustercmd_p 	Pointer to clustercmd
 * @param[in] 	arg_p		Pointer to argument
 *
 * @retval	zero 		Successfully initialized.
 * @retval	non-zero 	Got error, while initializing.
 * 
 */

static int cluster_recvproc_setid(clustercmd_t *clustercmd_p) {
	static time_t updatets = 0;

	// 	Is this the most recent information? Skipping if not.
	clustercmd_setiddata_t *data_setid_p = &clustercmd_p->data_setid;
	if(!(data_setid_p->updatets > updatets))
		return 0;

	// 	Is the node name length in message equals to our node name length? Skipping if not.
	uint32_t recv_nodename_len;
	recv_nodename_len = CLUSTER_RESTDATALEN(clustercmd_p, clustercmd_setiddata_t);
	if(recv_nodename_len != options_p->cluster_nodename_len)
		return 0;

	// 	Is the node name equals to ours? Skipping if not.
	if(memcmp(data_setid_p->node_name, options_p->cluster_nodename, recv_nodename_len))
		return 0;

	//	Remembering the node that answered us
	node_status_change(clustercmd_p->h.src_node_id, NODESTATUS_SEEMSONLINE);

	// 	Seems, that somebody knows our node id, remembering it.
	node_id_my  = clustercmd_p->h.dst_node_id;
	updatets    = data_setid_p->updatets;

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
	(void)sa;	// Anti-warning

	sa.sin_family		= AF_INET;
	sa.sin_port 		= htons(options_p->cluster_mcastipport);
	sa.sin_addr.s_addr	= INADDR_ANY;

	// Initializing global variables, pt. 1
	options_p	= _options_p;
	indexes_p	= _indexes_p;

	cluster_timeout	= options_p->cluster_timeout * 1000;

	// Initializing a cluster_read_proc() with cluster_read_proc_init()
	cluster_recv_proc_init();

	// Getting my ID in the cluster

	//	Trying to preserve my node_id after restart. :)
	//	Asking another nodes about my previous node_id
	{
		clustercmd_t *clustercmd_p = CLUSTER_ALLOCA(clustercmd_getmyid_t, options_p->cluster_nodename_len);
		memcpy(clustercmd_p->data_getmyid.node_name, options_p->cluster_nodename, clustercmd_p->h.data_len+1);

		clustercmd_p->h.cmd_id = CLUSTERCMDID_GETMYID;
		cluster_send(clustercmd_p);
	}

	//	Processing answers
	cluster_recv_proc_set(CLUSTERCMDID_SETID, cluster_recvproc_setid);

	if((ret=cluster_recv_proc(cluster_timeout)))
		return ret;

	printf_ddd("Debug3: cluster_init(): After communicating with others, my node_id is %i.\n", node_id_my);

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
		printf_ddd("Debug3: cluster_init(): I was have to set my node_id to %i.\n", node_id_my);
	}

	//	If there's no free id-s, then exit :(
	if(node_id_my == NODEID_NOID) {
		printf_e("Error: Cannot find free node ID. Seems, that all %i ID-s are already occupied.\n");
		return ENOMEM;
	}

	// Registering in the cluster

	// 	Sending registration information
	node_status_change(node_id_my, NODESTATUS_SEEMSONLINE);
	{
		clustercmd_t *clustercmd_p = CLUSTER_ALLOCA(clustercmd_register_t, options_p->cluster_nodename_len);
		clustercmd_register_t *data_register_p = &clustercmd_p->data_register;

		memcpy(data_register_p->node_name, options_p->cluster_nodename, options_p->cluster_nodename_len+1);

		clustercmd_p->h.cmd_id = CLUSTERCMDID_REGISTER;
		cluster_send(clustercmd_p);
	}

	// 	Getting answers
	if((ret=cluster_recv_proc(cluster_timeout)))
		return ret;

	node_status_change(node_id_my, NODESTATUS_ONLINE);

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

	cluster_recv_proc_deinit();

#ifdef VERYPARANOID
	int i=0;
#endif
	while(node_count) {
#ifdef VERYPARANOID
		if(i++ > NODES_MAX) {
			printf_e("Error: cluster_deinit() looped. Forcing break.");
			break;
		}
#endif
		node_status_change(0, NODESTATUS_DOESNTEXIST);
	}

#ifdef VERYPARANOID
	memset(node_info, 0, sizeof(node_info));
	node_count  = 0;
	node_online = 0;
	node_id_my  = NODEID_NOID;
#endif

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
 * @param[in]	path		Canonized path to updated file/dir
 * @param[in]	dirlevel	Directory level provided by fts (man 3 fts)
 * @param[in]	st_mode		st_mode value to detect is it directory or not (S_IFDIR or not)
 * 
 * @retval	zero 		Successfully initialized
 * @retval	non-zero 	Got error, while initializing
 * 
 */

int cluster_modtime_update(const char *path, short int dirlevel, mode_t st_mode) {
	// "modtime" is incorrent name-part of function. Actually it updates "change time" (man 2 lstat64).
	int ret;

	// Getting relative directory level (depth)
	short int dirlevel_rel = dirlevel - options_p->watchdir_dirlevel;

	if((st_mode & S_IFMT) == S_IFDIR)
		dirlevel_rel++;

	// Don't remembering information about directories with level beyond the limits
	if((dirlevel_rel > options_p->cluster_scan_dl_max) || (dirlevel_rel < options_p->cluster_hash_dl_min))
		return 0;


	// Getting directory/file-'s information (including "change time" aka "st_ctime")
	struct stat64 stat64;
	ret=lstat64(path, &stat64);
	if(ret) {
		printf_e("Error: cluster_modtime_update() cannot lstat64() on \"%s\": %s (errno: %i)\n", path, strerror(errno), errno);
		return errno;
	}

	// Getting absolute directory path
	const char *dirpath;
	if((st_mode & S_IFMT) == S_IFDIR) {
		dirpath = path;
	} else {
		char *path_dup = strdup(path);
		dirpath = (const char *)dirname(path_dup);
		free(path_dup);
	}

	// Getting relative directory path
	//	Initializing
	size_t  dirpath_len   = strlen(dirpath);
	char   *dirpath_rel_p = xmalloc(dirpath_len+1);
	char   *dirpath_rel   = dirpath_rel_p;

	const char *dirpath_rel_full     = &dirpath[options_p->watchdirlen];
	size_t      dirpath_rel_full_len = dirpath_len - options_p->watchdirlen;

	// 	Getting coodinate of the end (directory path is already canonized, so we can simply count number of slashes to get directory level)
	int     slashcount=0;
	size_t  dirpath_rel_end=0;
	while(dirpath_rel_full[dirpath_rel_end] && (dirpath_rel_end < dirpath_rel_full_len)) {
		if(dirpath_rel_full[dirpath_rel_end] == '/') {
			slashcount++;
			if(slashcount >= options_p->cluster_hash_dl_max)
				break;
		}
		dirpath_rel_end++;
	}

	//	Copy the required part of path to dirpath_rel
	memcpy(dirpath_rel, dirpath_rel_full, dirpath_rel_end);

	
	// Updating "st_ctime" information. We should check current value for this directory and update it only if it less or not set.
	//	Checking current value
	char toupdate = 0;
	gpointer ctime_gp = g_hash_table_lookup(nodeinfo_my->modtime_ht, dirpath_rel);
	if(ctime_gp == NULL)
		toupdate++;
	else if(GPOINTER_TO_INT(ctime_gp) < stat64.st_ctime)
		toupdate++;

	//	g_hash_table_replace() will replace existent information about the directory or create it if it doesn't exist.
	if(toupdate)
		g_hash_table_replace(nodeinfo_my->modtime_ht, strdup(dirpath_rel), GINT_TO_POINTER(stat64.st_ctime));

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

#endif

