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

window_t window_i = {0};
window_t window_o = {0};

uint32_t clustercmd_crc32_table[1<<8];

/**
 * @brief 			Adds command (message) to window_p->buffer
 * 
 * @param[in]	clustercmd_p	Pointer to cluster cmd to put into window
 * 
 * @retval	zero		Successful
 * @retval	non-zero	If got error while deleting the message. The error-code is placed into returned value.
 * 
 */

static inline int clustercmd_window_add(window_t *window_p, clustercmd_t *clustercmd_p) {

	// Checking if there enough window_p->cells allocated
	if(window_p->packets_len >= window_p->size) {
		window_p->size 		+= ALLOC_PORTION;

#		define CXREALLOC(a, size) \
			(typeof(a))xrealloc((char *)(a), (size_t)(size) * sizeof(*(a)))
	
		window_p->packets_id     = CXREALLOC(window_p->packets_id,	 window_p->size);
		window_p->occupied_sides = CXREALLOC(window_p->occupied_sides, window_p->size);
#		undef CXREALLOC
	}

	// Calculating required memory space in buffer for the message
	size_t clustercmd_size = CLUSTERCMD_SIZE(*clustercmd_p);
	size_t required_space  = sizeof(clustercmdqueuedpackethdr_t) + clustercmd_size;

	// Searching occupied boundaries in the window_p->buffer
	size_t occupied_left = SIZE_MAX, occupied_right=0;
	int i;
	i = 0;
	while(i < window_p->packets_len) {
		unsigned int window_id;
		window_id  = window_p->packets_id[i];

		occupied_left  = MIN(occupied_left,  window_p->occupied_sides[window_id].left);
		occupied_right = MAX(occupied_right, window_p->occupied_sides[window_id].right);
	}

	printf_ddd("Debug3: clustercmd_window_add(): w.size == %u, b_left == %u; b_right == %u; w.buf_size == %u; r_space == %u\n",
		window_p->size, occupied_left, occupied_right, window_p->buf_size, required_space);

	// Trying to find a space in the buffer to place message
	size_t buf_coordinate = SIZE_MAX;
	if(window_p->packets_len) {
		// Free space from left  (start of buffer)
		size_t free_left  = occupied_left;
		// Free space from right (end of buffer)
		size_t free_right = window_p->buf_size - occupied_right;

		if(free_left  > required_space)
			buf_coordinate = free_left - required_space;
		else
		if(free_right > required_space)
			buf_coordinate   = occupied_right;
		else
		{
			// Not enough space in the window_p->buffer;
			window_p->buf_size += MAX(CLUSTER_WINDOW_BUFSIZE_PORTION, required_space);
			window_p->buf	    = xrealloc(window_p->buf, window_p->buf_size);
			buf_coordinate      = occupied_right;
		}
		printf_ddd("Debug3: clustercmd_window_add(): f_left == %u; f_right == %u; b_coord == %u; w.buf_size == %u",
			free_left, free_right, buf_coordinate, window_p->buf_size);
	}

	unsigned int window_id;

	// packet id in window
	window_id = window_p->packets_len;

	// reserving the space in buffer
	window_p->occupied_sides[window_id].left  = buf_coordinate;
	window_p->occupied_sides[window_id].right = buf_coordinate + required_space;

	// placing information into buffer
	clustercmdqueuedpacket_t *queuedpacket_p;

	queuedpacket_p = (clustercmdqueuedpacket_t *)&window_p->buf[buf_coordinate];

	memset(&queuedpacket_p->h,	0,		sizeof(queuedpacket_p->h));
	memcpy(&queuedpacket_p->cmd, 	clustercmd_p, 	clustercmd_size);

	queuedpacket_p->h.window_id  = window_id;

	// remembering new packet
	g_hash_table_insert(window_p->serial2queuedpacket_ht, GINT_TO_POINTER(clustercmd_p->h.serial), queuedpacket_p);
	window_p->packets_id[window_p->packets_len++] = window_id;

	return 0;
}


/**
 * @brief 			Removes command (message) from window_p->buffer
 * 
 * @param[in]	queuedpacket_p	Pointer to queuedpacket structure of the command (message)
 * 
 * @retval	zero		Successful
 * @retval	non-zero	If got error while deleting the message. The error-code is placed into returned value.
 * 
 */

static inline int clustercmd_window_del(window_t *window_p, clustercmdqueuedpacket_t *queuedpacket_p) {
#ifdef PARANOID
	if(!window_p->size) {
		printf_e("Error: clustercmd_window_del(): window not allocated.\n");
		return EINVAL;
	}
	if(!window_p->packets_len) {
		printf_e("Error: clustercmd_window_del(): there already no packets in the window.\n");
		return EINVAL;
	}
#endif

	unsigned int window_id_del  =  queuedpacket_p->h.window_id;
	unsigned int window_id_last = --window_p->packets_len;

	// Forgeting the packet

	// 	Moving the last packet into place of deleting packet, to free the tail in "window_p->packets_id" and "window_p->occupied_sides"
	if(window_id_del != window_id_last) {
		printf_ddd("Debug3: clustercmd_window_del(): %i -> %i\n", window_id_last, window_id_del);

		window_p->packets_id[window_id_del] = window_p->packets_id[window_id_last];

		memcpy(&window_p->occupied_sides[window_id_del], &window_p->occupied_sides[window_id_last], sizeof(window_p->occupied_sides[window_id_del]));
	}

	// 	Removing from hash table
	g_hash_table_remove(window_p->serial2queuedpacket_ht, GINT_TO_POINTER(queuedpacket_p->cmd.h.serial));

	return 0;
}


/**
 * @brief 			Initializes table for CRC32 calculations
 * 
 * @param[in]	clustercmd_p	Pointer to clustercmd
 * 
 * @retval	uint32_t	CRC32 value of clustecmd
 * 
 */

/*
   Name  : CRC-32
   Poly  : 0x04C11DB7    x^32 + x^26 + x^23 + x^22 + x^16 + x^12 + x^11 
                        + x^10 + x^8 + x^7 + x^5 + x^4 + x^2 + x + 1
   Init  : 0xFFFFFFFF
   Revert: true
   XorOut: 0xFFFFFFFF
   Check : 0xCBF43926 ("123456789")
 */
int clustercmd_crc32_calc_init() {
	int i;
	uint32_t crc32;

	i=0;
	while(i < (1<<8)) {
		int j;
		crc32 = i;

		j = 0;
		while(j < 8) {
			crc32  =  (crc32 & 1) ? (crc32 >> 1) ^ 0xEDB88320 : crc32 >> 1;
			j++;
		}
	
		clustercmd_crc32_table[i] = crc32;
		i++;
	};

	return 0;
}

/**
 * @brief 			Calculates CRC32 for clustercmd
 * 
 * @param[in]	clustercmd_p	Pointer to clustercmd
 * 
 * @retval	zero		On successful calculation
 * @retval	non-zero	On error. Error-code is placed into returned value.
 * 
 */

/*
   Name  : CRC-32
   Poly  : 0x04C11DB7    x^32 + x^26 + x^23 + x^22 + x^16 + x^12 + x^11 
                        + x^10 + x^8 + x^7 + x^5 + x^4 + x^2 + x + 1
   Init  : 0xFFFFFFFF
   Revert: true
   XorOut: 0xFFFFFFFF
   Check : 0xCBF43926 ("123456789")
 */
int clustercmd_crc32_calc(clustercmd_t *clustercmd_p, clustercmdcrc32_t *clustercmdcrc32_p, crc32_calc_t flags) {

	if(flags & CRC32_CALC_HEADER) {
		uint32_t crc32;
		clustercmdcrc32_t crc32_save;

		// Preparing
		memcpy(&crc32_save, 	&clustercmd_p->h.crc32, sizeof(clustercmdcrc32_t));
		memset(&clustercmd_p->h.crc32, 		0, 	sizeof(clustercmdcrc32_t));
		crc32 = 0xFFFFFFFF;

		uint32_t size = sizeof(clustercmdhdr_t);
		char    *ptr  = (char *)&clustercmd_p->h;

		// Calculating
		crc32 = 0;
		while(size--) 
			crc32 = clustercmd_crc32_table[(crc32 ^ *(ptr++)) & 0xFF] ^ (crc32 >> 8);

		// Ending
		memcpy(&clustercmd_p->h.crc32, &crc32_save, sizeof(clustercmdcrc32_t));
		clustercmdcrc32_p->hdr = crc32 ^ 0xFFFFFFFF;
	}

	if(flags & CRC32_CALC_DATA) {
		uint32_t crc32;

		uint32_t size = clustercmd_p->h.data_len;
		char    *ptr  = clustercmd_p->data_p;

#ifdef PARANOID
		if(size & 0x3) {
			printf_e("Error: clustercmd_crc32_calc(): clustercmd_p->h.data_len&0x3 != 0: %u\n",
				clustercmd_p->h.data_len);
			return EINVAL;
		}
#endif

		// Calculating
		crc32 = 0;
		while(size--) 
			crc32 = clustercmd_crc32_table[(crc32 ^ *(ptr++)) & 0xFF] ^ (crc32 >> 8);

		// Ending
		clustercmdcrc32_p->dat = crc32 ^ 0xFFFFFFFF;
	}

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
 * @brief 			Safe wrapper for read() function
 * 
 * @param[in]	sock		The socket descriptor
 * @param[in]	buf		Pointer to buffer
 * @param[in]	size		Amount of bytes to read
 * 
 * @retval	zero		Successful
 * @retval	non-zero	If got error while read()-ing. The error-code is placed into returned value. "-1" means that message is too short.
 * 
 */

static inline int cluster_read(int sock, void *buf, size_t size) {
	int readret = read(sock, buf, size);
#ifdef PARANOID
	if(!readret) {
		printf_e("Error: cluster_read(): read() returned 0. This shouldn't happend. Exit.");
		return EINVAL;
	}
#endif
	if(readret < 0) {
		printf_e("Error: cluster_read(): read() returned %i. "
			"Seems, that something wrong with network socket: %s (errno %i).\n", 
			readret, strerror(errno), errno);
		return errno != -1 ? errno : -2;
	}

	if(readret < size) {
		// Too short message
		printf_e("Warning: cluster_read(): Got too short message from node. Ignoring it.\n");
		return -1;
	}

	return 0;
}


/**
 * @brief 			Sends packet-reject notification
 * 
 * @param[in]	sock		The socket descriptor
 * @param[in]	buf		Pointer to buffer
 * @param[in]	size		Amount of bytes to read
 * 
 * @retval	zero		Successful
 * @retval	non-zero	If got error while read()-ing. The error-code is placed into returned value. "-1" means that message is too short.
 * 
 */

static inline int clustercmd_reject(clustercmd_t *clustercmd_p, uint8_t reason) {
	clustercmd_t *clustercmd_rej_p 		= CLUSTER_ALLOCA(clustercmd_rej_t, 0);
	clustercmd_rej_p->h.dst_node_id 	= clustercmd_p->h.src_node_id;
	clustercmd_rej_p->data_rej.serial 	= clustercmd_p->h.serial;
	clustercmd_rej_p->data_rej.reason 	= reason;

	return cluster_send(clustercmd_rej_p);
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
		errno = EINVAL;
		return -1;
	}

	if((*clustercmd_pp != NULL) && (*size_p == 0)) {
		printf_e("Error: cluster_recv(): *clustercmd_pp != NULL && *size_p == 0.\n");
		errno = EINVAL;
		return -1;
	}

	if((*clustercmd_pp == NULL) && (*size_p != 0)) {
		printf_e("Error: cluster_recv(): *clustercmd_pp == NULL && *size_p != 0.\n");
		errno = EINVAL;
		return -1;
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

	// Getting pointer to space to place clustercmd
	clustercmd_t *clustercmd_p = *clustercmd_pp;

	// Checking if there any event on read socket
	//	select()
	struct timeval tv;

	fd_set rfds;
	FD_ZERO(&rfds);
	FD_SET(sock, &rfds);

	tv.tv_sec  = timeout / 1000;
	tv.tv_usec = timeout % 1000;

	int selret = select(sock+1, &rfds, NULL, NULL, &tv);

	// 	Remembering the rest part of timeout
	if(timeout_p != NULL)
		*timeout_p = tv.tv_sec * 1000 + tv.tv_usec / 1000;

	//	processing select()'s retuned value
	if(selret <  0) {
		printf_e("Error: cluster_recv(): got error while select(): %s (errno: %i).\n", 
			strerror(errno), errno);
		return 0;
	}
	if(selret == 0) {
		printf_ddd("Debug: cluster_recv(): no new messages.\n");
		return 0;
	}
	printf_ddd("Debug: cluster_recv(): got new message(s).\n");

	// Reading new message's header
	clustercmdcrc32_t crc32;
	//clustercmd_t *clustercmd_p = (clustercmd_t *)mmap(NULL, sizeof(clustercmdhdr_t), PROT_NONE, 
	//	MAP_PRIVATE, sock, 0);
	int ret;
	if((ret=cluster_read(sock, (void *)clustercmd_p, sizeof(clustercmdhdr_t)))) {
		if(ret == -1) return 0; // Invalid message? Skipping.

		printf_e("Error: cluster_recv(): Got error from cluster_read(): %s (errno %i).\n",
			strerror(errno), errno);
		errno = ret;
		return -1;
	}

	// Checking CRC32 of packet headers.
	clustercmd_crc32_calc(clustercmd_p, &crc32, CRC32_CALC_HEADER);
	if(crc32.hdr != clustercmd_p->h.crc32.hdr) {
		printf_d("Debug: cluster_recv(): hdr-CRC32 mismatch: %p != %p.\n", 
			(void*)(long)clustercmd_p->h.crc32.hdr, (void*)(long)crc32.hdr);

		if((ret=clustercmd_reject(clustercmd_p, REJ_CRC32MISMATCH))) {
			printf_e("Error: cluster_recv(): Got error while clustercmd_reject(): %s (errno: %i).\n", 
				strerror(ret), ret);
			errno = ret;
			return -1;
		}
	}

	// Checking src_node_id and dst_node_id
	uint8_t src_node_id = clustercmd_p->h.src_node_id;
	uint8_t dst_node_id = clustercmd_p->h.dst_node_id;

	// 	Packet from registering node?
	if(src_node_id == NODEID_NOID) {
		// 	Wrong command from registering node?
		if(clustercmd_p->h.cmd_id != CLUSTERCMDID_GETMYID) {
			printf_e("Warning: cluster_recv(): Got non getmyid packet from NOID node. Ignoring the packet.\n");
			return 0;
		}
	} else
	// 	Wrong src_node_id?
	if(src_node_id >= MAXNODES) {
		printf_e("Warning: cluster_recv(): Invalid h.src_node_id: %i >= "XTOSTR(MAXNODES)"\n",
			src_node_id);
		return 0;
	}

	// 	Is this broadcast message?
	if(dst_node_id == NODEID_NOID) {
		// CODE HERE
	} else
	//	Wrong dst_node_id?
	if(dst_node_id >= MAXNODES) {
		printf_e("Warning: cluster_recv(): Invalid h.dst_node_id: %i >= "XTOSTR(MAXNODES)"\n", 
			dst_node_id);
		return 0;
	}

	// Seems, that headers are correct. Continuing.
	printf_ddd("Debug3: cluster_recv(): Received: {h.dst_node_id: %u, h.src_node_id: %u, cmd_id: %u,"
		" crc32: %u, data_len: %u}, timeout: %u -> %u\n",
		dst_node_id, src_node_id, clustercmd_p->h.cmd_id, 
		clustercmd_p->h.crc32, clustercmd_p->h.data_len, *timeout_p, timeout);

	// Paranoid routines
	//	The message from us? Something wrong if it is.
#ifdef PARANOID
	if((clustercmd_p->h.src_node_id == node_id_my) && (node_id_my != NODEID_NOID)) {
#ifdef VERYPARANOID
		printf_e("Error: cluster_recv(): clustercmd_p->h.src_node_id == node_id_my (%i != %i)."
			" Exit.\n", clustercmd_p->h.src_node_id, node_id_my);
		return EINVAL;
#else
		printf_e("Warning: cluster_recv(): clustercmd_p->h.src_node_id == node_id_my (%i != %i)."
			" Ignoring the command.\n", clustercmd_p->h.src_node_id, node_id_my);
		clustercmd_p = NULL;
		return 0;
#endif
	}
#endif

	nodeinfo_t *nodeinfo_p = &nodeinfo[src_node_id];

	// Not actual packet?
	if(clustercmd_p->h.serial <= nodeinfo_p->last_serial) {
		printf_d("Debug: cluster_recv(): Ignoring packet from %i due to serial: %i <= %i\n", 
			src_node_id, clustercmd_p->h.serial, nodeinfo_p->last_serial);
		return 0;
	}

	// Is this misordered packet?
	if(clustercmd_p->h.serial != nodeinfo_p->last_serial + 1) {
		clustercmd_window_add(&window_i, clustercmd_p);
		return 0;
	}

	// Is this the end of packet (packet without data)
	if(clustercmd_p->h.data_len == 0) {
		return 1;
	}

	// Too big data?
	if(clustercmd_p->h.data_len > CLUSTER_PACKET_MAXSIZE) {
		printf_e("Warning: cluster_recv(): Got too big message from node %i. Ignoring it.\n",
			src_node_id);
		return 0;
	}

	// Incorrect size of data?
	if(clustercmd_p->h.data_len & 0x3) {
		printf_e("Warning: cluster_recv(): Received packet of size not a multiple of 4. Ignoring it.\n");
		return 0;
	}

	// Need more space for this packet?
	if(CLUSTERCMD_SIZE(*clustercmd_p) > size) {
		 size   = CLUSTERCMD_SIZE(*clustercmd_p);
		*clustercmd_pp = (clustercmd_t *)xrealloc((char *)clustercmd_p, size);
		 clustercmd_p  = *clustercmd_pp;
		*size_p = size;
	}

	// Reading the data
	if((ret=cluster_read(sock, (void *)clustercmd_p->data_p, clustercmd_p->h.data_len))) {
		if(ret == -1) return 0;

		printf_e("Error: cluster_recv(): Got error from cluster_read(): %s (errno %i).\n", 
			strerror(errno), errno);
		errno = ret;
		return -1;
	}

	// Checking CRC32 of packet data.
	clustercmd_crc32_calc(clustercmd_p, &crc32, CRC32_CALC_DATA);
	if(crc32.dat != clustercmd_p->h.crc32.dat) {
		printf_d("Debug: cluster_recv(): dat-CRC32 mismatch: %p != %p.\n", 
			(void*)(long)clustercmd_p->h.crc32.dat, (void*)(long)crc32.dat);

		if((ret=clustercmd_reject(clustercmd_p, REJ_CRC32MISMATCH))) {
			printf_e("Error: cluster_recv(): Got error while clustercmd_reject(): %s (errno: %i).\n", 
				strerror(ret), ret);
			errno = ret;
			return -1;
		}
	}

	return 1;
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

static int cluster_recv_proc(unsigned int _timeout) {
	static clustercmd_t *clustercmd_p=NULL;
	int ret;
	size_t size=0;
	unsigned int timeout = _timeout;
	while((ret=cluster_recv(&clustercmd_p, &size, &timeout))) {
		// Exit if error
		if(ret == -1) {
			printf_e("Error: cluster_recv_proc(): Got error while cluster_recv(): %s (%i).\n", 
				strerror(errno), errno);
			return errno;
		}

		// If we have appropriate callback function, then call it! :)
		if(recvproc_funct[clustercmd_p->h.cmd_id])
			if((ret=recvproc_funct[clustercmd_p->h.cmd_id](clustercmd_p))) {
				printf_e("Error: cluster_recv_proc(): Got error from recvproc_funct[%i]: %s (%i)\n", 
					clustercmd_p->h.cmd_id, strerror(ret), ret);
				return ret;
			}
	}

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

	clustercmdqueuedpacket_t *queuedpacket_p = 
		(clustercmdqueuedpacket_t *)g_hash_table_lookup(window_o.serial2queuedpacket_ht, GINT_TO_POINTER(cmd_serial_ack));

	if(queuedpacket_p == NULL)
		return 0;

	uint8_t node_id_from = clustercmd_p->h.src_node_id;

	if(! queuedpacket_p->h.o.ack_from[node_id_from]) {
		queuedpacket_p->h.o.ack_count++;
		queuedpacket_p->h.o.ack_from[node_id_from]++;

		if(queuedpacket_p->h.o.ack_count == node_count-1)
			clustercmd_window_del(&window_o, queuedpacket_p);
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

int cluster_io_init() {
	window_i.serial2queuedpacket_ht = g_hash_table_new_full(g_direct_hash, g_direct_equal, 0, 0);
	window_o.serial2queuedpacket_ht = g_hash_table_new_full(g_direct_hash, g_direct_equal, 0, 0);

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

int cluster_io_deinit() {

	if(window_i.serial2queuedpacket_ht != NULL)
		g_hash_table_destroy(window_i.serial2queuedpacket_ht);

	if(window_i.buf_size) {
#ifdef PARANOID
		if(window_i.buf == NULL) {
			printf_e("Error: cluster_recv_proc_deinit(): window_i.buf_size != 0, but window_i.buf == NULL.\n");
		} else
#endif
		free(window_i.buf);
	}

	if(window_o.serial2queuedpacket_ht != NULL)
		g_hash_table_destroy(window_o.serial2queuedpacket_ht);

	if(window_o.buf_size) {
#ifdef PARANOID
		if(window_o.buf == NULL) {
			printf_e("Error: cluster_recv_proc_deinit(): window_o.buf_size != 0, but window_o.buf == NULL.\n");
		} else
#endif
		free(window_o.buf);
	}

	return 0;
}

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

	// Initializing global variables, pt. 1
	options_p	= _options_p;
	indexes_p	= _indexes_p;
	cluster_timeout	= options_p->cluster_timeout * 1000;

	// Initializing network routines
	sock = socket(AF_INET, SOCK_DGRAM, 0);

	int reuse = 1;
	if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,(char *)&reuse, sizeof(reuse)) < 0) {
		printf_e("Error: cluster_init(): Got error while setsockopt(): %s (errno: %i)\n", 
			strerror(errno), errno);
		return errno;
	}

	struct sockaddr_in sa = {0};
	(void)sa;	// Anti-warning

	sa.sin_family		= AF_INET;
	sa.sin_port 		= htons(options_p->cluster_mcastipport);
	sa.sin_addr.s_addr	= INADDR_ANY;

	if(bind(sock, (struct sockaddr*)&sa, sizeof(sa))) {
		printf_e("Error: cluster_init(): Got error while bind(): %s (errno: %i)\n", 
			strerror(errno), errno);
		return errno;
	}

	struct ip_mreq group;
	group.imr_interface.s_addr = inet_addr(options_p->cluster_iface);
	group.imr_multiaddr.s_addr = inet_addr(options_p->cluster_mcastipaddr);

	if(setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, 
				(char *)&group, sizeof(group)) < 0) {
		printf_e("Error: cluster_init(): Cannot setsockopt() to enter to membership %s -> %s\n",
			options_p->cluster_iface, options_p->cluster_mcastipaddr);
		return errno;
	}


	// Initializing another routines
	clustercmd_crc32_calc_init();
	cluster_io_init();

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

	cluster_io_deinit();

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

	close(sock);

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

