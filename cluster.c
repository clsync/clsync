/*
    clsync - file tree sync utility based on inotify

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

/*
    Hello, dear developer.

    You can ask me directly by e-mail or IRC, if something seems too
    hard.

                                                           -- 0x8E30679C
 */


#ifdef CLUSTER_SUPPORT

#include "common.h"
#include "indexes.h"
#include "error.h"
#include "cluster.h"
#include "sync.h"
#include "calc.h"
#include "malloc.h"

// Global variables. They will be initialized in cluster_init()

#define CLUSTER_RECV_PROC_ERRLIMIT (1<<8)
#define NODES_ALLOC (MAX(MAXNODES, NODEID_NOID)+1)


int sock_i			= -1;
struct sockaddr_in sa_i		= {0};

int sock_o			= -1;
struct sockaddr_in sa_o		= {0};

ctx_t  *ctx_p		= NULL;
indexes_t  *indexes_p		= NULL;
pthread_t   pthread_cluster	= 0;

nodeinfo_t nodeinfo[NODES_ALLOC] = {{0}};

nodeinfo_t *nodeinfo_my				= NULL;
uint8_t	node_id_my				= NODEID_NOID;
uint8_t node_ids[NODES_ALLOC]			= {0};
unsigned int cluster_timeout			= 0;
uint8_t node_count				= 0;
uint8_t node_online				= 0;

cluster_recvproc_funct_t recvproc_funct[COUNT_CLUSTERCMDID] = {NULL};

window_t window_i = {0};
window_t window_o = {0};

/**
 * @brief 			Adds command (message) to window_p->buffer
 *
 * @param[in]	clustercmd_p	Pointer to cluster cmd to put into window
 *
 * @retval	zero		Successful
 * @retval	non-zero	If got error while deleting the message. The error-code is placed into returned value.
 *
 */

static inline int clustercmd_window_add ( window_t *window_p, clustercmd_t *clustercmd_p, GHashTable *serial2queuedpacket_ht )
{
#ifdef PARANOID

	if ( clustercmd_p->h.src_node_id >= MAXNODES ) {
		error ( "Invalid src_node_id: %i.", clustercmd_p->h.src_node_id );
		return EINVAL;
	}

#endif

	// Checking if there enough window_p->cells allocated
	if ( window_p->packets_len >= window_p->size ) {
		window_p->size 		+= ALLOC_PORTION;
#		define CXREALLOC(a, size) \
	(typeof(a))xrealloc((char *)(a), (size_t)(size) * sizeof(*(a)))
		window_p->packets_id     = CXREALLOC ( window_p->packets_id,	window_p->size );
		window_p->occupied_sides = CXREALLOC ( window_p->occupied_sides,	window_p->size );
#		undef CXREALLOC
	}

	// Calculating required memory space in buffer for the message
	size_t clustercmd_size = CLUSTERCMD_SIZE ( clustercmd_p );
	size_t required_space  = sizeof ( clustercmdqueuedpackethdr_t ) + clustercmd_size;
	// Searching occupied boundaries in the window_p->buffer
	size_t occupied_left = SIZE_MAX, occupied_right = 0;

	unsigned int i;
	i = 0;

	while ( i < window_p->packets_len ) {
		unsigned int window_id;
		window_id  = window_p->packets_id[ i++ ];
		occupied_left  = MIN ( occupied_left,  window_p->occupied_sides[window_id].left );
		occupied_right = MAX ( occupied_right, window_p->occupied_sides[window_id].right );
	}

	debug ( 3, "w.size == %u, b_left == %u; b_right == %u; w.buf_size == %u; r_space == %u",
	        window_p->size, occupied_left, occupied_right, window_p->buf_size, required_space );
	// Trying to find a space in the buffer to place message
	size_t buf_coordinate = SIZE_MAX;

	if ( window_p->packets_len ) {
		// Free space from left  (start of buffer)
		size_t free_left  = occupied_left;
		// Free space from right (end of buffer)
		size_t free_right = window_p->buf_size - occupied_right;

		if ( free_left  > required_space )
			buf_coordinate = free_left - required_space;
		else if ( free_right > required_space )
			buf_coordinate   = occupied_right;
		else {
			// Not enough space in the window_p->buffer;
			window_p->buf_size += MAX ( CLUSTER_WINDOW_BUFSIZE_PORTION, required_space );
			window_p->buf	    = xrealloc ( window_p->buf, window_p->buf_size );
			buf_coordinate      = occupied_right;
		}

		debug ( 3, "f_left == %u; f_right == %u; b_coord == %u; w.buf_size == %u",
		        free_left, free_right, buf_coordinate, window_p->buf_size );
	} else {
		buf_coordinate = 0;

		if ( window_p->buf_size <= required_space ) {
			window_p->buf_size += MAX ( CLUSTER_WINDOW_BUFSIZE_PORTION, required_space );
			window_p->buf	    = xrealloc ( window_p->buf, window_p->buf_size );
		}
	}

	unsigned int window_id;
	// packet id in window
	window_id = window_p->packets_len;
	// reserving the space in buffer
	window_p->occupied_sides[window_id].left  = buf_coordinate;
	window_p->occupied_sides[window_id].right = buf_coordinate + required_space;
	// placing information into buffer
	clustercmdqueuedpacket_t *queuedpacket_p;
	debug ( 3, "b_coord == %u", buf_coordinate );
	queuedpacket_p = ( clustercmdqueuedpacket_t * ) &window_p->buf[buf_coordinate];
	memset ( &queuedpacket_p->h,	0,		sizeof ( queuedpacket_p->h ) );
	memcpy ( &queuedpacket_p->cmd, 	clustercmd_p, 	clustercmd_size );
	queuedpacket_p->h.window_id  = window_id;
	// remembering new packet
	g_hash_table_insert ( serial2queuedpacket_ht, GINT_TO_POINTER ( clustercmd_p->h.serial ), queuedpacket_p );
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

static inline int clustercmd_window_del ( window_t *window_p, clustercmdqueuedpacket_t *queuedpacket_p, GHashTable *serial2queuedpacket_ht )
{
#ifdef PARANOID

	if ( !window_p->size ) {
		error ( "window not allocated." );
		return EINVAL;
	}

	if ( !window_p->packets_len ) {
		error ( "there already no packets in the window." );
		return EINVAL;
	}

#endif
	unsigned int window_id_del  =  queuedpacket_p->h.window_id;
	unsigned int window_id_last = --window_p->packets_len;

	// Forgeting the packet

	// 	Moving the last packet into place of deleting packet, to free the tail in "window_p->packets_id" and "window_p->occupied_sides"
	if ( window_id_del != window_id_last ) {
		debug ( 3, "%i -> %i", window_id_last, window_id_del );
		window_p->packets_id[window_id_del] = window_p->packets_id[window_id_last];
		memcpy ( &window_p->occupied_sides[window_id_del], &window_p->occupied_sides[window_id_last], sizeof ( window_p->occupied_sides[window_id_del] ) );
	}

	// 	Removing from hash table
	g_hash_table_remove ( serial2queuedpacket_ht, GINT_TO_POINTER ( queuedpacket_p->cmd.h.serial ) );
	return 0;
}


/**
 * @brief 			Calculates Adler32 for clustercmd
 *
 * @param[in]	clustercmd_p	Pointer to clustercmd
 * @param[out]	clustercmdadler32_p Pointer to structure to return value(s)
 *
 * @retval	zero		On successful calculation
 * @retval	non-zero	On error. Error-code is placed into returned value.
 *
 */

int clustercmd_adler32_calc ( clustercmd_t *clustercmd_p, clustercmdadler32_t *clustercmdadler32_p, adler32_calc_t flags )
{
	debug ( 15, "(%p, %p, 0x%x)", clustercmd_p, clustercmdadler32_p, flags );

	if ( flags & ADLER32_CALC_DATA ) {
		uint32_t adler32;
		uint32_t size = clustercmd_p->h.data_len;
		char    *ptr  = clustercmd_p->data.p;
		// Calculating
		adler32 = adler32_calc ( ( unsigned char * ) ptr, CLUSTER_PAD ( size ) );
		debug ( 20, "dat: 0x%x", adler32 );
		// Ending
		clustercmdadler32_p->dat = adler32 ^ 0xFFFFFFFF;
	}

	if ( flags & ADLER32_CALC_HEADER ) {
		uint32_t adler32;
		clustercmdadler32_t adler32_save;
		// Preparing
		memcpy ( &adler32_save.hdr,		&clustercmd_p->h.adler32.hdr,	sizeof ( clustercmd_p->h.adler32.hdr ) );
		memset ( &clustercmd_p->h.adler32.hdr, 	0,				sizeof ( clustercmd_p->h.adler32.hdr ) );
		adler32 = 0xFFFFFFFF;
		uint32_t size = sizeof ( clustercmdhdr_t );
		char    *ptr  = ( char * ) &clustercmd_p->h;
		// Calculating
		adler32 = adler32_calc ( ( unsigned char * ) ptr, size );
		debug ( 20, "hdr: 0x%x", adler32 );
		// Ending
		memcpy ( &clustercmd_p->h.adler32.hdr, &adler32_save.hdr, sizeof ( clustercmd_p->h.adler32.hdr ) );
		clustercmdadler32_p->hdr = adler32 ^ 0xFFFFFFFF;
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

int _cluster_send ( clustercmd_t *clustercmd_p )
{
	debug ( 10, "{h.dst_node_id: %u, h.src_node_id: %u, cmd_id: %u, data_len: %u}",
	        clustercmd_p->h.dst_node_id, clustercmd_p->h.src_node_id, clustercmd_p->h.cmd_id,
	        clustercmd_p->h.data_len );
	clustercmd_p->h.src_node_id = node_id_my;
	SAFE ( clustercmd_adler32_calc ( clustercmd_p, &clustercmd_p->h.adler32, ADLER32_CALC_ALL ), return _SAFE_rc );
	debug ( 3, "Sending: "
	        "{h.dst_node_id: %u, h.src_node_id: %u, cmd_id: %u, adler32.hdr: %p, adler32.dat: %p, data_len: %u}",
	        clustercmd_p->h.dst_node_id, clustercmd_p->h.src_node_id, clustercmd_p->h.cmd_id,
	        ( void * ) ( long ) clustercmd_p->h.adler32.hdr, ( void * ) ( long ) clustercmd_p->h.adler32.dat,
	        clustercmd_p->h.data_len );
	nodeinfo_t *nodeinfo_p;
	nodeinfo_p = &nodeinfo[clustercmd_p->h.dst_node_id];

	// Checking if the node online
	switch ( nodeinfo_p->status ) {
		case NODESTATUS_DOESNTEXIST:
		case NODESTATUS_OFFLINE:
			debug ( 1, "There's no online node with id %u. Skipping sending.", clustercmd_p->h.dst_node_id );
			return EADDRNOTAVAIL;

		default:
			break;
	}

	// Putting the message into an output window
	if ( nodeinfo_my != NULL )
		clustercmd_window_add ( &window_o, clustercmd_p, nodeinfo_my->serial2queuedpacket_ht );

	// Sending the message
	debug ( 10, "sendto(%p, %p, %i, 0, %p, %i)", sock_o, clustercmd_p, CLUSTERCMD_SIZE_PADDED ( clustercmd_p ), &sa_o, sizeof ( sa_o ) );
	debug ( 50, "clustercmd_p->data.p[0] == 0x%x", clustercmd_p->data.p[0] );
	critical_on ( sendto ( sock_o, clustercmd_p, CLUSTERCMD_SIZE_PADDED ( clustercmd_p ), 0, &sa_o, sizeof ( sa_o ) ) == -1 );
	// Finishing
	return 0;
}

static inline int cluster_send ( clustercmd_t *clustercmd_p )
{
	int rc;
	rc = _cluster_send ( clustercmd_p );
	debug ( 10, "__________________sent___________________ %i", rc );
	return rc;
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

int node_update_status ( uint8_t node_id, uint8_t node_status )
{
	debug ( 3, "%i, %i", node_id, node_status );
	uint8_t node_status_old = nodeinfo[node_id].status;
	nodeinfo_t *nodeinfo_p = &nodeinfo[node_id];

	if ( ( node_status == NODESTATUS_DOESNTEXIST ) && ( node_status_old != NODESTATUS_DOESNTEXIST ) ) {
		node_count--;
		node_ids[nodeinfo_p->num] = node_ids[node_count];
		g_hash_table_destroy ( nodeinfo_p->modtime_ht );
		g_hash_table_destroy ( nodeinfo_p->serial2queuedpacket_ht );
#ifdef VERYPARANOID
		memset ( nodeinfo_p, 0, sizeof ( *nodeinfo_p ) );
#endif
		return 0;
	}

	if ( node_status == node_status_old )
		return 0;

	switch ( node_status_old ) {
		case NODESTATUS_DOESNTEXIST:
			nodeinfo_p->id			   = node_id;
			nodeinfo_p->num			   = node_count;
			nodeinfo_p->last_serial		   = -1;
			nodeinfo_p->modtime_ht 		   = g_hash_table_new_full ( g_str_hash,	  g_str_equal,	  free, 0 );
			nodeinfo_p->serial2queuedpacket_ht = g_hash_table_new_full ( g_direct_hash, g_direct_equal, 0,    0 );
			node_ids[node_count] = node_id;
			node_count++;
#ifdef PARANOID

			if ( node_status == NODESTATUS_OFFLINE )
				break; // In case of NODESTATUS_DOESNTEXIST -> NODESTATUS_OFFLINE, node_online should be increased

#endif

		case NODESTATUS_OFFLINE:
			nodeinfo_p->last_serial		   = -1;
			node_online++;
			break;

		default:
			if ( node_status == NODESTATUS_OFFLINE )
				node_online--;

			break;
	}

	nodeinfo[node_id].status = node_status;
	return 0;
}


/**
 * @brief 			Changes information about node's name and updates connected information.
 *
 * @param[in]	node_id		node_id of the node.
 * @param[in]	node_name	New node name
 *
 * @retval	zero		Successful
 * @retval	non-zero	If got error while changing the status. The error-code is placed into returned value.
 *
 */

int node_update_name ( uint8_t node_id, const char *node_name )
{
	debug ( 3, "%i, \"%s\"", node_id, node_name );
	nodeinfo_t *nodeinfo_p = &nodeinfo[node_id];
	void *ret = g_hash_table_lookup ( indexes_p->nodenames_ht, node_name );

	if ( ret != NULL ) {
		int rc;
		uint8_t node_old_id = GPOINTER_TO_INT ( ret );
		nodeinfo_t *nodeinfo_old_p = &nodeinfo[node_old_id];
		debug ( 5, "nodename \"%s\" had been used by node_id == %i", node_name, node_old_id );

		if ( node_old_id == node_id ) {
			debug ( 10, "node_old_id [%i] == node_id [%i]", node_old_id, node_id );
			return 0;
		}

		{
			debug ( 15, "Sending a DIE command to node_id (%i)", node_old_id );
			clustercmd_t *clustercmd_p  = CLUSTER_ALLOCA ( clustercmd_die_t, 0 );
			clustercmd_p->h.cmd_id      = CLUSTERCMDID_DIE;
			clustercmd_p->h.dst_node_id = node_old_id;

			if ( ( rc = cluster_send ( clustercmd_p ) ) )
				return rc;
		}

		nodeinfo_old_p->node_name = NULL;
		debug ( 3, "changing status of node_id == %i to NODESTATUS_OFFLINE", node_old_id );
		node_update_status ( node_old_id, NODESTATUS_OFFLINE );
	}

	char *node_name_dup = strdup ( node_name );
	nodeinfo_p->node_name = node_name_dup;
	g_hash_table_replace ( indexes_p->nodenames_ht, node_name_dup, GINT_TO_POINTER ( node_id ) );
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

static inline int cluster_recv_proc_set ( clustercmd_id_t cmd_id, cluster_recvproc_funct_t procfunct )
{
	recvproc_funct[cmd_id] = procfunct;
	return 0;
}


/**
 * @brief 			Safe wrapper for recvfrom() function
 *
 * @param[in]	sock		The socket descriptor
 * @param[out]	_buf_p		Pointer to pointer to buffer
 * @param[in]	flags		Flags...
 *
 * @retval	zero		Successful
 * @retval	non-zero	If got error while read()-ing. The error-code is placed into returned value. "-1" means that message is too short.
 *
 */

static inline int cluster_read ( int sock, clustercmd_t **cmd_pp, cluster_read_flags_t flags )
{
	static char buf[CLUSTER_PACKET_MAXSIZE];
	static clustercmd_t *cmd_p = ( void * ) buf;
	struct sockaddr_in sa_in;
	size_t sa_in_len = sizeof ( sa_in );
	*cmd_pp = cmd_p;
	debug ( 20, "%i, %p, 0x%x", sock, buf, flags );
	int readret = recvfrom ( sock, buf, CLUSTER_PACKET_MAXSIZE, MSG_WAITALL, ( struct sockaddr * ) &sa_in, ( socklen_t * restrict ) &sa_in_len );
	debug ( 30, "recvfrom(%i, %p, 0x%x, %p, %p) -> %i", sock, buf, MSG_WAITALL, &sa_in, &sa_in_len, readret );
#ifdef PARANOID

	if ( !readret ) {
		error ( "recvfrom() returned 0. This shouldn't happend. Exit." );
		return EINVAL;
	}

#endif

	if ( readret < 0 ) {
		error ( "recvfrom() returned %i. "
		        "Seems, that something wrong with network socket.",
		        readret );
		return errno != -1 ? errno : -2;
	}

	debug ( 2, "Got message from %s (len: %i).", inet_ntoa ( sa_in.sin_addr ), readret );

	if ( ( unsigned int ) readret < sizeof ( clustercmdhdr_t ) ) {
		// Too short message
		error ( "Warning: cluster_read(): Got too short message from node (no header [or too short]). Ignoring it." );
		return -1;
	}

	if ( ( unsigned int ) readret < CLUSTERCMD_SIZE ( cmd_p ) ) {
		// Too short message
		error ( "Warning: cluster_read(): Got too short message from node (no data [or too short]). Ignoring it." );
		return -1;
	}

	// Incorrect size?
	if ( readret & 0x3 ) {
		error ( "Warning: cluster_recv(): Received packet of size %i (not a multiple of 4). Ignoring it.", readret );
		return 0;
	}

	return 0;
}


/**
 * @brief 			Sends packet-reject notification
 *
 * @param[in]	clustercmd_p	Pointer to clustercmd that will be rejected
 * @param[in]	reason		Reason why the clustercmd is denied
 *
 * @retval	zero		Successful
 * @retval	non-zero	If got error while read()-ing. The error-code is placed into returned value. "-1" means that message is too short.
 *
 */

static inline int clustercmd_reject ( clustercmd_t *clustercmd_p, uint8_t reason )
{
	clustercmd_t *clustercmd_rej_p 		= CLUSTER_ALLOCA ( clustercmd_rej_t, 0 );
	clustercmd_rej_p->h.dst_node_id 	= clustercmd_p->h.src_node_id;
	clustercmd_rej_p->data.rej.serial 	= clustercmd_p->h.serial;
	clustercmd_rej_p->data.rej.reason 	= reason;
	return cluster_send ( clustercmd_rej_p );
}


#define CLUSTER_RECV_RETURNMESSAGE(clustercmd_p) {\
		last_serial      = (clustercmd_p)->h.serial;\
		last_src_node_id = (clustercmd_p)->h.src_node_id;\
		if(clustercmd_pp != NULL)\
			*clustercmd_pp = (clustercmd_p);\
		return 1;\
	}
/**
 * @brief 			Receives message from another nodes of the cluster. (not thread-safe)
 *
 * @param[out]	clustercmd_pp	Pointer to command structure pointer. It will be re-allocated every time when size is not enough. Allocated space will be reused on next calling.
 * @param[i]	timeout		Timeout (in milliseconds).
 *
 * @retval	 1		If there's new message.
 * @retval	 0		If there's no new messages.
 * @retval	-1		If got error while receiving. The error-code is placed into "errno".
 *
 */

static int _cluster_recv ( clustercmd_t **clustercmd_pp, struct timeval *timeout )
{
	clustercmd_t   *clustercmd_p;
	static uint8_t  last_src_node_id  = NODEID_NOID;
	static uint32_t last_serial	  = 0;

	// Checking if there message is waiting in the window
	if ( last_src_node_id != NODEID_NOID ) {
		nodeinfo_t *nodeinfo_p = &nodeinfo[last_src_node_id];

		if ( nodeinfo_p->serial2queuedpacket_ht != NULL ) {
			clustercmdqueuedpacket_t *clustercmdqueuedpacket_p = ( clustercmdqueuedpacket_t * )
			        g_hash_table_lookup ( nodeinfo_p->serial2queuedpacket_ht, GINT_TO_POINTER ( last_serial + 1 ) );

			if ( clustercmdqueuedpacket_p != NULL )
				CLUSTER_RECV_RETURNMESSAGE ( &clustercmdqueuedpacket_p->cmd );
		}
	}

	// Checking if there any event on read socket
	//	select()
	fd_set rfds;
	FD_ZERO ( &rfds );
	FD_SET ( sock_i, &rfds );
	debug ( 3, "select() with timeout {%u, %u}", timeout->tv_sec, timeout->tv_usec );
	int selret = select ( sock_i + 1, &rfds, NULL, NULL, timeout );

	//	processing select()'s retuned value
	if ( selret <  0 ) {
		error ( "got error while select()." );
		return -1;
	}

	if ( selret == 0 ) {
		debug ( 3, "no new messages." );
		return 0;
	}

	debug ( 3, "got new message(s)." );
	debug ( 10, "Reading new message's header" );
	clustercmdadler32_t adler32;
	//clustercmd_t *clustercmd_p = (clustercmd_t *)mmap(NULL, sizeof(clustercmdhdr_t), PROT_NONE,
	//	MAP_PRIVATE, sock, 0);
	int ret;

	if ( ( ret = cluster_read ( sock_i, clustercmd_pp, CLREAD_NONE ) ) ) {
		if ( ret == -1 ) return 0; // Invalid message? Skipping.

		error ( "Got error from cluster_read()." );
		errno = ret;
		return -1;
	}

	clustercmd_p = *clustercmd_pp;
	debug ( 3, "Received: {h.dst_node_id: %u, h.src_node_id: %u, cmd_id: %u,"
	        " serial: %u, adler32: {0x%x, 0x%x}, data_len: %u}",
	        clustercmd_p->h.dst_node_id, clustercmd_p->h.src_node_id,
	        clustercmd_p->h.cmd_id, clustercmd_p->h.serial,
	        clustercmd_p->h.adler32.hdr, clustercmd_p->h.adler32.dat,
	        clustercmd_p->h.data_len );
	// Checking adler32 of packet headers.
	clustercmd_adler32_calc ( clustercmd_p, &adler32, ADLER32_CALC_HEADER );

	if ( adler32.hdr != clustercmd_p->h.adler32.hdr ) {
		debug ( 1, "hdr-adler32 mismatch: %p != %p.",
		        ( void* ) ( long ) clustercmd_p->h.adler32.hdr, ( void* ) ( long ) adler32.hdr );

		if ( ( ret = clustercmd_reject ( clustercmd_p, REJ_ADLER32MISMATCH ) ) != EADDRNOTAVAIL ) {
			error ( "Got error while clustercmd_reject()." );
			errno = ret;
			return -1;
		}
	}

	// Checking src_node_id and dst_node_id
	uint8_t src_node_id = clustercmd_p->h.src_node_id;
	uint8_t dst_node_id = clustercmd_p->h.dst_node_id;

	// 	Packet from registering node?
	if ( src_node_id == NODEID_NOID ) {
		// 	Wrong command from registering node?
		if ( clustercmd_p->h.cmd_id != CLUSTERCMDID_HELLO ) {
			error ( "Warning: cluster_recv(): Got non hello packet from NOID node. Ignoring the packet." );
			return 0;
		}

		if ( clustercmd_p->h.serial != 0 ) {
			error ( "Warning: cluster_recv(): Got packet with non-zero serial from NOID node. Ignoring the packet." );
			return 0;
		}
	} else

		// 	Wrong src_node_id?
		if ( src_node_id >= MAXNODES ) {
			error ( "Warning: cluster_recv(): Invalid h.src_node_id: %i >= "XTOSTR ( MAXNODES ) "",
			        src_node_id );
			return -1;
		}

	// 	Is this broadcast message?
	if ( dst_node_id == NODEID_NOID ) {
		// CODE HERE
	} else

		//	Wrong dst_node_id?
		if ( dst_node_id >= MAXNODES ) {
			error ( "Warning: cluster_recv(): Invalid h.dst_node_id: %i >= "XTOSTR ( MAXNODES ) "",
			        dst_node_id );
			return -1;
		}

	// Seems, that headers are correct. Continuing.

	// Paranoid routines
	//	The message from us? Something wrong if it is.
	if ( ( clustercmd_p->h.src_node_id == node_id_my ) && ( node_id_my != NODEID_NOID ) )
		critical ( "node_id collision" );

	nodeinfo_t *nodeinfo_p = &nodeinfo[src_node_id];
	// Not actual packet?
	long serial_diff = clustercmd_p->h.serial - nodeinfo_p->last_serial;
	debug ( 10, "serial_diff == %i", serial_diff );

	if ( serial_diff <= 0 || serial_diff > CLUSTER_WINDOW_PCKTLIMIT ) {
		debug ( 1, "Ignoring packet (serial %i) from %i due to serial_diff: 0 <= || > %i",
		        clustercmd_p->h.serial, src_node_id, serial_diff, CLUSTER_WINDOW_PCKTLIMIT );
		return -1;
	}

	// Is this misordered packet?
	if ( clustercmd_p->h.serial != nodeinfo_p->last_serial + 1 ) {
		clustercmd_window_add ( &window_i, clustercmd_p, nodeinfo_p->serial2queuedpacket_ht );
		return -1;
	}

	// Is this the end of packet (packet without data)
	if ( clustercmd_p->h.data_len == 0 )
		CLUSTER_RECV_RETURNMESSAGE ( clustercmd_p );

	// Too big data?
	if ( clustercmd_p->h.data_len > CLUSTER_PACKET_MAXSIZE ) {
		error ( "Warning: cluster_recv(): Got too big message from node %i. Ignoring it.",
		        src_node_id );
		return -1;
	}

	/*
		// Need more space for this packet?
		if (CLUSTERCMD_SIZE(clustercmd_p) > size) {
			size   = CLUSTERCMD_SIZE(clustercmd_p);
			clustercmd_p = (clustercmd_t *)xrealloc((char *)clustercmd_p, size);
		}

		debug(10, "Reading the data");
		if ((ret=cluster_read(sock_i, (void *)clustercmd_p->data.p, CLUSTER_PAD(clustercmd_p->h.data_len), CLREAD_CONTINUE))) {
			if (ret == -1) return 0;

			error("Got error from cluster_read().");
			errno = ret;
			return -1;
		}
	*/
	// Checking adler32 of packet data.
	clustercmd_adler32_calc ( clustercmd_p, &adler32, ADLER32_CALC_DATA );

	if ( adler32.dat != clustercmd_p->h.adler32.dat ) {
		debug ( 1, "dat-adler32 mismatch: %p != %p.",
		        ( void* ) ( long ) clustercmd_p->h.adler32.dat, ( void* ) ( long ) adler32.dat );

		if ( ( ret = clustercmd_reject ( clustercmd_p, REJ_ADLER32MISMATCH ) ) != EADDRNOTAVAIL ) {
			error ( "Got error while clustercmd_reject()." );
			errno = ret;
			return -1;
		}
	}

	CLUSTER_RECV_RETURNMESSAGE ( clustercmd_p );
}

static inline int cluster_recv ( clustercmd_t **clustercmd_pp, struct timeval *timeout )
{
	int rc;
	rc = _cluster_recv ( clustercmd_pp, timeout );
	debug ( 10, "__________________recv___________________ %i", rc );
	return rc;
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

int cluster_recv_proc ( unsigned int timeout_rel_int )
{
	struct timeval timeout_rel, timeout_abs, tv_abs;
	int error_count, iteration;
	debug ( 3, "cluster_recv_proc(%i)", timeout_rel_int );
	clustercmd_t *clustercmd_p = NULL;
	int ret;
	timeout_rel.tv_sec  = timeout_rel_int / 1000;
	timeout_rel.tv_usec = timeout_rel_int % 1000;
	gettimeofday ( &tv_abs, NULL );
	timeradd ( &tv_abs, &timeout_rel, &timeout_abs );
	error_count = 0;
	iteration   = 0;

	while ( 1 ) {
		if ( iteration++ ) {
			gettimeofday ( &tv_abs, NULL );

			if ( timercmp ( &timeout_abs, &tv_abs, > ) )
				timersub ( &timeout_abs, &tv_abs, &timeout_rel );
			else
				memset ( &timeout_rel, 0, sizeof ( timeout_rel ) );

			debug ( 5, "timeout_abs == {%u, %u}; tv_abs == {%u, %u}; timeout_rel == {%u, %u}",
			        timeout_abs.tv_sec, timeout_abs.tv_usec,
			        tv_abs.tv_sec,      tv_abs.tv_usec,
			        timeout_rel.tv_sec, timeout_rel.tv_usec
			      );
		}

		ret = cluster_recv ( &clustercmd_p, &timeout_rel );

		if ( !ret )
			break;

		// Exit if error
		if ( ret == -1 ) {
			warning ( "Got error while cluster_recv(). error_count == %i", error_count );
			error_count++;
			critical_on ( error_count >= CLUSTER_RECV_PROC_ERRLIMIT );
		}

		// If we have appropriate callback function, then call it! :)
		if ( recvproc_funct[clustercmd_p->h.cmd_id] != NULL ) {
			debug ( 2, "Calling function by pointer %p", recvproc_funct[clustercmd_p->h.cmd_id] );

			if ( ( ret = recvproc_funct[clustercmd_p->h.cmd_id] ( clustercmd_p ) ) ) {
				error ( "Got error from recvproc_funct[%i]: %s (%i)",
				        clustercmd_p->h.cmd_id );
				return ret;
			}

			continue;
		}

		// We didn't found an appropriate callback function
		debug ( 2, "There's no appropriate callback function for cmd_id == %i", clustercmd_p->h.cmd_id );
	}

	return 0;
}


/**
 * @brief 			recvproc-function for DIE-messages
 *
 * @param[in] 	clustercmd_p 	Pointer to clustercmd
 *
 * @retval	zero 		Successfully initialized. (never happens)
 * @retval	non-zero 	Got error, while initializing.
 *
 */

static int cluster_recvproc_die ( clustercmd_t *clustercmd_p )
{
	critical ( "Got DIE message from node_id == %i,", clustercmd_p->h.src_node_id );
	return 0;
}


/**
 * @brief 			recvproc-function for ACK-messages
 *
 * @param[in] 	clustercmd_p 	Pointer to clustercmd
 *
 * @retval	zero 		Successfully initialized.
 * @retval	non-zero 	Got error, while initializing.
 *
 */

static int cluster_recvproc_ack ( clustercmd_t *clustercmd_p )
{
	uint32_t cmd_serial_ack = clustercmd_p->data.ack.serial;
	clustercmdqueuedpacket_t *queuedpacket_p =
	    ( clustercmdqueuedpacket_t * ) g_hash_table_lookup ( nodeinfo_my->serial2queuedpacket_ht, GINT_TO_POINTER ( cmd_serial_ack ) );

	if ( queuedpacket_p == NULL )
		return 0;

	uint8_t node_id_from = clustercmd_p->h.src_node_id;

	if ( ! queuedpacket_p->h.w.o.ack_from[node_id_from] ) {
		queuedpacket_p->h.w.o.ack_count++;
		queuedpacket_p->h.w.o.ack_from[node_id_from]++;

		if ( queuedpacket_p->h.w.o.ack_count == node_count - 1 )
			clustercmd_window_del ( &window_o, queuedpacket_p, nodeinfo_my->serial2queuedpacket_ht );
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

int cluster_io_init()
{
	cluster_recv_proc_set ( CLUSTERCMDID_ACK, cluster_recvproc_ack );
	cluster_recv_proc_set ( CLUSTERCMDID_DIE, cluster_recvproc_die );
	return 0;
}


/**
 * @brief 			Antagonist of cluster_recv_proc_init() function. Freeing everything what was allocated in cluster_recv_proc_init()
 *
 * @retval	zero 		Successfully initialized
 * @retval	non-zero 	Got error, while initializing
 *
 */

int cluster_io_deinit()
{
	if ( window_i.buf_size ) {
#ifdef PARANOID

		if ( window_i.buf == NULL ) {
			error ( "window_i.buf_size != 0, but window_i.buf == NULL." );
		} else
#endif
			free ( window_i.buf );
	}

	if ( window_o.buf_size ) {
#ifdef PARANOID

		if ( window_o.buf == NULL ) {
			error ( "window_o.buf_size != 0, but window_o.buf == NULL." );
		} else
#endif
			free ( window_o.buf );
	}

	return 0;
}


/**
 * @brief 			recvproc-function for welcome-messages
 *
 * @param[in] 	clustercmd_p 	Pointer to clustercmd
 *
 * @retval	zero 		Successfully initialized.
 * @retval	non-zero 	Got error, while initializing.
 *
 */

static int cluster_recvproc_welcome ( clustercmd_t *clustercmd_p )
{
	debug ( 20, "%p", clustercmd_p );
//	static time_t updatets = 0;
	clustercmd_welcome_t *data_welcome_p = &clustercmd_p->data.welcome;
	/*
		// 	Is this the most recent information? Skipping if not.
		if (!(data_welcome_p->updatets > updatets))
			return 0;
	*/
	// 	Is the node name length in message equals to our node name length? Skipping if not.
	uint32_t recv_nodename_len;
	recv_nodename_len = welcome_to_node_name_len ( clustercmd_p );

	if ( recv_nodename_len != ctx_p->cluster_nodename_len ) {
		debug ( 9, "recv_nodename_len [%i] != ctx_p->cluster_nodename_len [%i]", recv_nodename_len, ctx_p->cluster_nodename_len );
		return 0;
	}

	// 	Is the node name equals to ours? Skipping if not.
	if ( memcmp ( welcome_to_node_name ( data_welcome_p ), ctx_p->cluster_nodename, recv_nodename_len ) ) {
		debug ( 9, "to_node_name != ctx_p->cluster_nodename" );
		return 0;
	}

	//	Remembering the node that answered us
	node_update_status ( clustercmd_p->h.src_node_id, NODESTATUS_SEEMSONLINE );
	{
		char *node_name;
		node_name = alloca ( data_welcome_p->from_node_name_len );
		memcpy ( node_name, data_welcome_p->from_node_name, data_welcome_p->from_node_name_len );
		node_update_name ( clustercmd_p->h.src_node_id, node_name );
	}
	// 	Seems, that somebody knows our node id, remembering it.
	node_id_my  = clustercmd_p->h.dst_node_id;
//	updatets    = data_welcome_p->updatets;
	return 0;
}


/**
 * @brief 			recvproc-function for hello-messages
 *
 * @param[in] 	clustercmd_p 	Pointer to clustercmd
 *
 * @retval	zero 		Successfully initialized.
 * @retval	non-zero 	Got error, while initializing.
 *
 */

static int cluster_recvproc_hello ( clustercmd_t *clustercmd_p )
{
	clustercmd_hello_t *data_hello_p = &clustercmd_p->data.hello;
	// Sending information to the new node
	{
		int ret;
		uint8_t node_id;
		debug ( 15, "Preparing a welcome message for nodename \"%s\" from nodename == \"%s\"", data_hello_p->node_name, ctx_p->cluster_nodename );
		size_t data_len = sizeof ( clustercmd_welcome_t ) + clustercmd_p->h.data_len + ctx_p->cluster_nodename_len;
		clustercmd_t *answer_p = CLUSTER_ALLOCA ( void, data_len );
		clustercmd_welcome_t *answer_data_p = &answer_p->data.welcome;
		answer_data_p->from_node_name_len = ctx_p->cluster_nodename_len;
		memcpy ( answer_data_p->from_node_name, ctx_p->cluster_nodename, ctx_p->cluster_nodename_len );
		memcpy ( welcome_to_node_name ( answer_data_p ), data_hello_p->node_name, clustercmd_p->h.data_len );
		{
			void *ptr;
			char *node_name = alloca ( clustercmd_p->h.data_len + 1 );
			memcpy ( node_name, data_hello_p->node_name, clustercmd_p->h.data_len + 1 );
			ptr = g_hash_table_lookup ( indexes_p->nodenames_ht, node_name );
			node_id = ( ptr == NULL ? NODEID_NOID : GPOINTER_TO_INT ( ptr ) );
			debug ( 3, "\"%s\" -> %i", node_name, node_id );
		}
		answer_p->h.data_len    = data_len;
		answer_p->h.cmd_id      = CLUSTERCMDID_WELCOME;
		answer_p->h.dst_node_id = node_id; // broadcast

		if ( ( ret = cluster_send ( answer_p ) ) )
			return ret;
	}
	return 0;
}


/**
 * @brief 			recvproc-function for register-messages
 *
 * @param[in] 	clustercmd_p 	Pointer to clustercmd
 *
 * @retval	zero 		Successfully initialized.
 * @retval	non-zero 	Got error, while initializing.
 *
 */

static int cluster_recvproc_register ( clustercmd_t *clustercmd_p )
{
	clustercmd_reg_t *data_register_p = &clustercmd_p->data.reg;
	char *node_name = alloca ( clustercmd_p->h.data_len + 1 );
	memcpy ( node_name, data_register_p->node_name, clustercmd_p->h.data_len + 1 );
	node_update_name ( clustercmd_p->h.src_node_id, node_name );
	return 0;
}

extern int cluster_loop();
/**
 * @brief 			Initializes cluster subsystem.
 *
 * @param[in] 	_ctx_p 	Pointer to "glob" variable, defined in main().
 * @param[in] 	_indexes_p	Pointer to "indexes" variable, defined in sync_run().
 *
 * @retval	zero 		Successfully initialized.
 * @retval	non-zero 	Got error, while initializing.
 *
 */

int cluster_init ( ctx_t *_ctx_p, indexes_t *_indexes_p )
{
	int ret;

	// Preventing double initializing
	if ( ctx_p != NULL ) {
		error ( "cluster subsystem is already initialized." );
		return EALREADY;
	}

	// Initializing global variables, pt. 1
	ctx_p		= _ctx_p;
	indexes_p	= _indexes_p;
	cluster_timeout	= ctx_p->cluster_timeout;
	indexes_p->nodenames_ht = g_hash_table_new_full ( g_str_hash,	  g_str_equal,	  free, 0 );
	node_update_status ( NODEID_NOID, NODESTATUS_ONLINE );
	{
		int i = 0;

		while ( i < MAXNODES ) {
			nodeinfo[i].last_serial = -1;
			i++;
		}
	}
	// Initializing network routines
	// 	Input socket
	//		Creating socket
	sock_i = socket ( AF_INET, SOCK_DGRAM, 0 );

	if ( sock_i < 0 ) {
		error ( "Cannot create socket for input traffic" );
		return errno;
	}

	// 		Enable SO_REUSEADDR to allow multiple instances of this application to receive copies
	// 		of the multicast datagrams.
	int reuse = 1;

	if ( setsockopt ( sock_i, SOL_SOCKET, SO_REUSEADDR, ( char * ) &reuse, sizeof ( reuse ) ) < 0 ) {
		error ( "Got error while setsockopt()" );
		return errno;
	}

	//		Binding
	sa_i.sin_family		= AF_INET;
	sa_i.sin_port 		= htons ( ctx_p->cluster_mcastipport );
	sa_i.sin_addr.s_addr	= INADDR_ANY;

	if ( bind ( sock_i, ( struct sockaddr* ) &sa_i, sizeof ( sa_i ) ) ) {
		error ( "Got error while bind()" );
		return errno;
	}

	//		Joining to multicast group
	struct ip_mreq group;
	group.imr_interface.s_addr = inet_addr ( ctx_p->cluster_iface );
	group.imr_multiaddr.s_addr = inet_addr ( ctx_p->cluster_mcastipaddr );

	if ( setsockopt ( sock_i, IPPROTO_IP, IP_ADD_MEMBERSHIP,
	                  ( char * ) &group, sizeof ( group ) ) < 0 ) {
		error ( "Cannot setsockopt() to enter to membership %s -> %s",
		        ctx_p->cluster_iface, ctx_p->cluster_mcastipaddr );
		return errno;
	}

	//	Output socket
	//		Creating socket
	sock_o = socket ( AF_INET, SOCK_DGRAM, 0 );

	if ( sock_o < 0 ) {
		error ( "Cannot create socket for output traffic" );
		return errno;
	}

	//		Initializing the group sockaddr structure
	sa_o.sin_family		= AF_INET;
	sa_o.sin_port 		= htons ( ctx_p->cluster_mcastipport );
	sa_o.sin_addr.s_addr	= inet_addr ( ctx_p->cluster_mcastipaddr );
	//		Disable looping back output datagrams
	{
		char loopch = 0;

		if ( setsockopt ( sock_o, IPPROTO_IP, IP_MULTICAST_LOOP, ( char * ) &loopch, sizeof ( loopch ) ) < 0 ) {
			error ( "Cannot disable loopback for output socket." );
			return errno;
		}
	}
	//		Setting local interface for output traffic
	{
		struct in_addr addr_o;
		addr_o.s_addr = inet_addr ( ctx_p->cluster_iface );

		if ( setsockopt ( sock_o, IPPROTO_IP, IP_MULTICAST_IF, &addr_o, sizeof ( addr_o ) ) < 0 ) {
			error ( "Cannot set local interface for outbound traffic" );
			return errno;
		}
	}
	// Initializing another routines
	cluster_io_init();
	// Getting my ID in the cluster
	//	Trying to preserve my node_id after restart. :)
	//	Asking another nodes about my previous node_id
	{
		debug ( 15, "Preparing a message with my nodename == \"%s\" (%i)", ctx_p->cluster_nodename, ctx_p->cluster_nodename_len );
		clustercmd_t *clustercmd_p = CLUSTER_ALLOCA ( clustercmd_hello_t, ctx_p->cluster_nodename_len );
		clustercmd_p->h.data_len = ctx_p->cluster_nodename_len;
		memcpy ( clustercmd_p->data.hello.node_name, ctx_p->cluster_nodename, clustercmd_p->h.data_len + 1 );
		clustercmd_p->h.cmd_id      = CLUSTERCMDID_HELLO;
		clustercmd_p->h.dst_node_id = NODEID_NOID; // broadcast

		if ( ( ret = cluster_send ( clustercmd_p ) ) )
			return ret;
	}
	//	Processing answers
	cluster_recv_proc_set ( CLUSTERCMDID_WELCOME, cluster_recvproc_welcome );

	if ( ( ret = cluster_recv_proc ( cluster_timeout ) ) )
		return ret;

	//	Ignore next welcome messages
	cluster_recv_proc_set ( CLUSTERCMDID_WELCOME, NULL );
	debug ( 3, "After communicating with others, my node_id is %i.", node_id_my );

	//	Getting free node_id if nobody said us the certain value (see above).
	if ( node_id_my == NODEID_NOID ) {
		int i = 0;

		while ( i < MAXNODES ) {
			if ( nodeinfo[i].status == NODESTATUS_DOESNTEXIST ) {
				node_id_my = i;
				break;
			}

			i++;
		}

		debug ( 3, "I was have to set my node_id to %i.", node_id_my );
	}

	//	If there's no free id-s, then exit :(
	if ( node_id_my == NODEID_NOID ) {
		error ( "Cannot find free node ID. Seems, that all %i ID-s are already occupied." );
		return ENOMEM;
	}

	// Initializing global variables, pt. 2
	nodeinfo_my = &nodeinfo[node_id_my];
	// Registering in the cluster
	// 	Sending registration information
	node_update_status ( node_id_my, NODESTATUS_SEEMSONLINE );
	{
		clustercmd_t *clustercmd_p = CLUSTER_ALLOCA ( clustercmd_reg_t, ctx_p->cluster_nodename_len );
		clustercmd_reg_t *data_reg_p = &clustercmd_p->data.reg;
		memcpy ( data_reg_p->node_name, ctx_p->cluster_nodename, ctx_p->cluster_nodename_len + 1 );
		clustercmd_p->h.data_len    = ctx_p->cluster_nodename_len + 1;
		clustercmd_p->h.cmd_id      = CLUSTERCMDID_REG;
		clustercmd_p->h.dst_node_id = NODEID_NOID; // broadcast

		if ( ( ret = cluster_send ( clustercmd_p ) ) )
			return ret;
	}
	//	Setting process functions
	cluster_recv_proc_set ( CLUSTERCMDID_HELLO,	cluster_recvproc_hello );
	cluster_recv_proc_set ( CLUSTERCMDID_REG,		cluster_recvproc_register );

	// 	Getting answers
	if ( ( ret = cluster_recv_proc ( cluster_timeout ) ) )
		return ret;

	node_update_status ( node_id_my, NODESTATUS_ONLINE );
	// Running thread, that will process background communicating routines with another nodes.
	// The process is based on function cluster_loop() [let's use shorthand "cluster_loop()-thread"]
	ret = pthread_create ( &pthread_cluster, NULL, ( void * ( * ) ( void * ) ) cluster_loop, NULL );
	return ret;
}

/**
 * @brief 			(syncop) Sends signal to cluster_loop()-thread
 *
 * @param[in] 	signal 		Signal number
 *
 * @retval	zero 		Successfully send the signal
 * @retval	non-zero 	Got error, while sending the signal
 *
 */

static inline int cluster_signal ( int signal )
{
	if ( pthread_cluster )
		return pthread_kill ( pthread_cluster, signal );

	return 0;
}


extern int cluster_modtime_exchange_cleanup();
/**
 * @brief 			Antagonist of cluster_init() function. Kills cluster_loop()-thread and cleaning up
 *
 * @retval	zero 		Successfully initialized
 * @retval	non-zero 	Got error, while initializing
 *
 */

int cluster_deinit()
{
	int ret = 0;
	cluster_signal ( SIGTERM );
	ret = pthread_join ( pthread_cluster, NULL );
	cluster_io_deinit();
	node_update_status ( NODEID_NOID, NODESTATUS_DOESNTEXIST );
#ifdef VERYPARANOID
	int i = 0;
#endif

	while ( node_count ) {
#ifdef VERYPARANOID

		if ( i++ > MAXNODES ) {
			error ( "cluster_deinit() looped. Forcing break." );
			break;
		}

#endif
		node_update_status ( 0, NODESTATUS_DOESNTEXIST );
	}

	close ( sock_i );
	close ( sock_o );
#ifdef VERYPARANOID
	memset ( nodeinfo, 0, sizeof ( nodeinfo_t ) * NODES_ALLOC );
	nodeinfo_my = NULL;
	node_count  = 0;
	node_online = 0;
	node_id_my  = NODEID_NOID;
	memset ( &sa_i,	0, sizeof ( sa_i ) );
	memset ( &sa_o,	0, sizeof ( sa_o ) );
#endif
	cluster_modtime_exchange_cleanup();
	g_hash_table_destroy ( indexes_p->nodenames_ht );
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

int cluster_lock ( const char *fpath )
{
	( void ) fpath;

	return 0;
}


/**
 * @brief 			(syncop) Forces anothes nodes to ignore events about all files and directories listed in queues of "indexes_p"
 *
 * @retval	zero 		Successfully initialized
 * @retval	non-zero 	Got error, while initializing
 *
 */

int cluster_lock_byindexes()
{
	return 0;
}


/**
 * @brief 			(syncop) Returns events-handling on another nodes about all files and directories, locked by cluster_lock() and cluster_lock_byindexes() from this node
 *
 * @retval	zero 		Successfully initialized
 * @retval	non-zero 	Got error, while initializing
 *
 */

int cluster_unlock_all()
{
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

int cluster_loop()
{
	int ret = 0;
	sigset_t sigset_cluster;
	// Ignoring SIGINT signal
	sigemptyset ( &sigset_cluster );
	sigaddset ( &sigset_cluster, SIGINT );
	CLUSTER_LOOP_CHECK ( pthread_sigmask ( SIG_BLOCK, &sigset_cluster, NULL ) );
	// Don't ignoring SIGTERM signal
	sigemptyset ( &sigset_cluster );
	sigaddset ( &sigset_cluster, SIGTERM );
	CLUSTER_LOOP_CHECK ( pthread_sigmask ( SIG_UNBLOCK, &sigset_cluster, NULL ) );
	// Starting the loop
	debug ( 3, "cluster_loop() started." );

	while ( 1 ) {
		int _ret;
		// Waiting for event
		fd_set rfds;
		FD_ZERO ( &rfds );
		FD_SET ( sock_i, &rfds );
		debug ( 3, "select()" );
		_ret = select ( sock_i + 1, &rfds, NULL, NULL, NULL );

		// Exit if error
		if ( ( _ret == -1 ) && ( errno != EINTR ) ) {
			ret = errno;
			sync_term ( ret );
			break;
		}

		// Breaking the loop, if there's SIGTERM signal for this thread
		debug ( 3, "sigpending()" );

		if ( sigpending ( &sigset_cluster ) )
			if ( sigismember ( &sigset_cluster, SIGTERM ) )
				break;

		// Processing new messages
		debug ( 3, "cluster_recv_proc()" );

		if ( ( ret = cluster_recv_proc ( 0 ) ) ) {
			sync_term ( ret );
			break;
		}
	}

	debug ( 3, "cluster_loop() finished with exitcode %i.", ret );
	return ret;
#ifdef DOXYGEN
	sync_term ( 0 );
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

int cluster_modtime_update ( const char *path, short int dirlevel, mode_t st_mode )
{
	// "modtime" is incorrent name-part of function. Actually it updates "change time" (man 2 lstat64).
	int ret;
	// Getting relative directory level (depth)
	short int dirlevel_rel = dirlevel - ctx_p->watchdir_dirlevel;

	if ( ( st_mode & S_IFMT ) == S_IFDIR )
		dirlevel_rel++;

	// Don't remembering information about directories with level beyond the limits
	if ( ( dirlevel_rel > ctx_p->cluster_scan_dl_max ) || ( dirlevel_rel < ctx_p->cluster_hash_dl_min ) )
		return 0;

	// Getting directory/file-'s information (including "change time" aka "st_ctime")
	stat64_t stat64;
	ret = lstat64 ( path, &stat64 );

	if ( ret ) {
		error ( "Cannot lstat64()", path );
		return errno;
	}

	// Getting absolute directory path
	const char *dirpath;

	if ( ( st_mode & S_IFMT ) == S_IFDIR ) {
		dirpath = path;
	} else {
		char *path_dup = strdup ( path );
		dirpath = ( const char * ) dirname ( path_dup );
		free ( path_dup );
	}

	// Getting relative directory path
	//	Initializing
	size_t  dirpath_len   = strlen ( dirpath );
	char   *dirpath_rel_p = xmalloc ( dirpath_len + 1 );
	char   *dirpath_rel   = dirpath_rel_p;
	const char *dirpath_rel_full     = &dirpath[ctx_p->watchdirlen];
	size_t      dirpath_rel_full_len = dirpath_len - ctx_p->watchdirlen;
	// 	Getting coodinate of the end (directory path is already canonized, so we can simply count number of slashes to get directory level)
	int     slashcount = 0;
	size_t  dirpath_rel_end = 0;

	while ( dirpath_rel_full[dirpath_rel_end] && ( dirpath_rel_end < dirpath_rel_full_len ) ) {
		if ( dirpath_rel_full[dirpath_rel_end] == '/' ) {
			slashcount++;

			if ( slashcount >= ctx_p->cluster_hash_dl_max )
				break;
		}

		dirpath_rel_end++;
	}

	//	Copy the required part of path to dirpath_rel
	memcpy ( dirpath_rel, dirpath_rel_full, dirpath_rel_end );
	// Updating "st_ctime" information. We should check current value for this directory and update it only if it less or not set.
	//	Checking current value
	char toupdate = 0;
	gpointer ctime_gp = g_hash_table_lookup ( nodeinfo_my->modtime_ht, dirpath_rel );

	if ( ctime_gp == NULL )
		toupdate++;
	else if ( GPOINTER_TO_INT ( ctime_gp ) < stat64.st_ctime )
		toupdate++;

	//	g_hash_table_replace() will replace existent information about the directory or create it if it doesn't exist.
	if ( toupdate )
		g_hash_table_replace ( nodeinfo_my->modtime_ht, strdup ( dirpath_rel ), GINT_TO_POINTER ( stat64.st_ctime ) );

	// Why I'm using "st_ctime" instead of "st_mtime"? Because "st_ctime" also updates on updating inode information.
	return 0;
}


/**
 * @brief 			Puts entry to list to be send to other nodes. To be called from cluster_modtime_exchange()
 *
 * @param[in] 	pushrentry_arg_p Pointer to pushentry_arg structure
 *
 */

void cluster_modtime_exchange_pushentry ( gpointer dir_gp, gpointer modtype_gp, void *pushentry_arg_gp )
{
	struct pushdoubleentry_arg *pushentry_arg_p = ( struct pushdoubleentry_arg * ) pushentry_arg_gp;
	char  *dir   = ( char * ) dir_gp;
	time_t ctime = ( time_t ) GPOINTER_TO_INT ( modtype_gp );
	size_t size  = strlen ( dir ) + 1;				// TODO: strlen should be already prepared
	// but not re-calculated here

	if ( pushentry_arg_p->allocated <= pushentry_arg_p->total ) {
		pushentry_arg_p->allocated += ALLOC_PORTION;
		pushentry_arg_p->entry      = ( struct doubleentry * )
		                              xrealloc (
		                                  ( char * ) pushentry_arg_p->entry,
		                                  pushentry_arg_p->allocated * sizeof ( *pushentry_arg_p->entry )
		                              );
	}

	pushentry_arg_p->entry[pushentry_arg_p->total].dat0  = dir;
	pushentry_arg_p->entry[pushentry_arg_p->total].size0 = size;
	pushentry_arg_p->entry[pushentry_arg_p->total].dat1  = ( void * ) ctime;	// Will be problems if sizeof(time_t) > sizeof(void *)
	pushentry_arg_p->entry[pushentry_arg_p->total].size1 = sizeof ( ctime );
	pushentry_arg_p->size += size;
	pushentry_arg_p->total++;
	return;
}


static struct pushdoubleentry_arg cluster_modtime_exchange_pushentry_arg = {0};
/**
 * @brief 			Clean up after the last run of cluster_modtime_exchange.
 *
 * @retval	zero 		Successfully initialized
 * @retval	non-zero 	Got error, while initializing
 *
 */

int cluster_modtime_exchange_cleanup()
{
	struct pushdoubleentry_arg *pushentry_arg_p = &cluster_modtime_exchange_pushentry_arg;
	int i = 0;

	while ( i < pushentry_arg_p->allocated ) {
		if ( pushentry_arg_p->entry[i].alloc0 )
			free ( pushentry_arg_p->entry[i].dat0 );

		if ( pushentry_arg_p->entry[i].alloc1 )
			free ( pushentry_arg_p->entry[i].dat1 );

		i++;
	}

	free ( pushentry_arg_p->entry );
#ifdef VERYPARANOID
	memset ( pushentry_arg_p, 0, sizeof ( *pushentry_arg_p ) );
#endif
	return 0;
}


/**
 * @brief 			Exchanging with "modtime_ht"-s to be able to compare them.
 *
 * @retval	zero 		Successfully initialized
 * @retval	non-zero 	Got error, while initializing
 *
 */

int cluster_modtime_exchange()
{
	struct pushdoubleentry_arg *pushentry_arg_p = &cluster_modtime_exchange_pushentry_arg;
	// Getting hash table entries
	pushentry_arg_p->size = 0;
	pushentry_arg_p->total = 0;
	g_hash_table_foreach ( nodeinfo_my->modtime_ht, cluster_modtime_exchange_pushentry, ( void * ) pushentry_arg_p );

	if ( !pushentry_arg_p->total ) {
		// !!!
	}

	// Calculating required RAM to compile clustercmd
	size_t toalloc = 0;
	int i = 0;

	while ( i < pushentry_arg_p->total ) {
		toalloc += 4;					// for size header
		toalloc += pushentry_arg_p->entry[i].size0;	// for path
		toalloc += pushentry_arg_p->entry[i].size1;	// for ctime
	}

	// Allocating space for the clustercmd
	clustercmd_t *clustercmd_p = ( clustercmd_t * ) xmalloc ( sizeof ( clustercmdhdr_t ) + toalloc );
	memset ( clustercmd_p, 0, sizeof ( clustercmdhdr_t ) );
	// Setting up clustercmd
	clustercmd_p->h.dst_node_id	= NODEID_NOID;
	clustercmd_p->h.cmd_id		= CLUSTERCMDID_HT_EXCH;
	clustercmd_p->h.data_len	= toalloc;
	// Filing clustercmd with hash-table entriyes
	i = 0;
	clustercmd_ht_exch_t *clustercmd_ht_exch_p = &clustercmd_p->data.ht_exch;

	while ( i < pushentry_arg_p->total ) {
		// Setting the data
		clustercmd_ht_exch_p->ctime       = ( time_t ) pushentry_arg_p->entry[i].dat1;
		clustercmd_ht_exch_p->path_length = ( time_t ) pushentry_arg_p->entry[i].size0;
		memcpy (
		    clustercmd_ht_exch_p->path,
		    pushentry_arg_p->entry[i].dat0,
		    clustercmd_ht_exch_p->path_length
		);
		// Pointing to space for next entry:
		size_t offset = sizeof ( clustercmd_ht_exch_t ) - 1 + pushentry_arg_p->entry[i].size0;
		clustercmd_ht_exch_p = ( clustercmd_ht_exch_t * )
		                       ( & ( ( char * ) clustercmd_ht_exch_p ) [offset] );
	}

	// Sending
	cluster_send ( clustercmd_p );
	// Cleanup
	free ( clustercmd_p );
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

int cluster_initialsync()
{
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

int cluster_capture ( const char *path )
{
	( void ) path;

	return 0;
}

#endif

