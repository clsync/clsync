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

#ifdef CLUSTER_SUPPORT

// Macros for reading messages

#define CLUSTER_RESTDATALEN(clustercmd_p, data_type) \
	((clustercmd_p)->h.data_len - sizeof(data_type) + sizeof(char *))

#define CLUSTER_LOOP_EXPECTCMD(clustercmd_p, clustercmd_id, ret) {\
		/* Exit if error */ \
		if(ret == -1) { \
			error("CLUSTER_LOOP_EXPECTCMD()"); \
			return errno; \
		}\
\
		/* Is that the command we are expecting? Skipping if not. */\
		if(clustercmd_p->h.cmd_id != clustercmd_id)\
			continue;\
}

// Macros for writing messages

//	calculated required memory for clustercmd packet
#define CLUSTER_REQMEM(data_type, restdata_len) \
	(sizeof(clustercmdhdr_t) + sizeof(data_type) + (restdata_len) + 2)

//	calculated required memory for clustercmd packet with padding
#define CLUSTER_REQMEM_PADDED(data_type, restdata_len) \
	CLUSTER_PAD(CLUSTER_REQMEM(data_type, restdata_len))

//	allocated memory for clustercmd packet with padding
#define CLUSTER_ALLOC(data_type, restdata_len, alloc_funct)\
	(clustercmd_t *)memset((alloc_funct)(CLUSTER_REQMEM_PADDED(data_type, restdata_len)), 0, CLUSTER_REQMEM_PADDED(data_type, restdata_len))

//	allocated memory for clustercmd packet with padding with alloca()
#define CLUSTER_ALLOCA(data_type, restdata_len)\
	CLUSTER_ALLOC(data_type, restdata_len, alloca)

//	allocated memory for clustercmd packet with padding with xmalloc()
#define CLUSTER_MALLOC(data_type, restdata_len)\
	CLUSTER_ALLOC(data_type, restdata_len, xmalloc)

// Common macros

#define CLUSTER_PAD(size) ((((size) + 3) >> 2) << 2)

#define CLUSTERCMD_SIZE(clustercmd_p)        (sizeof(clustercmdhdr_t) +             (*(clustercmd_p)).h.data_len)
#define CLUSTERCMD_SIZE_PADDED(clustercmd_p) (sizeof(clustercmdhdr_t) + CLUSTER_PAD((*(clustercmd_p)).h.data_len))

// Types

enum adler32_calc {
	ADLER32_CALC_NONE		= 0x00,
	ADLER32_CALC_HEADER	= 0x01,
	ADLER32_CALC_DATA		= 0x02,
	ADLER32_CALC_ALL		= 0x03,
};
typedef enum adler32_calc adler32_calc_t;

enum cluster_read_flags {
	CLREAD_NONE		= 0x00,
	CLREAD_CONTINUE		= 0x01,
	CLREAD_ALL		= 0xff
};
typedef enum cluster_read_flags cluster_read_flags_t;

enum nodestatus {
	NODESTATUS_DOESNTEXIST = 0,
	NODESTATUS_OFFLINE,
	NODESTATUS_SEEMSONLINE,
	NODESTATUS_ONLINE,
	NODESTATUS_BANNED
};
typedef enum nodestatus nodestatus_t;

enum nodeid {
	NODEID_NOID		= MAXNODES
};
typedef enum nodeid nodeid_t;

struct packets_stats {
	uint64_t	 tot;
	uint64_t	 rej;
};
typedef struct packets_stats packets_stats_t;

struct nodeinfo {
	uint8_t      	 id;
	uint8_t      	 num;
	nodestatus_t 	 status;
	uint32_t    	 updatets;
	GHashTable  	*modtime_ht;
	GHashTable	*serial2queuedpacket_ht;
	packets_stats_t	 packets_in;
	packets_stats_t	 packets_out;
	uint32_t	 last_serial;
};
typedef struct nodeinfo nodeinfo_t;

enum clustercmd_id {
	CLUSTERCMDID_PING 	= 0,
	CLUSTERCMDID_ACK 	= 1,
	CLUSTERCMDID_REG 	= 2,
	CLUSTERCMDID_GETMYID	= 3,
	CLUSTERCMDID_SETID	= 4,
	CLUSTERCMDID_HT_EXCH	= 5,
	COUNT_CLUSTERCMDID
};
typedef enum clustercmd_id clustercmd_id_t;

struct clustercmd_getmyid {
	char      node_name[1];
};
typedef struct clustercmd_getmyid clustercmd_getmyid_t;

struct clustercmd_setiddata {
	uint32_t  updatets;
	char      node_name[1];
};
typedef struct clustercmd_setiddata clustercmd_setiddata_t;

struct clustercmd_reg {
	char      node_name[1];
};
typedef struct clustercmd_reg clustercmd_reg_t;

struct clustercmd_ack {
	uint32_t serial;
};
typedef struct clustercmd_ack clustercmd_ack_t;

enum reject_reason {
	REJ_UNKNOWN		= 0,
	REJ_adler32MISMATCH,
};
typedef enum reject_reason reject_reason_t;

struct clustercmd_rej {
	uint32_t serial;
	uint8_t	 reason;
};
typedef struct clustercmd_rej clustercmd_rej_t;

struct clustercmd_ht_exch {
	time_t	 ctime;
	size_t	 path_length;
	char	 path[1];
};
typedef struct clustercmd_ht_exch clustercmd_ht_exch_t;

struct clustercmdadler32 {
	uint32_t hdr;
	uint32_t dat;
};
typedef struct clustercmdadler32 clustercmdadler32_t;

struct clustercmdhdr {					// bits
	uint8_t			dst_node_id;		// 8
	uint8_t			src_node_id;		// 16
	uint8_t			flags;			// 24	(for future compatibility)
	uint8_t			cmd_id;			// 32
	clustercmdadler32_t	adler32;		// 64
	uint32_t		data_len;		// 96
	uint32_t		ts;			// 128
	uint32_t		serial;			// 160
};
typedef struct clustercmdhdr clustercmdhdr_t;

struct clustercmd {
	clustercmdhdr_t h;
	union data {
		char 			p[1];
		clustercmd_setiddata_t	setid;
		clustercmd_reg_t	reg;
		clustercmd_ack_t	ack;
		clustercmd_rej_t	rej;
		clustercmd_getmyid_t	getmyid;
		clustercmd_ht_exch_t	ht_exch;
	} data;
};
typedef struct clustercmd clustercmd_t;

struct clustercmdqueuedpackethdri {
	char	dummy; // anti-warning
};
typedef struct clustercmdqueuedpackethdri clustercmdqueuedpackethdri_t;

struct clustercmdqueuedpackethdro {
	char 		ack_from[MAXNODES];
	uint8_t 	ack_count;
};
typedef struct clustercmdqueuedpackethdro clustercmdqueuedpackethdro_t;

struct clustercmdqueuedpackethdr {
	unsigned int	window_id;
	union w {
		clustercmdqueuedpackethdri_t i;
		clustercmdqueuedpackethdro_t o;
	} w;
};
typedef struct clustercmdqueuedpackethdr clustercmdqueuedpackethdr_t;

struct clustercmdqueuedpacket {
	clustercmdqueuedpackethdr_t	h;
	clustercmd_t 			cmd;
};
typedef struct clustercmdqueuedpacket clustercmdqueuedpacket_t;

struct window_occupied_sides {
	size_t	left;
	size_t	right;
};
typedef struct window_occupied_sides window_occupied_sides_t;

struct window {
	unsigned int		  size;			// Allocated cells
	unsigned int		  packets_len;		// Count of packets (are waiting for ACK-s)
	unsigned int		 *packets_id;		// Array of cells' id-s with packets
	window_occupied_sides_t	 *occupied_sides;	// Array of structures with coordinates in buffer of occupied space by cell ida (aka window_id)
	size_t			  buf_size;		// Allocated space of the buffer
	char 			 *buf;			// Pointer to the buffer
};
typedef struct window window_t;

typedef int (*cluster_recvproc_funct_t)(clustercmd_t *clustercmd_p);

// Externs

extern int cluster_init(glob_t *glob_p, indexes_t *indexes_p);
extern int cluster_deinit();

extern int cluster_lock(const char *fpath);
extern int cluster_lock_byindexes();
extern int cluster_unlock_all();
extern int cluster_capture(const char *fpath);

extern int cluster_modtime_update(const char *dirpath, short int dirlevel, mode_t st_mode);
extern int cluster_initialsync();

#endif

