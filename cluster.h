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

#ifdef CLUSTER_SUPPORT

// Macros for reading messages

#define CLUSTER_RESTDATALEN(clustercmd_p, data_type) \
	((clustercmd_p)->h.data_len - sizeof(data_type) + sizeof(char *))

#define CLUSTER_LOOP_EXPECTCMD(clustercmd_p, clustercmd_id, ret) {\
		/* Exit if error */ \
		if(ret == -1) { \
			printf_e("Error: CLUSTER_LOOP_EXPECTCMD(): Got error while cluster_recv(): %s (%i).\n", strerror(errno), errno); \
			return errno; \
		}\
\
		/* Is that the command we are expecting? Skipping if not. */\
		if(clustercmd_p->h.cmd_id != clustercmd_id)\
			continue;\
}

// Macros for writing messages

#define CLUSTER_REQMEM(data_type, restdata_len) \
	(sizeof(clustercmdhdr_t) + sizeof(data_type) + (restdata_len) + 2)

#define CLUSTER_ALLOC(data_type, restdata_len, alloc_funct)\
	(clustercmd_t *)PARANOIDV(memset)((alloc_funct)(CLUSTER_REQMEM(data_type, restdata_len))PARANOIDV(, 0, CLUSTER_REQMEM(data_type, restdata_len)))

#define CLUSTER_ALLOCA(data_type, restdata_len)\
	CLUSTER_ALLOC(data_type, restdata_len, alloca)

#define CLUSTER_MALLOC(data_type, restdata_len)\
	CLUSTER_ALLOC(data_type, restdata_len, xmalloc)

// Types

enum nodestatus {
	NODESTATUS_DOESNTEXIST = 0,
	NODESTATUS_OFFLINE,
	NODESTATUS_SEEMSONLINE,
	NODESTATUS_ONLINE
};
typedef enum nodestatus nodestatus_t;

enum nodeid {
	NODEID_NOID		= MAXNODES
};
typedef enum nodeid nodeid_t;

struct nodeinfo {
	uint8_t      id;
	uint8_t      num;
	nodestatus_t status;
	uint32_t     updatets;
	GHashTable  *modtime_ht;
};
typedef struct nodeinfo nodeinfo_t;

enum clustercmd_id {
	CLUSTERCMDID_PING 	= 0,
	CLUSTERCMDID_ACK 	= 1,
	CLUSTERCMDID_REGISTER 	= 2,
	CLUSTERCMDID_GETMYID	= 3,
	CLUSTERCMDID_SETID	= 4,
	COUNT_CLUSTERCMDID
};
typedef enum clustercmd_id clustercmd_id_t;

struct clustercmd_getmyid {
	char     node_name[1];
};
typedef struct clustercmd_getmyid clustercmd_getmyid_t;

struct clustercmd_setiddata {
	uint32_t  updatets;
	char      node_name[1];
};
typedef struct clustercmd_setiddata clustercmd_setiddata_t;

struct clustercmd_register {
	char     node_name[1];
};
typedef struct clustercmd_register clustercmd_register_t;

struct clustercmd_ack {
	uint32_t serial;
};
typedef struct clustercmd_ack clustercmd_ack_t;

struct clustercmdhdr {
	uint8_t   dst_node_id;
	uint8_t   src_node_id;
	uint8_t   cmd_id;
	uint32_t  crc32;
	uint32_t  data_len;
	uint32_t  ts;
	uint32_t  serial;
};
typedef struct clustercmdhdr clustercmdhdr_t;

struct clustercmd {
	clustercmdhdr_t h;
	union {
		char data_p[1];
		clustercmd_setiddata_t	data_setid;
		clustercmd_register_t	data_register;
		clustercmd_ack_t	data_ack;
		clustercmd_getmyid_t	data_getmyid;
	};
};
typedef struct clustercmd clustercmd_t;

struct clustercmdwaitackhdr {
	unsigned int	window_id;
	char 		ack_from[MAXNODES];
	uint8_t 	ack_count;
};
typedef struct clustercmdwaitackhdr clustercmdwaitackhdr_t;

struct clustercmdwaitack {
	clustercmdwaitackhdr_t	h;
	clustercmd_t 		cmd;
};
typedef struct clustercmdwaitack clustercmdwaitack_t;

struct window_busy_sides {
	size_t	left;
	size_t	right;
};
typedef struct window_busy_sides window_busy_sides_t;

struct window {
	unsigned int		  size;
	unsigned int		  packets;
	unsigned int		  used;
	unsigned int		  idstack_len;
	unsigned int		 *idstack;
	char			 *idstacked;
	unsigned int		 *busy_id;
	window_busy_sides_t	 *busy_sides;
	GHashTable		 *serial2waitack_ht;
	size_t			  buf_size;
	char 			 *buf;
};
typedef struct window window_t;

typedef int (*cluster_recvproc_funct_t)(clustercmd_t *clustercmd_p);

// Externs

extern int cluster_init(options_t *options_p, indexes_t *indexes_p);
extern int cluster_deinit();

extern int cluster_lock(const char *fpath);
extern int cluster_lock_byindexes();
extern int cluster_unlock_all();
extern int cluster_capture(const char *fpath);

extern int cluster_modtime_update(const char *dirpath, short int dirlevel, mode_t st_mode);
extern int cluster_initialsync();

#endif

