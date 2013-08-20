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
	((clustercmd_p)->data_len - sizeof(data_type) + sizeof(char *))

#define CLUSTER_LOOP_EXPECTCMD(clustercmd_p, clustercmd_id, ret) {\
		/* Exit if error */ \
		if(ret == -1) { \
			printf_e("Error: cluster_init(): Got error while cluster_recv(): %s (%i).\n", strerror(errno), errno); \
			return errno; \
		}\
\
		/* Is that the command we are expecting? Skipping if not. */\
		if(clustercmd_p->cmd_id != clustercmd_id)\
			continue;\
}

// Macros for writing messages

#define CLUSTER_REQMEM(data_type, restdata_len) \
	(sizeof(clustercmd_t)-1 + sizeof(data_type)-1 + (restdata_len) + 2)

#define CLUSTER_ALLOC(clustercmd_p, data_type, t_data_p, restdata_len, alloc_funct)\
	clustercmd_t *clustercmd_p = (clustercmd_t *)(alloc_funct)(CLUSTER_REQMEM(data_type, restdata_len));\
	PARANOIDV(memset(clustercmd_p, 0, CLUSTER_REQMEM(data_type, restdata_len)));\
	data_type *t_data_p = (data_type *)clustercmd_p->data_p;\
	(void)t_data_p; /* anti-warning */

#define CLUSTER_ALLOCA(clustercmd_p, data_type, data_p, restdata_len)\
	CLUSTER_ALLOC(clustercmd_p, data_type, data_p, restdata_len, alloca)

#define CLUSTER_MALLOC(clustercmd_p, data_type, data_p, restdata_len)\
	CLUSTER_ALLOC(clustercmd_p, data_type, data_p, restdata_len, xmalloc)

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
};
typedef enum clustercmd_id clustercmd_id_t;

struct clustercmd {
	uint32_t  crc32;
	uint8_t   node_id;
	uint8_t   cmd_id;
	uint32_t  data_len;
	uint32_t  ts;
	uint32_t  serial;
	char      data_p[1];
};
typedef struct clustercmd clustercmd_t;

struct clustercmd_setiddata {
	uint8_t   node_id;
	uint32_t  updatets;
	char      node_name[1];
};
typedef struct clustercmd_setiddata clustercmd_setiddata_t;

struct clustercmd_register {
	char     node_name[1];
};
typedef struct clustercmd_register clustercmd_register_t;

struct clustercmd_ack {
	uint8_t  node_id;
	uint32_t serial;
};
typedef struct clustercmd_ack clustercmd_ack_t;

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

