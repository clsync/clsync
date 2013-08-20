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

enum nodestatus {
	NODESTATUS_DOESNTEXIST = 0,
	NODESTATUS_OFFLINE,
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
	CLUSTERCMDID_REGISTER 	= 1,
	CLUSTERCMDID_GETMYID	= 2,
	CLUSTERCMDID_SETID	= 3,
};
typedef enum clustercmd_id clustercmd_id_t;

struct clustercmd {
	uint32_t  crc32;
	uint8_t   node_id;
	uint8_t   cmd_id;
	uint32_t  data_len;
	void     *data_p;
};
typedef struct clustercmd clustercmd_t;

struct clustercmd_setiddata {
	uint8_t  node_id;
	uint32_t updatets;
	char    *node_name;
};

typedef struct clustercmd_setiddata clustercmd_setiddata_t;

extern int cluster_init(options_t *options_p, indexes_t *indexes_p);
extern int cluster_deinit();

extern int cluster_lock(const char *fpath);
extern int cluster_lock_byindexes();
extern int cluster_unlock_all();
extern int cluster_capture(const char *fpath);

extern int cluster_modtime_update(const char *dirpath, short int dirlevel, mode_t st_mode);
extern int cluster_initialsync();

#endif

