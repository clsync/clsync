/*
    clsync - file tree sync utility based on inotify/kqueue
    
    Copyright (C) 2013-2015 Dmitry Yu Okunev <dyokunev@ut.mephi.ru> 0x8E30679C
    
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

#ifndef __CLSYNC_FILETREE_CACHE_H
#define __CLSYNC_FILETREE_CACHE_H

struct filetree_cache_entry_data {
	stat64_t	stat;
	size_t		path_len;
	char		path[PATH_MAX+1];
};
typedef struct filetree_cache_entry_data filetree_cache_entry_data_t;


struct filetree_cache_entry {
	size_t		id;
	char		to_delete;
	char		is_synced;
	char		is_saved;
	char		is_marked;
	filetree_cache_entry_data_t dat;
};
typedef struct filetree_cache_entry filetree_cache_entry_t;

extern int filetree_cache_flush(ctx_t *ctx_p, char dontunlock);
extern int filetree_cache_load(ctx_t *ctx_p);
extern int filetree_cache_save(ctx_t *ctx_p);

extern int filetree_cache_add(ctx_t *ctx_p, filetree_cache_entry_data_t *entry);
extern int filetree_cache_update(ctx_t *ctx_p, filetree_cache_entry_data_t *entry);
extern int filetree_cache_set(ctx_t *ctx_p, filetree_cache_entry_data_t *entry);
extern int filetree_cache_del(ctx_t *ctx_p, const char *path);
extern int filetree_cache_queueadd(ctx_t *ctx_p, const char *path, stat64_t *st_p);
extern int filetree_cache_queuedel(ctx_t *ctx_p, const char *path);
extern int filetree_cache_queueflush(ctx_t *ctx_p);

static inline filetree_cache_entry_t *filetree_cache_get(ctx_t *ctx_p, const char *path) {
	filetree_cache_entry_t *r = indexes_filetreecache_get(ctx_p->indexes_p, path);
	debug(8, "\"%s\" => %p", path, r);
	return r;
}

static inline char filetree_cache_comparestat(filetree_cache_entry_t *entry, stat64_t *stat) {	// TODO: Consider deduplication with fileutils.c:stat_diff()
	stat64_t stcmp_a, stcmp_b;

	memcpy(&stcmp_a,  stat,		   sizeof(*stat));
	memcpy(&stcmp_b, &entry->dat.stat, sizeof(entry->dat.stat));

	stcmp_a.st_nlink = stcmp_b.st_nlink = 0; // Do not compare amount of hard links

	return memcmp(&stcmp_a, &stcmp_b, sizeof(stcmp_a));
}

static inline void filetree_cache_setdatato(filetree_cache_entry_data_t *entrydat, const char *path, stat64_t *st_p) {
	memcpy(&entrydat->stat, st_p, sizeof(entrydat->stat));
	entrydat->path_len = strlen(path);
	memcpy( entrydat->path, path, entrydat->path_len);

	return;
}

#endif

