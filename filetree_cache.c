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

#include "common.h"

#include <errno.h>
#include <assert.h>
#include <assert.h>

#include "indexes.h"
#include "filetree_cache.h"

pthread_mutex_t filetree_cache_mutex = PTHREAD_MUTEX_INITIALIZER;

int
filetree_cache_flush (
		ctx_t *ctx_p,
		char dontunlock
	)
{
	pthread_mutex_lock(&filetree_cache_mutex);

	if (ctx_p->filetree_cache == NULL)
		return 0;

	g_hash_table_remove_all(((indexes_t *)ctx_p->indexes_p)->filetree_cache_ht);

	ctx_p->filetree_cache_len = 0;
	ctx_p->filetree_cache_size = 0;
	free(ctx_p->filetree_cache);
	ctx_p->filetree_cache = NULL;

	if (!dontunlock)
		pthread_mutex_unlock(&filetree_cache_mutex);
	return 0;
}

int
_filetree_cache_add (
		ctx_t *ctx_p,
		filetree_cache_entry_data_t *data_entry
	)
{
	size_t entry_id = ctx_p->filetree_cache_len++;

	if (ctx_p->filetree_cache_len >= ctx_p->filetree_cache_size) {
		filetree_cache_entry_t *old_ptr = ctx_p->filetree_cache;
		ctx_p->filetree_cache_size += ALLOC_PORTION;
		ctx_p->filetree_cache = xrealloc(ctx_p->filetree_cache, sizeof(*ctx_p->filetree_cache) * ctx_p->filetree_cache_size);

		if (old_ptr != ctx_p->filetree_cache) {	// rebuilding indexes if the pointer changed
			indexes_filetreecache_flush(ctx_p->indexes_p);
			size_t i = 0;
			while (i < ctx_p->filetree_cache_len-1)
				indexes_filetreecache_add(ctx_p->indexes_p, &ctx_p->filetree_cache[i++]);
		}
	}

	filetree_cache_entry_t *entry = &ctx_p->filetree_cache[entry_id];

#ifdef PARANOID
	memset(entry, 0, sizeof(*entry))
#else
	entry->is_synced = 0;
	entry->is_saved  = 0;
#endif
	memcpy(&entry->dat, data_entry, sizeof(*data_entry));

	entry->id = entry_id;

	indexes_filetreecache_add(ctx_p->indexes_p, entry);
	return 0;
}

int
_filetree_cache_update (
		ctx_t *ctx_p,
		filetree_cache_entry_t *entry_old,
		filetree_cache_entry_data_t *entry_data_new
	)
{
	if (entry_old == NULL) {
		entry_old = filetree_cache_get(ctx_p, entry_data_new->path);
		if (entry_old == NULL) {
			errno = ENOENT;
			critical("Cannot find a file tree cache entry \"%s\"", entry_data_new->path);
			return errno;
		}
	}

	memcpy(&entry_old->dat, entry_data_new, sizeof(*entry_data_new));

	return 0;
}


// This function shouldn't be used to add entries very often (it may be quite slow for that)
int
filetree_cache_add (
		ctx_t *ctx_p,
		filetree_cache_entry_data_t *data_entry
	)
{
	pthread_mutex_lock(&filetree_cache_mutex);
	int rc = _filetree_cache_add(ctx_p, data_entry);
	pthread_mutex_unlock(&filetree_cache_mutex);
	return rc;
}

int
filetree_cache_update (
		ctx_t *ctx_p,
		filetree_cache_entry_data_t *data_entry
	)
{
	pthread_mutex_lock(&filetree_cache_mutex);
	int rc = _filetree_cache_update(ctx_p, NULL, data_entry);
	pthread_mutex_unlock(&filetree_cache_mutex);
	return rc;
}

// This function shouldn't be used to add entries very often (it may be quite slow for that)
int
filetree_cache_set (
		ctx_t *ctx_p,
		filetree_cache_entry_data_t *data_entry
	)
{
	int rc = 0;
	pthread_mutex_lock(&filetree_cache_mutex);
	filetree_cache_entry_t *entry_old = filetree_cache_get(ctx_p, data_entry->path);

	if (entry_old == NULL)
		rc = _filetree_cache_add(ctx_p, data_entry);
	else
		rc = _filetree_cache_update(ctx_p, entry_old, data_entry);

	pthread_mutex_unlock(&filetree_cache_mutex);
	return rc;
}

int
filetree_cache_del (
		ctx_t *ctx_p,
		const char *path
	)
{
	pthread_mutex_lock(&filetree_cache_mutex);
	filetree_cache_entry_t *entry_del  = filetree_cache_get(ctx_p, path);
	filetree_cache_entry_t *entry_move = &ctx_p->filetree_cache[--ctx_p->filetree_cache_len];

	indexes_filetreecache_del(ctx_p->indexes_p, path);
	indexes_filetreecache_del(ctx_p->indexes_p, entry_move->dat.path);

	size_t entry_id = entry_del->id;
	memcpy(entry_del, entry_move, sizeof(*entry_del));
	ctx_p->filetree_cache[entry_id].id = entry_id;

	indexes_filetreecache_add(ctx_p->indexes_p, entry_move);
	pthread_mutex_unlock(&filetree_cache_mutex);
	return 0;
}



int
filetree_cache_load (	// TODO: Implement mmap() support
		ctx_t *ctx_p
	)
{
	filetree_cache_flush(ctx_p, 1);

	stat64_t st;

	int rc = lstat64(ctx_p->filetree_cache_path, &st);
	if (rc == -1)
		return errno;

	FILE *f = fopen(ctx_p->filetree_cache_path, "r");
	if (f == NULL)
		return errno;

	ctx_p->filetree_cache      = xmalloc(st.st_size);
	ctx_p->filetree_cache_size = st.st_size / sizeof(*ctx_p->filetree_cache);
	do {
		filetree_cache_entry_data_t buf[ALLOC_PORTION];

		size_t r = fread(&buf, sizeof(filetree_cache_entry_data_t), ALLOC_PORTION, f);
		if (ferror(f)) {
#ifdef PARANOID
			assert (errno != 0);
#endif
			return errno;
		}

		size_t i;
		i = 0;
		while (i < r) {
			rc = _filetree_cache_add(ctx_p, &buf[i++]);
			if (rc)
				return rc;
		}
	} while (!feof(f));

	rc = fclose(f);

	pthread_mutex_unlock(&filetree_cache_mutex);

	return rc;
}

int
filetree_cache_save (	// TODO: Implement mmap() support [much faster]
		ctx_t *ctx_p
	)
{
	pthread_mutex_lock(&filetree_cache_mutex);

	FILE *f = fopen(ctx_p->filetree_cache_path, "w");
	if (f == NULL)
		return errno;

	size_t entry_id = 0;
	while (entry_id < ctx_p->filetree_cache_len) {
		filetree_cache_entry_t *entry = &ctx_p->filetree_cache[entry_id++];

		if (entry->is_saved)
			continue;

		int rc = fseek(f, entry_id*sizeof(entry->dat), SEEK_SET);
		if (rc == -1)
			return errno;

		size_t w = fwrite(&entry->dat, sizeof(entry->dat), 1, f);
		if (w != 1) {
#ifdef PARANOID
			assert (errno != 0);
#endif
			return errno;
		}
	};

	pthread_mutex_unlock(&filetree_cache_mutex);
	return 0;
}
