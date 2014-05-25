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

#ifndef __CLSYNC_INDEXES_H
#define __CLSYNC_INDEXES_H

#include <glib.h>

#include "common.h"
#include "error.h"
#include "malloc.h"

struct indexes {
	GHashTable *wd2fpath_ht;			// watching descriptor -> file path
	GHashTable *fpath2wd_ht;			// file path -> watching descriptor
	GHashTable *fpath2ei_ht;			// file path -> event information
	GHashTable *exc_fpath_ht;			// excluded file path
	GHashTable *exc_fpath_coll_ht[QUEUE_MAX];	// excluded file path aggregation hashtable for every queue
	GHashTable *fpath2ei_coll_ht[QUEUE_MAX];	// "file path -> event information" aggregation hashtable for every queue
	GHashTable *out_lines_aggr_ht;			// output lines aggregation hashtable
	GHashTable *nonthreaded_syncing_fpath2ei_ht;	// events that are synchronized in signle-mode (non threaded)
};
typedef struct indexes indexes_t;

// Removes necessary rows from hash_tables if some watching descriptor closed
// Return: 0 on success, non-zero on fail

static inline int indexes_remove_bywd(indexes_t *indexes_p, int wd) {
	int ret=0;

	char *fpath = g_hash_table_lookup(indexes_p->wd2fpath_ht, GINT_TO_POINTER(wd));

	ret |= g_hash_table_remove(indexes_p->wd2fpath_ht, GINT_TO_POINTER(wd));
	if(fpath == NULL) {
		error("Cannot remove from index \"fpath2wd\" by wd %i.", wd);
		return -1;
	}
	ret |= g_hash_table_remove(indexes_p->fpath2wd_ht, fpath);

	return ret;
}

// Adds necessary rows to hash_tables if some watching descriptor opened
// Return: 0 on success, non-zero on fail

static inline int indexes_add_wd(indexes_t *indexes_p, int wd, const char *fpath_const, size_t fpathlen) {
	debug(3, "indexes_add_wd(indexes_p, %i, \"%s\", %i)", wd, fpath_const, fpathlen);

	char *fpath = xmalloc(fpathlen+1);
	memcpy(fpath, fpath_const, fpathlen+1);
	g_hash_table_insert(indexes_p->wd2fpath_ht, GINT_TO_POINTER(wd), fpath);
	g_hash_table_insert(indexes_p->fpath2wd_ht, fpath, GINT_TO_POINTER(wd));

	return 0;
}

// Lookups file path by watching descriptor from hash_tables
// Return: file path on success, NULL on fail

static inline char *indexes_wd2fpath(indexes_t *indexes_p, int wd) {
	return g_hash_table_lookup(indexes_p->wd2fpath_ht, GINT_TO_POINTER(wd));
}

//

static inline int indexes_fpath2wd(indexes_t *indexes_p, const char *fpath) {
	gpointer gint_p = g_hash_table_lookup(indexes_p->fpath2wd_ht, fpath);
	if(gint_p == NULL)
		return -1;

	return GPOINTER_TO_INT(gint_p);
}

static inline eventinfo_t *indexes_fpath2ei(indexes_t *indexes_p, const char *fpath) {
	return (eventinfo_t *)g_hash_table_lookup(indexes_p->fpath2ei_ht, fpath);
}

static inline int indexes_fpath2ei_add(indexes_t *indexes_p, char *fpath, eventinfo_t *evinfo) {
	debug(5, "\"%s\"", fpath);
	g_hash_table_replace(indexes_p->fpath2ei_ht, fpath, evinfo);

	return 0;
}

static inline int indexes_queueevent(indexes_t *indexes_p, char *fpath, eventinfo_t *evinfo, queue_id_t queue_id) {

	g_hash_table_replace(indexes_p->fpath2ei_coll_ht[queue_id], fpath, evinfo);

	debug(3, "indexes_queueevent(indexes_p, \"%s\", evinfo, %i). It's now %i events collected in queue %i.", fpath, queue_id, g_hash_table_size(indexes_p->fpath2ei_coll_ht[queue_id]), queue_id);
	return 0;
}

static inline eventinfo_t *indexes_lookupinqueue(indexes_t *indexes_p, const char *fpath, queue_id_t queue_id) {
	return (eventinfo_t *)g_hash_table_lookup(indexes_p->fpath2ei_coll_ht[queue_id], fpath);
}

static inline int indexes_queuelen(indexes_t *indexes_p, queue_id_t queue_id) {
	return g_hash_table_size(indexes_p->fpath2ei_coll_ht[queue_id]);
}

static inline int indexes_removefromqueue(indexes_t *indexes_p, char *fpath, queue_id_t queue_id) {
//	debug(3, "indexes_removefromqueue(indexes_p, \"%s\", %i).", fpath, queue_id);

	g_hash_table_remove(indexes_p->fpath2ei_coll_ht[queue_id], fpath);

	debug(3, "indexes_removefromqueue(indexes_p, \"%s\", %i). It's now %i events collected in queue %i.", fpath, queue_id, g_hash_table_size(indexes_p->fpath2ei_coll_ht[queue_id]), queue_id);
	return 0;
}

static inline int indexes_addexclude(indexes_t *indexes_p, char *fpath, eventinfo_flags_t flags, queue_id_t queue_id) {
	g_hash_table_replace(indexes_p->exc_fpath_coll_ht[queue_id], fpath, GINT_TO_POINTER(flags));

	debug(3, "indexes_addexclude(indexes_p, \"%s\", %i). It's now %i events collected in queue %i.", fpath, queue_id, g_hash_table_size(indexes_p->exc_fpath_coll_ht[queue_id]), queue_id);
	return 0;
}

static inline int indexes_addexclude_aggr(indexes_t *indexes_p, char *fpath, eventinfo_flags_t flags) {
	debug(3, "indexes_addexclude_aggr(indexes_p, \"%s\", %u).", fpath, flags);

	gpointer flags_gp = g_hash_table_lookup(indexes_p->exc_fpath_ht, fpath);
	if(flags_gp != NULL)
		flags |= GPOINTER_TO_INT(flags_gp);

	// Removing extra flags
	if((flags&(EVIF_RECURSIVELY | EVIF_CONTENTRECURSIVELY)) == (EVIF_RECURSIVELY | EVIF_CONTENTRECURSIVELY))
		flags &= ~EVIF_CONTENTRECURSIVELY;

	g_hash_table_replace(indexes_p->exc_fpath_ht, fpath, GINT_TO_POINTER(flags));

	debug(3, "indexes_addexclude_aggr(indexes_p, \"%s\", flags): %u.", fpath, flags);
	return 0;
}

static inline int indexes_outaggr_add(indexes_t *indexes_p, char *outline, eventinfo_flags_t flags) {
	gpointer flags_gp = g_hash_table_lookup(indexes_p->out_lines_aggr_ht, outline);
	if(flags_gp != NULL)
		flags |= GPOINTER_TO_INT(flags_gp);

	// Removing extra flags
	if((flags&(EVIF_RECURSIVELY | EVIF_CONTENTRECURSIVELY)) == (EVIF_RECURSIVELY | EVIF_CONTENTRECURSIVELY))
		flags &= ~EVIF_CONTENTRECURSIVELY;

	g_hash_table_replace(indexes_p->out_lines_aggr_ht, outline, GINT_TO_POINTER(flags));

	debug(3, "indexes_outaggr_aggr(indexes_p, \"%s\").", outline);
	return 0;
}

#endif

