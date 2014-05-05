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

#ifndef __CLSYNC_INDEXES_H
#define __CLSYNC_INDEXES_H

#include <glib.h>

struct indexes {
	GHashTable *wd2fpath_ht;			// watching descriptor -> file path
	GHashTable *fpath2wd_ht;			// file path -> watching descriptor
	GHashTable *fpath2ei_ht;			// file path -> event information
	GHashTable *exc_fpath_ht;			// excluded file path
	GHashTable *exc_fpath_coll_ht[QUEUE_MAX];	// excluded file path aggregation hashtable for every queue
	GHashTable *fpath2ei_coll_ht[QUEUE_MAX];	// "file path -> event information" aggregation hashtable for every queue
	GHashTable *out_lines_aggr_ht;			// output lines aggregation hashtable
};
typedef struct indexes indexes_t;

#endif

