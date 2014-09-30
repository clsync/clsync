/*
    clsync - file tree sync utility based on inotify/kqueue/bsm
    
    Copyright (C) 2014  Dmitry Yu Okunev <dyokunev@ut.mephi.ru> 0x8E30679C
    
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
#include "error.h"
#include "searchex.h"

#include <search.h>

#ifdef __GNUC__
int tdup(void **to, void *from, int (*compar)(const void *, const void *)) {
	debug(20, "");
	int count;
	if (from == NULL)
		return 0;

	count = 0;
	void tdup_item(const void *node_p, const VISIT which, const int depth) {
		debug(40, "%p, %i, %i", node_p, which, depth);
		switch (which) {
			case leaf:
				tsearch(*(void **)node_p, to, compar);
				count++;
				break;
			default:
				critical("This code shoudn't be reached (%p, %i, %i).", node_p, which, depth);
		}
	}
	twalk(from, tdup_item);

	return count;
}
#else
int   _tdup_count;
void *_tdup_to;
int (*_tdup_compar)(const void *, const void *);
void tdup_item(const void *node_p, const VISIT which, const int depth) {
	debug(40, "%p, %i, %i", node_p, which, depth);
	switch (which) {
		case leaf:
			tsearch(*(void **)node_p, _tdup_to, _tdup_compar);
			_tdup_count++;
			break;
		default:
			critical("This code shoudn't be reached (%p, %i, %i).", node_p, which, depth);
	}
	return;
}
int tdup(void **to, void *from, int (*compar)(const void *, const void *)) {
	int count;
#ifdef PARANOID
	static int lock = 1;
	if (!g_atomic_int_dec_and_test(&lock))
		critical ("tdup() is not thread-safe function");
#endif
	debug(20, "");
	if (from == NULL) {
		g_atomic_int_inc(&lock);
		return 0;
	}

	_tdup_count  = 0;
	_tdup_to     = to;
	_tdup_compar = compar;
	twalk(from, tdup_item);

	count = _tdup_count;
	g_atomic_int_inc(&lock);
	return count;
}
#endif

