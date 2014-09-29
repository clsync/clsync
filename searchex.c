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

#include <search.h>

int tdup(void **to, void *from, int (*compar)(const void *, const void *)) {
	int count;

	count =0;

	void tdup_item(const void *node_p, const VISIT which, const int depth) {
		switch (which) {
			case leaf:
				tsearch(node_p, to, compar);
				count++;
				break;
			default:
				critical("This code shoudn't be reached (%p, %i, %i).", node_p, which, depth);
		}
	}
	twalk(from, tdup_item);

	return count;
}

