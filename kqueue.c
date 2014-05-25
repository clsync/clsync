/*
    clsync - file tree sync utility based on inotify/kqueue
    
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
#include "port-hacks.h"
#include "error.h"
#include "sync.h"
#include "indexes.h"
#include "kqueue.h"

int kqueue_add_watch(int kqueue_d, const char *const accpath) {
	return -1;
}

int kqueue_wait(int kqueue_d, ctx_t *ctx_p, indexes_t *indexes_p) {
	return -1;
}

int kqueue_handle(int kqueue_d, ctx_t *ctx_p, indexes_t *indexes_p) {
	return -1;
}

