/*
    clsync - file tree sync utility based on inotify/kqueue
    
    Copyright (C) 2013-2014 Dmitry Yu Okunev <dyokunev@ut.mephi.ru> 0x8E30679C
    
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

extern int inotify_wait(struct ctx *ctx_p, struct indexes *indexes_p, struct timeval *tv_p);
extern int inotify_handle(struct ctx *ctx_p, struct indexes *indexes_p);
extern int inotify_add_watch_dir(struct ctx *ctx_p, struct indexes *indexes_p, const char *const accpath);
extern int inotify_deinit(ctx_t *ctx_p);

