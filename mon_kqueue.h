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


/* We will use inotify event masks while kqueue in clsync, so it's required to
   define it: */
#ifndef IN_ISDIR
#define IN_ACCESS        0x00000001 /* File was accessed.  */
#define IN_MODIFY        0x00000002 /* File was modified.  */
#define IN_ATTRIB        0x00000004 /* Metadata changed.  */
#define IN_CLOSE_WRITE   0x00000008 /* Writtable file was closed.  */
#define IN_CLOSE_NOWRITE 0x00000010 /* Unwrittable file closed.  */
#define IN_CLOSE         (IN_CLOSE_WRITE | IN_CLOSE_NOWRITE) /* Close.  */
#define IN_OPEN          0x00000020 /* File was opened.  */
#define IN_MOVED_FROM    0x00000040 /* File was moved from X.  */
#define IN_MOVED_TO      0x00000080 /* File was moved to Y.  */
#define IN_MOVE          (IN_MOVED_FROM | IN_MOVED_TO) /* Moves.  */
#define IN_CREATE        0x00000100 /* Subfile was created.  */
#define IN_DELETE        0x00000200 /* Subfile was deleted.  */
#define IN_DELETE_SELF   0x00000400 /* Self was deleted.  */
#define IN_MOVE_SELF     0x00000800 /* Self was moved.  */
#define IN_IGNORED       0x00008000
#define IN_ISDIR         0x40000000
#endif

extern int kqueue_init();
extern int kqueue_add_watch_dir(struct ctx *ctx_p, struct indexes *indexes_p, const char *const accpath);
extern int kqueue_wait(struct ctx *ctx_p, struct indexes *indexes_p, struct timeval *tv_p);
extern int kqueue_handle(struct ctx *ctx_p, struct indexes *indexes_p);
extern int kqueue_deinit(ctx_t *ctx_p);

