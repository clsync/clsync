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

#include <search.h>

#include "error.h"
#include "sync.h"
#include "indexes.h"
#include "fileutils.h"
#include "calc.h"
#include "searchex.h"
#include "mon_kqueue.h"

struct monobj {
	ino_t          inode;
	dev_t          device;
	int            fd;
	int            dir_fd;
	char          *name;
	size_t         name_len;
	uint32_t       name_hash;
	unsigned char  type;
	size_t         changelist_id;
	struct monobj *parent;

	// For directories only
	void          *children_tree;
};
typedef struct monobj monobj_t;

struct kqueue_data {
	int kqueue_d;

	struct kevent *changelist;
	size_t         changelist_alloced;
	size_t         changelist_used;
	struct kevent  eventlist[KQUEUE_EVENTLISTSIZE];
	size_t         eventlist_count;
	void   *file_btree;
	void     *fd_btree;
};

struct recognize_event_return {
	union {
		struct {
			eventobjtype_t objtype_old:16;
			eventobjtype_t objtype_new:16;
		} v;
		uint32_t i;
	} u;
};

static inline uint32_t recognize_event(uint32_t event, int is_dir) {
	struct recognize_event_return r = {{{0}}};

	eventobjtype_t type;
	int is_created;
	int is_deleted;

	type       = (is_dir ? EOT_DIR : EOT_FILE);
	is_created =  event & (NOTE_LINK);
	is_deleted =  event & (NOTE_DELETE);

	debug(4, "type == %x; is_created == %x; is_deleted == %x", type, is_created, is_deleted);

	r.u.v.objtype_old = type;
	r.u.v.objtype_new = type;

	if (is_created)
		r.u.v.objtype_old = EOT_DOESNTEXIST;

	if (is_deleted)
		r.u.v.objtype_new = EOT_DOESNTEXIST;

	return r.u.i;
}

int kqueue_init(ctx_t *ctx_p) {
	ctx_p->fsmondata = xcalloc(1, sizeof(struct kqueue_data));
	if (ctx_p->fsmondata == NULL)
		return -1;

	struct kqueue_data *dat = ctx_p->fsmondata;

	dat->kqueue_d = kqueue();

	return 0;
}

static int monobj_filecmp(const void *_a, const void *_b) {
	const monobj_t *a=_a, *b=_b;

	int diff_inode  = a->inode  - b->inode;
	debug(10, "diff_inode = %i", diff_inode);
	if (diff_inode)
		return diff_inode;

	int diff_device = a->device - b->device;
	debug(10, "diff_device = %i", diff_device);
	if (diff_device)
		return diff_device;

	int diff_dir_fd = a->dir_fd - b->dir_fd;
	debug(10, "diff_dir_fd = %i (%i - %i)", diff_dir_fd, a->dir_fd, b->dir_fd);
	if (diff_dir_fd)
		return diff_dir_fd;

	int diff_name_hash = a->name_hash - b->name_hash;
	debug(10, "diff_name_hash = %i", diff_name_hash);
	if (diff_name_hash)
		return diff_name_hash;

	
	debug(10, "strcmp(\"%s\", \"%s\") = %i", a->name, b->name, strcmp(a->name, b->name));
	return strcmp(a->name, b->name);
}

static int monobj_fdcmp(const void *a, const void *b) {
	return ((monobj_t *)a)->fd - ((monobj_t *)b)->fd;
}

int kqueue_mark(ctx_t *ctx_p, monobj_t *obj_p) {
	struct kqueue_data *dat = ctx_p->fsmondata;
#ifdef VERYPARANOID
	if (obj_p == NULL) {
		errno = EINVAL;
		return -1;
	}
	if (tfind((void *)obj_p, &dat->file_btree, monobj_filecmp) != NULL) {
		warning("\"%s\" is already marked", obj_p->name);
		return 0;
	}
#endif
	debug(9, "");

	if (obj_p->dir_fd == -1)
		obj_p->fd = open(ctx_p->watchdir, O_RDONLY|O_NOFOLLOW);
	else
		obj_p->fd = openat(obj_p->dir_fd, obj_p->name, O_RDONLY|O_NOFOLLOW);

	debug(4, "obj_p->: dir_fd == %i; name == \"%s\"; fd == %i; type == %i (isdir == %i)", obj_p->dir_fd, obj_p->name, obj_p->fd, obj_p->type, obj_p->type == DT_DIR);

	if (obj_p->fd == -1) {
		debug(2, "File/dir \"%s\" disappeared. Skipping", obj_p->name);
		return 0;
	}

	if (dat->changelist_used >= dat->changelist_alloced) {
		dat->changelist_alloced += ALLOC_PORTION;
		dat->changelist          = xrealloc(dat->changelist, dat->changelist_alloced*sizeof(dat->changelist));
	}

	switch (obj_p->type) {
		case DT_DIR:
			EV_SET(&dat->changelist[dat->changelist_used], obj_p->fd,
				EVFILT_VNODE,
				EV_ADD | EV_CLEAR,
				NOTE_WRITE | NOTE_EXTEND | NOTE_ATTRIB | NOTE_DELETE,
				0, 0);
			break;
		default:
			EV_SET(&dat->changelist[dat->changelist_used], obj_p->fd,
				EVFILT_VNODE,
				EV_ADD | EV_CLEAR,
				NOTE_WRITE | NOTE_ATTRIB | NOTE_DELETE,
				0, 0);
			break;
	}

	obj_p->changelist_id = dat->changelist_used++;

	return 0;
}


int kqueue_unmark(ctx_t *ctx_p, monobj_t *obj_p) {
	struct kqueue_data *dat = ctx_p->fsmondata;
#ifdef VERYPARANOID
	if (obj_p == NULL) {
		errno = EINVAL;
		return -1;
	}
#endif

	if (obj_p->changelist_id+1 < dat->changelist_used)
		memcpy(&dat->changelist[obj_p->changelist_id], &dat->changelist[dat->changelist_used], sizeof(*dat->changelist));

	dat->changelist_used--;

	close(obj_p->fd);

	void child_free(monobj_t *node) {
		critical_on (kqueue_unmark(ctx_p, node));
	}
	tdestroy(obj_p->children_tree, (void (*)(void *))child_free);
	tdelete(obj_p, &dat->file_btree, monobj_filecmp);
	tdelete(obj_p,   &dat->fd_btree, monobj_fdcmp);
	free(obj_p->name);
	free(obj_p);

	return 0;
}

monobj_t *kqueue_start_watch(ctx_t *ctx_p, ino_t inode, dev_t device, int dir_fd, const char *const fname, size_t name_len, unsigned char type) {
	monobj_t *obj_p, *parent, parent_pattern;
	struct kqueue_data *dat = ctx_p->fsmondata;
	debug(3, "(ctx_p, %i, \"%s\", %u, %u)", dir_fd, fname, name_len, type);

	obj_p = xmalloc(sizeof(*obj_p));
	obj_p->inode	 = inode;
	obj_p->device	 = device;
	obj_p->dir_fd	 = dir_fd;
	obj_p->name_len	 = name_len;
	obj_p->name	 = xmalloc(obj_p->name_len+1);
	obj_p->type	 = type;
	memcpy(obj_p->name, fname, obj_p->name_len+1);
	obj_p->name_hash = adler32_calc((const unsigned char *)fname, name_len);

	parent_pattern.fd = dir_fd;
	obj_p->parent = tfind(&parent_pattern, &dat->fd_btree, monobj_fdcmp);
	parent = obj_p->parent;

	switch (type) {
		case DT_DIR:
		case DT_UNKNOWN:
		case DT_REG:
			if (kqueue_mark(ctx_p, obj_p)) {
				error("Got error while kqueue_mark()");
				free(obj_p->name);
				free(obj_p);
				return NULL;
			}
			break;
		default:
			debug(4, "I won't open() this object due to it's type == %u.", type);
			break;
	}

	debug(8, "storing: inode == %u; device == %u; dir_fd == %i; fd == %i; parent == %p", obj_p->inode, obj_p->device, obj_p->dir_fd, obj_p->fd, parent);
	if (tsearch((void *)obj_p, &dat->file_btree, monobj_filecmp) == NULL)
		critical("Not enough memory");
	if (tsearch((void *)obj_p,   &dat->fd_btree, monobj_fdcmp) == NULL)
		critical("Not enough memory");

	if (parent != NULL) {
		if (tsearch((void *)obj_p, &parent->children_tree, monobj_filecmp) == NULL)
			critical("Not enough memory");
	}

	return obj_p;
}

monobj_t *kqueue_add_watch_direntry(ctx_t *ctx_p, indexes_t *indexes_p, struct dirent *entry, monobj_t *dir_obj_p) {
	struct kqueue_data *dat = ctx_p->fsmondata;
	monobj_t *obj_p;
	uint32_t name_hash;
#ifdef VERYPARANOID
	if (entry == NULL) {
		errno = EINVAL;
		return NULL;
	}
#endif
	size_t name_len = strlen(entry->d_name);

	name_hash = adler32_calc((unsigned char *)entry->d_name, name_len);
	{
		monobj_t obj, **obj_pp;
		obj.inode     = entry->d_ino;
		obj.device    = dir_obj_p->device;
		obj.dir_fd    = dir_obj_p->fd;
		obj.name_hash = name_hash;
		if ((obj_pp = tfind((void *)&obj, &dat->file_btree, monobj_filecmp)) != NULL)
			return *obj_pp;
	}

	if ((obj_p = kqueue_start_watch(ctx_p, entry->d_ino, dir_obj_p->device, dir_obj_p->fd, entry->d_name, name_len, entry->d_type)) == NULL)
		error("Got error while kqueue_start_watch()");

	obj_p->inode     = entry->d_ino;
	obj_p->device    = dir_obj_p->device;
	obj_p->dir_fd    = dir_obj_p->fd;
	obj_p->name_hash = name_hash;

	return obj_p;
}

monobj_t *kqueue_add_watch_path(ctx_t *ctx_p, indexes_t *indexes_p, const char *const path) {
	struct stat st;
	struct kqueue_data *dat = ctx_p->fsmondata;
	monobj_t *obj_p = NULL;
	uint32_t name_hash;
	const char *file_name;
	int dir_fd;
	size_t name_len;

#ifdef VERYPARANOID
	if (path == NULL) {
		errno = EINVAL;
		return NULL;
	}
#endif
	debug(6, "(ctx_p, indexes_p, \"%s\")", path);

	{
		char *dir_path, *ptr;

		ptr = strrchr(path, '/');
		if (ptr == NULL) {
			file_name = path;
			dir_fd = indexes_fpath2wd(indexes_p, "");
		} else {
			dir_path = strdup(path);
			dir_path[ptr - path] = 0;
			dir_fd = indexes_fpath2wd(indexes_p, dir_path);
			if (dir_fd == -1) {
				if (strcmp(ctx_p->watchdir, path)) {
					errno = ENOENT;
					error("Cannot find file descriptor of directory \"%s\"", dir_path);
					return NULL;
				}
			}
			free(dir_path);
			file_name = &ptr[1];
		}

		name_len  = strlen(file_name);
		name_hash = adler32_calc((unsigned char *)file_name, name_len);
	}

	lstat(path, &st);

	{
		monobj_t obj, **obj_pp;
		obj.inode     = st.st_ino;
		obj.device    = st.st_dev;
		obj.dir_fd    = dir_fd;
		obj.name_hash = name_hash;
		obj.name      = (char *)file_name;
		if ((obj_pp = tfind((void *)&obj, &dat->file_btree, monobj_filecmp)) != NULL)
			return *obj_pp;
	}

	debug(9, "not monitored file/dir \"%s\", yet.", file_name);

	{
		const char *name_start;

		name_start = strrchr(path, '/');
		if (name_start == NULL)
			name_start = path;
		else
			name_start++;

		if ((obj_p = kqueue_start_watch(ctx_p, st.st_ino, st.st_dev, dir_fd, file_name, name_len, (st.st_mode&S_IFMT) == S_IFDIR ? DT_DIR : DT_REG)) == NULL)
			error("Got error while kqueue_start_watch()");
	}

	obj_p->inode     = st.st_ino;
	obj_p->device    = st.st_dev;
	obj_p->dir_fd    = dir_fd;
	obj_p->name_hash = name_hash;
	return obj_p;
}

int kqueue_add_watch_dir(ctx_t *ctx_p, indexes_t *indexes_p, const char *const accpath) {
	DIR      *dir;
	monobj_t *dir_obj_p = NULL;
	struct dirent *entry;

#ifdef VERYPARANOID
	if (accpath == NULL) {
		errno = EINVAL;
		return -1;
	}
#endif

	debug(5, "(ctx_p, indexes_p, \"%s\")", accpath);

	if ((dir_obj_p = kqueue_add_watch_path(ctx_p, indexes_p, accpath)) == NULL) {
		error("Got error while kqueue_add_watch_path(ctx_p, \"%s\")", accpath);
		return -1;
	}

	dir = fdopendir(dir_obj_p->fd);
	if (dir == NULL)
		return -1;

	while ((entry = readdir(dir))) {
		if (!memcmp(entry->d_name, ".",  2))
			continue;
		if (!memcmp(entry->d_name, "..", 3))
			continue;
		if (kqueue_add_watch_direntry(ctx_p, indexes_p, entry, dir_obj_p) == NULL) {
			error("Got error while kqueue_add_watch_direntry(ctx_p, indexes_p, entry {->d_name == \"%s\"}, %u)", entry->d_name, dir_obj_p->fd);
			return -1;
		}
	}

	return dir_obj_p->fd;
}

int kqueue_wait(ctx_t *ctx_p, struct indexes *indexes_p, struct timeval *tv_p) {
	struct kqueue_data *dat = ctx_p->fsmondata;
	struct timespec ts;
	debug(3, "tv_p->: tv_sec == %li; tv_usec == %li", tv_p->tv_sec, tv_p->tv_usec);

#ifdef PARANOID
	if (tv_p == NULL)
		return dat->eventlist_count = kevent(dat->kqueue_d, dat->changelist, dat->changelist_used, dat->eventlist, KQUEUE_EVENTLISTSIZE, NULL);
#endif

	ts.tv_sec  = tv_p->tv_sec;
	ts.tv_nsec = tv_p->tv_usec * 1000;

	return dat->eventlist_count = kevent(dat->kqueue_d, dat->changelist, dat->changelist_used, dat->eventlist, KQUEUE_EVENTLISTSIZE, &ts);
}

// Not a thread-safe function!
char *kqueue_getpath(ctx_t *ctx_p, indexes_t *indexes_p, monobj_t *obj_p) {
	char  *dirpath;
	size_t dirpath_len;
	static char   filepath[PATH_MAX+2];
	size_t filepath_len;

	dirpath = indexes_wd2fpath(indexes_p, obj_p->fd);
	if (dirpath != NULL)
		return strdup(dirpath);

	if (obj_p->dir_fd == -1) {
		errno = ENOENT;
		error("Cannot find fd of parent directory of \"%s\"", obj_p->name);
		return NULL;
	}

	dirpath = indexes_wd2fpath(indexes_p, obj_p->dir_fd);
	if (dirpath == NULL) {
		errno = ENOENT;
		error("Cannot find directory with fd == %u", obj_p->dir_fd);
		return NULL;
	}

	dirpath_len  = strlen(dirpath);
	filepath_len = dirpath_len + obj_p->name_len + 1;

#ifdef PARANOID
	if (filepath_len + 1 >= PATH_MAX) {
		errno = ENAMETOOLONG;
		error("Too long file path: \"%s/%s\"", dirpath, obj_p->name);
		return NULL;
	}
#endif

	memcpy(filepath, dirpath, dirpath_len);
	filepath[dirpath_len] = '/';
	memcpy(&filepath[dirpath_len+1], obj_p->name, obj_p->name_len+1);

	return filepath;
}

int kqueue_sync(ctx_t *ctx_p, indexes_t *indexes_p, struct kevent *ev_p, monobj_t *obj_p) {
	stat64_t lstat, *lstat_p;
	char *path_full = kqueue_getpath(ctx_p, indexes_p, obj_p);

#ifdef PARANOID
	if (path_full == NULL) {
		error("Cannot get full path for \"%s\" (fd: %u)", obj_p->name, obj_p->fd);
		return -1;
	}
#endif
	debug(8, "path_full = \"%s\"", path_full);

	mode_t st_mode;
	size_t st_size;
	if ((ctx_p->flags[CANCEL_SYSCALLS]&CSC_MON_STAT) || lstat64(path_full, &lstat)) {
		debug(2, "Cannot or cancelled lstat64(\"%s\", lstat). The object disappeared or option \"--cancel-syscalls=mon_stat\" is set.", path_full);
		if(obj_p->type == DT_DIR)
			st_mode = S_IFDIR;
		else
			st_mode = S_IFREG;
		st_size = 0;
		lstat_p = NULL;
	} else {
		st_mode =  lstat.st_mode;
		st_size =  lstat.st_size;
		lstat_p = &lstat;
	}

	{
		char   *path_rel	= NULL;
		size_t  path_rel_len	= 0;
		struct  recognize_event_return r;
		r.u.i = recognize_event(ev_p->fflags, obj_p->type == DT_DIR);

		int ret = sync_prequeue_loadmark(1, ctx_p, indexes_p, path_full, NULL, lstat_p, r.u.v.objtype_old, r.u.v.objtype_new, ev_p->fflags, ev_p->ident, st_mode, st_size, &path_rel, &path_rel_len, NULL);

		if (path_rel != NULL)
			free(path_rel);

		return ret;
	}

	return 0;
}

static inline int _kqueue_handle_oneevent_dircontent_item(struct kqueue_data *dat, ctx_t *ctx_p, indexes_t *indexes_p, monobj_t *dir_obj_p, struct dirent *entry, void *children_notfound) {
	static monobj_t obj, *obj_p;
	struct kevent ev = {0};
	debug(9, "\"%s\"", entry->d_name);

	obj.type      = entry->d_type;
	obj.inode     = entry->d_ino;
	obj.device    = dir_obj_p->device;
	obj.dir_fd    = dir_obj_p->fd;
	obj.name      = entry->d_name;
	obj.name_len  = strlen(entry->d_name);
	obj.name_hash = adler32_calc((unsigned char *)entry->d_name, obj.name_len);

	if (tfind((void *)&obj, &dat->file_btree, monobj_filecmp) != NULL)
		return 0;

	tdelete((void *)&obj, &children_notfound, monobj_filecmp);

	if ((obj_p = kqueue_start_watch(ctx_p, entry->d_ino, dir_obj_p->device, dir_obj_p->fd, obj.name, obj.name_len, obj.type)) == NULL) {
		error("Got error while kqueue_start_watch()");
		return -1;
	}

	ev.ident  = obj_p->fd;
	ev.fflags = NOTE_LINK;
	if (kqueue_sync(ctx_p, indexes_p, &ev, obj_p)) {
		error("Got error while kqueue_sync()");
		return -1;
	}

	return 0;
}

int _kqueue_handle_oneevent_dircontent(ctx_t *ctx_p, indexes_t *indexes_p, monobj_t *obj_p) {
	DIR *dir;
	void *children_tree_dup;
	struct dirent *entry;
	struct kqueue_data *dat = ctx_p->fsmondata;
	debug(8, "obj_p->dir_fd == %i", obj_p->dir_fd);

	children_tree_dup = NULL;
	tdup(&children_tree_dup, obj_p->children_tree, monobj_filecmp);

	int fd;

	if (obj_p->dir_fd == -1)
		fd = open(ctx_p->watchdir, O_RDONLY|O_PATH);
	else
		fd = openat(obj_p->dir_fd, obj_p->name, O_RDONLY|O_PATH);

	dir = fdopendir(fd);

	while ((entry = readdir(dir))) {
		debug(10, "file/dir: \"%s\"", entry->d_name);
		if (!memcmp(entry->d_name, ".",  2))
			continue;
		if (!memcmp(entry->d_name, "..", 3))
			continue;
		if (_kqueue_handle_oneevent_dircontent_item(dat, ctx_p, indexes_p, obj_p, entry, children_tree_dup)) {
			error("Got error while _kqueue_handle_oneevent_dircontent_item(ctx_p, obj_p, entry {->d_name == \"%s\"})", entry->d_name);
			return -1;
		}
	}

	void unmarkchild(monobj_t *obj_p) {
		static struct kevent ev = {0};
		ev.ident  = obj_p->fd;
		ev.fflags = NOTE_DELETE;
		critical_on (kqueue_sync(ctx_p, indexes_p, &ev, obj_p));

		debug(4, "Unmarking the child \"%s\" (dir_fd: %i; fd: %i)", obj_p->name, obj_p->dir_fd, obj_p->fd);
		kqueue_unmark(ctx_p, obj_p);
		return;
	}
	tdestroy(children_tree_dup, (void (*)(void *))unmarkchild);

	closedir(dir);

	return 0;
}

int kqueue_handle_oneevent(ctx_t *ctx_p, indexes_t *indexes_p, struct kevent *ev_p, monobj_t *obj_p) {
#ifdef VERYPARANOID
	if (ev_p == NULL) {
		errno = EINVAL;
		return -1;
	}
	if (obj_p == NULL) {
		errno = EINVAL;
		return -1;
	}
#endif
	debug(9, "obj_p->: name == \"%s\"; dir_fd == %i; type == 0x%x (isdir == %i); fd = %i. ev_p->fflags == 0x%x", obj_p->name, obj_p->dir_fd, obj_p->type, obj_p->type == DT_DIR, obj_p->fd, ev_p->fflags);
	int ret    = 0;

	if (obj_p->type == DT_DIR && (ev_p->fflags & (NOTE_EXTEND|NOTE_WRITE)))
		ret |= _kqueue_handle_oneevent_dircontent(ctx_p, indexes_p, obj_p);

	if (ev_p->fflags & (NOTE_EXTEND|NOTE_WRITE|NOTE_ATTRIB|NOTE_DELETE|NOTE_RENAME))
		ret |= kqueue_sync(ctx_p, indexes_p, ev_p, obj_p);

	if (ev_p->fflags & NOTE_DELETE)
		ret |= kqueue_unmark(ctx_p, obj_p);

	return ret;
}

int kqueue_handle(ctx_t *ctx_p, indexes_t *indexes_p) {
	static struct timeval tv={0};
	struct kqueue_data *dat = ctx_p->fsmondata;
	debug(3, "dat->eventlist_count == %i", dat->eventlist_count);

	if (dat->eventlist_count == 0)
		return 0;

	int count = 0;

	do {
		int i = 0;
#ifdef PARANOID
		g_hash_table_remove_all(indexes_p->fpath2ei_ht);
#endif

		while (i < dat->eventlist_count) {
			struct kevent *ev_p = &dat->eventlist[i++];

			monobj_t obj;
			obj.fd = ev_p->ident;
			monobj_t **obj_pp = tfind((void *)&obj, &dat->fd_btree, monobj_fdcmp);
			if (obj_pp == NULL) {
				error("Internal error. Cannot find internal structure for fd == %u. Skipping the event.", ev_p->ident);
				continue;
			}
			monobj_t *obj_p = *obj_pp;

			if (kqueue_handle_oneevent(ctx_p, indexes_p, ev_p, obj_p)) {
				error("Got error from kqueue_handle_oneevent()");
				return -1;
			}
			count++;
		}

		// Globally queueing captured events:
		// Moving events from local queue to global ones
		sync_prequeue_unload(ctx_p, indexes_p);

		dat->eventlist_count = 0;
	} while (kqueue_wait(ctx_p, indexes_p, &tv));

	return count;
}

void btree_free(void *node_p) {
	monobj_t *obj_p = node_p;

	free(obj_p->name);
	free(obj_p);

	return;
}

int kqueue_deinit(ctx_t *ctx_p) {
	struct kqueue_data *dat = ctx_p->fsmondata;

#if 0
	void btree_unmark(const void *_obj_p, const VISIT which, const int depth) {
		monobj_t *obj_p = _obj_p;
		kqueue_unmark(ctx_p, obj_p);

		return;
	}
	twalk(dat->fd_btree, btree_close);
#endif

	// TODO: fix segfault on cleanup:
#if 0
#if __USE_GNU
	tdestroy(dat->file_btree, btree_free);
	tdestroy(dat->fd_btree, NULL);
#else
	free(dat->file_btree);
	free(dat->fd_btree);
#endif
	free(ctx_p->fsmondata);
#ifdef PARANOID
	ctx_p->fsmondata      = NULL;
#endif
#endif
	return 0;
}

