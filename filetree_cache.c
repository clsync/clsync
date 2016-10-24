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
	debug ( 8, "" );
	pthread_mutex_lock ( &filetree_cache_mutex );

	if ( ctx_p->filetree_cache == NULL )
		return 0;

	g_hash_table_remove_all ( ( ( indexes_t * ) ctx_p->indexes_p )->filetree_cache_ht );
	ctx_p->filetree_cache_len = 0;
	ctx_p->filetree_cache_size = 0;
	free ( ctx_p->filetree_cache );
	ctx_p->filetree_cache = NULL;

	if ( !dontunlock )
		pthread_mutex_unlock ( &filetree_cache_mutex );

	return 0;
}

filetree_cache_entry_t *
_filetree_cache_update (
    ctx_t *ctx_p,
    filetree_cache_entry_t *entry_old,
    filetree_cache_entry_data_t *entry_data_new
)
{
#ifdef PARANOID
	assert ( entry_data_new != NULL );
#endif
	debug ( 8, "\"%s\": mtime: %u -> %u", entry_old->dat.path, entry_old->dat.stat.st_mtime, entry_data_new->stat.st_mtime );

	if ( entry_old == NULL ) {
		entry_old = filetree_cache_get ( ctx_p, entry_data_new->path );

		if ( entry_old == NULL ) {
			errno = ENOENT;
			critical ( "Cannot find a file tree cache entry \"%s\"", entry_data_new->path );
			return NULL;
		}
	}

	memcpy ( &entry_old->dat, entry_data_new, sizeof ( *entry_data_new ) );
#ifdef _DEBUG_FORCE
	entry_old = filetree_cache_get ( ctx_p, entry_data_new->path );
	debug ( 12, "\"%s\" (%p, %i): mtime: %u", entry_old->dat.path, entry_old, entry_old->id, entry_old->dat.stat.st_mtime );
#endif
	return entry_old;
}


filetree_cache_entry_t *
_filetree_cache_add (
    ctx_t *ctx_p,
    filetree_cache_entry_data_t *data_entry
)
{
#ifdef PARANOID
	assert ( data_entry != NULL );
#endif
	debug ( 8, "start" );
	{
		filetree_cache_entry_t *entry_old = filetree_cache_get ( ctx_p, data_entry->path );

		if ( entry_old != NULL ) {
			warning ( "\"%s\" is already cached. Updating.", data_entry->path );
			return _filetree_cache_update ( ctx_p, entry_old, data_entry );
		}
	}
	size_t entry_id = ctx_p->filetree_cache_len++;

	if ( ctx_p->filetree_cache_len >= ctx_p->filetree_cache_size ) {
		filetree_cache_entry_t *old_ptr = ctx_p->filetree_cache;
		ctx_p->filetree_cache_size += ALLOC_PORTION;
		debug ( 8, "reallocating buffer to item-size: %u", ctx_p->filetree_cache_size );
		ctx_p->filetree_cache = xrealloc ( ctx_p->filetree_cache, sizeof ( *ctx_p->filetree_cache ) * ctx_p->filetree_cache_size );

		if ( old_ptr != ctx_p->filetree_cache ) {
			debug ( 8, "rebuilding indexes because the pointer has changed" );
			indexes_filetreecache_flush ( ctx_p->indexes_p );
			size_t i = 0;

			while ( i < ctx_p->filetree_cache_len - 1 )
				indexes_filetreecache_add ( ctx_p->indexes_p, &ctx_p->filetree_cache[i++] );
		}
	}

	filetree_cache_entry_t *entry = &ctx_p->filetree_cache[entry_id];
#ifdef PARANOID
	memset ( entry, 0, sizeof ( *entry ) );
#else
	entry->is_synced = 0;
	entry->is_saved  = 0;
	entry->is_marked = 0;
	entry->to_delete = 0;
#endif
	memcpy ( &entry->dat, data_entry, sizeof ( *data_entry ) );
	entry->id = entry_id;
	indexes_filetreecache_add ( ctx_p->indexes_p, entry );
	debug ( 8, "end" );
	return entry;
}


// This function shouldn't be used to add entries very often (it may be quite slow for that)
int
filetree_cache_add (
    ctx_t *ctx_p,
    filetree_cache_entry_data_t *data_entry
)
{
#ifdef PARANOID
	assert ( data_entry != NULL );
#endif
	debug ( 8, "" );
	pthread_mutex_lock ( &filetree_cache_mutex );
	int rc = _filetree_cache_add ( ctx_p, data_entry ) == NULL ? ( errno ? errno : -1 ) : 0;
	pthread_mutex_unlock ( &filetree_cache_mutex );
	return rc;
}

int
filetree_cache_update (
    ctx_t *ctx_p,
    filetree_cache_entry_data_t *data_entry
)
{
#ifdef PARANOID
	assert ( data_entry != NULL );
#endif
	debug ( 8, "" );
	pthread_mutex_lock ( &filetree_cache_mutex );
	int rc = _filetree_cache_update ( ctx_p, NULL, data_entry ) == NULL ? ( errno ? errno : -1 ) : 0;
	pthread_mutex_unlock ( &filetree_cache_mutex );
	return rc;
}

// This function shouldn't be used to add entries very often (it may be quite slow for that)
int
filetree_cache_set (
    ctx_t *ctx_p,
    filetree_cache_entry_data_t *data_entry
)
{
#ifdef PARANOID
	assert ( data_entry != NULL );
#endif
	debug ( 8, "" );
	int rc = 0;
	pthread_mutex_lock ( &filetree_cache_mutex );
	filetree_cache_entry_t *entry_old = filetree_cache_get ( ctx_p, data_entry->path );

	if ( entry_old == NULL )
		rc = _filetree_cache_add ( ctx_p, data_entry ) == NULL ? ( errno ? errno : -1 ) : 0;
	else
		rc = _filetree_cache_update ( ctx_p, entry_old, data_entry ) == NULL ? ( errno ? errno : -1 ) : 0;

	pthread_mutex_unlock ( &filetree_cache_mutex );
	return rc;
}

int
_filetree_cache_del (
    ctx_t *ctx_p,
    filetree_cache_entry_t *entry_del
)
{
#ifdef PARANOID
	assert ( entry_del != NULL );
#endif
	debug ( 8, "" );
	filetree_cache_entry_t *entry_move = &ctx_p->filetree_cache[--ctx_p->filetree_cache_len];
	indexes_filetreecache_del ( ctx_p->indexes_p,  entry_del->dat.path );
	indexes_filetreecache_del ( ctx_p->indexes_p, entry_move->dat.path );
	size_t entry_id = entry_del->id;
	memcpy ( entry_del, entry_move, sizeof ( *entry_del ) );
	ctx_p->filetree_cache[entry_id].id = entry_id;
	indexes_filetreecache_add ( ctx_p->indexes_p, entry_move );
	return 0;
}

int
filetree_cache_del (
    ctx_t *ctx_p,
    const char *path
)
{
#ifdef PARANOID
	assert ( path != NULL );
#endif
	debug ( 8, "" );
	pthread_mutex_lock ( &filetree_cache_mutex );
	filetree_cache_entry_t *entry_del  = filetree_cache_get ( ctx_p, path );
#ifdef PARANOID
	critical_on ( entry_del == NULL );
#endif
	int rc = _filetree_cache_del ( ctx_p, entry_del );
	pthread_mutex_unlock ( &filetree_cache_mutex );
	return rc;
}

int
filetree_cache_queueadd (
    ctx_t *ctx_p,
    const char *path,
    stat64_t *st_p
)
{
#ifdef PARANOID
	assert ( path != NULL );
	assert ( st_p != NULL );
#endif
	debug ( 8, "" );
	pthread_mutex_lock ( &filetree_cache_mutex );
	size_t queuedentry_id = ctx_p->filetree_cache_queued_add_len++;

	if ( ctx_p->filetree_cache_queued_add_len >= ctx_p->filetree_cache_queued_add_size ) {
		ctx_p->filetree_cache_queued_add_size += ALLOC_PORTION;
		ctx_p->filetree_cache_queued_add = xrealloc ( ctx_p->filetree_cache_queued_add, sizeof ( *ctx_p->filetree_cache_queued_add ) * ctx_p->filetree_cache_queued_add_size );
	}

	filetree_cache_entry_data_t *entrydata = &ctx_p->filetree_cache_queued_add[queuedentry_id];
	filetree_cache_setdatato ( entrydata, path, st_p );
	pthread_mutex_unlock ( &filetree_cache_mutex );
	return 0;
}

int
filetree_cache_queuedel (
    ctx_t *ctx_p,
    const char *path
)
{
#ifdef PARANOID
	assert ( path != NULL );
#endif
	debug ( 8, "" );
	pthread_mutex_lock ( &filetree_cache_mutex );
	filetree_cache_entry_t *entry_del = filetree_cache_get ( ctx_p, path );
#ifdef PARANOID
	critical_on ( entry_del == NULL );
#endif
	entry_del->to_delete = 1;
	pthread_mutex_unlock ( &filetree_cache_mutex );
	return 0;
}


int
filetree_cache_queueflush (
    ctx_t *ctx_p
)
{
	debug ( 8, "" );
	pthread_mutex_lock ( &filetree_cache_mutex );
	size_t entry_id = 0;

	while ( entry_id < ctx_p->filetree_cache_len ) {
		filetree_cache_entry_t *entry = &ctx_p->filetree_cache[entry_id++];

		if ( entry->to_delete ) {
			critical_on ( _filetree_cache_del ( ctx_p, entry ) );
			continue;
		}
	};

	size_t queuedentry_id = 0;

	while ( queuedentry_id < ctx_p->filetree_cache_queued_add_len ) {
		filetree_cache_entry_data_t *entrydata = &ctx_p->filetree_cache_queued_add[queuedentry_id];
		critical_on ( _filetree_cache_add ( ctx_p, entrydata ) == NULL );
		queuedentry_id++;
	}

	ctx_p->filetree_cache_queued_add_len = 0;
	pthread_mutex_unlock ( &filetree_cache_mutex );
	return 0;
}

pthread_t filetree_cache_saver_thread;
static char filetree_cache_saver_handler_running = 0;

int
filetree_cache_saver_handler (
    ctx_t *ctx_p
)
{
	if ( ctx_p->filetree_cache_save_interval <= 0 ) {
		debug ( 5, "ctx_p->filetree_cache_save_interval <= 0" );
		return 0;
	}

	debug ( 5, "started" );

	while ( filetree_cache_saver_handler_running ) {
		debug ( 9, "sleeping for %i second(s)", ctx_p->filetree_cache_save_interval );
		sleep ( ctx_p->filetree_cache_save_interval );
		debug ( 9, "wake up" );
		filetree_cache_save ( ctx_p );
	}

	return 0;
}

int
filetree_cache_init (	// TODO: Implement mmap() support
    ctx_t *ctx_p
)
{
	debug ( 7, "\"%s\"", ctx_p->filetree_cache_path );
	SAFE ( pthread_mutex_lock ( &filetree_cache_mutex ), return errno );
	stat64_t st;
	int rc = lstat64 ( ctx_p->filetree_cache_path, &st );

	if ( rc == -1 ) {
		FILE *f = fopen ( ctx_p->filetree_cache_path, "w" );

		if ( f == NULL )
			goto filetree_cache_init_error;

		SAFE ( fclose ( f ), goto filetree_cache_init_error );
	}

	FILE *f = fopen ( ctx_p->filetree_cache_path, "r+" );

	if ( f == NULL )
		goto filetree_cache_init_error;

	ctx_p->filetree_cache_f = f;
	filetree_cache_saver_handler_running = 1;
	SAFE ( pthread_create ( &filetree_cache_saver_thread, NULL, ( void * ( * ) ( void * ) ) filetree_cache_saver_handler, ctx_p ), goto filetree_cache_init_error );
	pthread_mutex_unlock ( &filetree_cache_mutex );
	debug ( 9, "end" );
	return 0;
filetree_cache_init_error:

	if ( f != NULL )
		fclose ( f );

	pthread_mutex_unlock ( &filetree_cache_mutex );
	debug ( 7, "end (error)" );
	return errno;
}

int
filetree_cache_deinit (	// TODO: Implement mmap() support
    ctx_t *ctx_p
)
{
	debug ( 7, "waiting for filetree_cache_saver_thread to quit" );
	filetree_cache_saver_handler_running = 0;
	SAFE ( pthread_join ( filetree_cache_saver_thread, NULL ), return errno );
	debug ( 7, "cleaning up" );
	SAFE ( pthread_mutex_lock ( &filetree_cache_mutex ), return errno );
	SAFE ( fclose ( ctx_p->filetree_cache_f ), goto filetree_cache_deinit_error );
	ctx_p->filetree_cache_f = NULL;
	pthread_mutex_unlock ( &filetree_cache_mutex );
	debug ( 9, "end" );
	return 0;
filetree_cache_deinit_error:
	pthread_mutex_unlock ( &filetree_cache_mutex );
	debug ( 7, "end (error)" );
	return errno;
}

int
filetree_cache_load (	// TODO: Implement mmap() support
    ctx_t *ctx_p
)
{
	debug ( 8, "\"%s\"", ctx_p->filetree_cache_path );
	filetree_cache_flush ( ctx_p, 1 );
	FILE *f = ctx_p->filetree_cache_f;
#ifdef PARANOID
	assert ( f != NULL );
#endif
	stat64_t st;
	SAFE ( fstat64 ( fileno ( f ), &st ),	goto filetree_cache_load_error );
	SAFE ( fflush ( f ),			goto filetree_cache_load_error );
	SAFE ( fseek ( f, 0L, SEEK_SET ),		goto filetree_cache_load_error );
	ctx_p->filetree_cache_len  = 0;
	ctx_p->filetree_cache_size = ( st.st_size / sizeof ( *ctx_p->filetree_cache ) ) + 1 + ALLOC_PORTION;
	ctx_p->filetree_cache      = xmalloc ( ctx_p->filetree_cache_size * sizeof ( *ctx_p->filetree_cache ) );

	do {
		filetree_cache_entry_data_t buf[ALLOC_PORTION];
		size_t r = fread ( &buf, sizeof ( filetree_cache_entry_data_t ), ALLOC_PORTION, f );

		if ( ferror ( f ) ) {
#ifdef PARANOID
			assert ( errno != 0 );
#endif
			goto filetree_cache_load_error;
		}

		debug ( 8, "Got %i records", r );
		size_t i;
		i = 0;

		while ( i < r ) {
			filetree_cache_entry_t *entry;
			debug ( 8, "adding record %i (mtime: %u)", i, buf[i].stat.st_mtime );
			SAFE ( ( entry = _filetree_cache_add ( ctx_p, &buf[i] ) ) == NULL , goto filetree_cache_load_error );
			entry->is_saved = 1;
			i++;
		}
	} while ( !feof ( f ) );

	pthread_mutex_unlock ( &filetree_cache_mutex );
	debug ( 9, "end" );
	return 0;
filetree_cache_load_error:
	pthread_mutex_unlock ( &filetree_cache_mutex );
	debug ( 7, "end (error)" );
	return errno;
}

int
filetree_cache_save (	// TODO: Implement mmap() support [much faster]
    ctx_t *ctx_p
)
{
	debug ( 7, "" );
	SAFE ( pthread_mutex_lock ( &filetree_cache_mutex ), return errno );
	FILE *f = ctx_p->filetree_cache_f;
#ifdef PARANOID
	assert ( f != NULL );
#endif
	//SAFE ( fseek(f, 0L, SEEK_SET), goto filetree_cache_save_error );
	size_t entry_id = 0;

	while ( entry_id < ctx_p->filetree_cache_len ) {
		filetree_cache_entry_t *entry = &ctx_p->filetree_cache[entry_id++];
		debug ( 8, "Saving entry #%i \"%s\" (%p, mtime: %u)", entry->id, entry->dat.path, entry, entry->dat.stat.st_mtime );

		if ( entry->is_saved ) {
			debug ( 9, "Already on the disk, skipping" );
			continue;
		}

		int rc = fseek ( f, entry->id * sizeof ( entry->dat ), SEEK_SET );

		if ( rc == -1 ) {
			error ( "Got error from fseek()" );
			goto filetree_cache_save_error;
		}

		entry->is_saved = 1;
		debug ( 9, "Writting to the disk" );
		size_t w = fwrite ( &entry->dat, sizeof ( entry->dat ), 1, f );

		if ( w != 1 ) {
#ifdef PARANOID
			assert ( errno != 0 );
#endif
			error ( "Got error from fwrite()" );
			goto filetree_cache_save_error;
		}
	};

	SAFE ( ftruncate ( fileno ( f ) , ftell ( f ) ),	goto filetree_cache_save_error );

	SAFE ( fflush ( f ),					goto filetree_cache_save_error );

	pthread_mutex_unlock ( &filetree_cache_mutex );

	debug ( 9, "end" );

	return 0;

filetree_cache_save_error:
	pthread_mutex_unlock ( &filetree_cache_mutex );

	debug ( 7, "end (error)" );

	return errno;
}
