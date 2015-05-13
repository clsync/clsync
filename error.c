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

/*
 * This file implements way to output debugging information. It's supposed
 * to be slow but convenient functions.
 */

#include <stdlib.h>
#include <execinfo.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <syslog.h>
#include <pthread.h>	/* pthread_self() */
#include <sys/types.h>	/* getpid() */
#include <unistd.h>	/* getpid() */


#include "configuration.h"

#include "error.h"
#include "pthreadex.h"	/* pthread_*_shared() */

static int zero     = 0;
static int three    = 3;

static int *outputmethod = &zero;
static int *debug	 = &zero;
static int *quiet	 = &zero;
static int *verbose	 = &three;

pthread_mutex_t *error_mutex_p = NULL;

static int printf_stderr(const char *fmt, ...) {
	va_list args;
	int rc;

	va_start(args, fmt);
	rc = vfprintf(stderr, fmt, args);
	va_end(args);

	return rc;
}

static int printf_stdout(const char *fmt, ...) {
	va_list args;
	int rc;

	va_start(args, fmt);
	rc = vfprintf(stdout, fmt, args);
	va_end(args);

	return rc;
}

static int vprintf_stderr(const char *fmt, va_list args) {
	return vfprintf(stderr, fmt, args);
}

static int vprintf_stdout(const char *fmt, va_list args) {
	return vfprintf(stdout, fmt, args);
}


static void flush_stderr(int level) {
	fprintf(stderr, "\n");
	fflush(stderr);
}

static void flush_stdout(int level) {
	fprintf(stdout, "\n");
	fflush(stdout);
}


static char _syslog_buffer[SYSLOG_BUFSIZ+1] = {0};
size_t      _syslog_buffer_filled = 0;

static int vsyslog_buf(const char *fmt, va_list args) {
	int len;
	size_t size;

	size = SYSLOG_BUFSIZ - _syslog_buffer_filled;

#ifdef VERYPARANOID
	if (
		(			 size	> SYSLOG_BUFSIZ)	|| 
		(_syslog_buffer_filled + size	> SYSLOG_BUFSIZ)	||
		(_syslog_buffer_filled		> SYSLOG_BUFSIZ)
	) {
		fprintf(stderr, "Security problem while vsyslog_buf(): "
			"_syslog_buffer_filled == %lu; "
			"size == %lu; "
			"SYSLOG_BUFSIZ == "XTOSTR(SYSLOG_BUFSIZ)"\n",
			_syslog_buffer_filled, size);
		exit(ENOBUFS);
	}
#endif
	if (!size)
		return 0;

	len = vsnprintf (
		&_syslog_buffer[_syslog_buffer_filled],
		size,
		fmt,
		args
	);

	if (len>0) {
		_syslog_buffer_filled += len;
		if (_syslog_buffer_filled > SYSLOG_BUFSIZ)
			_syslog_buffer_filled = SYSLOG_BUFSIZ;
	}

	return 0;
}

static int syslog_buf(const char *fmt, ...) {
	va_list args;
	int rc;

	va_start(args, fmt);
	rc = vsyslog_buf(fmt, args);
	va_end(args);

	return rc;
}

static void syslog_flush(int level) {
	syslog(level, "%s", _syslog_buffer);
	_syslog_buffer_filled = 0;
}

typedef int  *(  *outfunct_t)(const char *format, ...);
typedef int  *( *voutfunct_t)(const char *format, va_list ap);
typedef void *(*flushfunct_t)(int level);

static outfunct_t outfunct[] = {
	[OM_STDERR]	= (outfunct_t)printf_stderr,
	[OM_STDOUT]	= (outfunct_t)printf_stdout,
	[OM_SYSLOG]	= (outfunct_t)syslog_buf,
};

static voutfunct_t voutfunct[] = {
	[OM_STDERR]	= (voutfunct_t)vprintf_stderr,
	[OM_STDOUT]	= (voutfunct_t)vprintf_stdout,
	[OM_SYSLOG]	= (voutfunct_t)vsyslog_buf,
};

static flushfunct_t flushfunct[] = {
	[OM_STDERR]	= (flushfunct_t)flush_stderr,
	[OM_STDOUT]	= (flushfunct_t)flush_stdout,
	[OM_SYSLOG]	= (flushfunct_t)syslog_flush,
};

void _critical(const char *const function_name, const char *fmt, ...) {
	if (*quiet)
		return;

	struct timespec abs_time;
	clock_gettime(CLOCK_REALTIME , &abs_time);
	abs_time.tv_sec += 1;

	if (error_mutex_p != NULL)
		pthread_mutex_timedlock(error_mutex_p, &abs_time);

	outputmethod_t method = *outputmethod;

	{
		va_list args;
		pthread_t thread = pthread_self();
		pid_t pid = getpid();

		outfunct[method]("Critical (pid: %u; thread: %p): %s(): ", pid, thread, function_name);
		va_start(args, fmt);
		voutfunct[method](fmt, args);
		va_end(args);
		outfunct[method](" (current errno %i: %s)", errno, strerror(errno));
		flushfunct[method](LOG_CRIT);
	}

#ifdef BACKTRACE_SUPPORT
	{
		void  *buf[BACKTRACE_LENGTH];
		char **strings;
		int backtrace_len = backtrace((void **)buf, BACKTRACE_LENGTH);

		strings = backtrace_symbols(buf, backtrace_len);
		if (strings == NULL) {
			outfunct[method]("_critical(): Got error, but cannot print the backtrace. Current errno: %u: %s\n",
				errno, strerror(errno));
			flushfunct[method](LOG_CRIT);
			pthread_mutex_unlock(error_mutex_p);
			exit(EXIT_FAILURE);
		}

		for (int j = 1; j < backtrace_len; j++) {
			outfunct[method]("        %s", strings[j]);
			flushfunct[method](LOG_CRIT);
		}
	}
#endif

	if (error_mutex_p != NULL)
		pthread_mutex_unlock(error_mutex_p);

	error_deinit();
	exit(errno);

	return;
}

void _error(const char *const function_name, const char *fmt, ...) {
	va_list args;

	if (*quiet)
		return;

	if (*verbose < 1)
		return;

	if (error_mutex_p != NULL)
		pthread_mutex_reltimedlock(error_mutex_p, 0, OUTPUT_LOCK_TIMEOUT);

	pthread_t thread = pthread_self();
	pid_t pid = getpid();
	outputmethod_t method = *outputmethod;

	outfunct[method](*debug ? "Error (pid: %u; thread: %p): %s(): " : "Error: ", pid, thread, function_name);
	va_start(args, fmt);
	voutfunct[method](fmt, args);
	va_end(args);
	if (errno)
		outfunct[method](" (%i: %s)", errno, strerror(errno));
	flushfunct[method](LOG_ERR);

	if (error_mutex_p != NULL)
		pthread_mutex_unlock(error_mutex_p);
	return;
}

void _info(const char *const function_name, const char *fmt, ...) {
	va_list args;

	if (*quiet)
		return;

	if (*verbose < 3)
		return;

	if (error_mutex_p != NULL)
		pthread_mutex_reltimedlock(error_mutex_p, 0, OUTPUT_LOCK_TIMEOUT);

	pthread_t thread = pthread_self();
	pid_t pid = getpid();
	outputmethod_t method = *outputmethod;

	outfunct[method](*debug ? "Info (pid: %u; thread: %p): %s(): " : "Info: ", pid, thread, function_name);
	va_start(args, fmt);
	voutfunct[method](fmt, args);
	va_end(args);
	flushfunct[method](LOG_INFO);

	if (error_mutex_p != NULL)
		pthread_mutex_unlock(error_mutex_p);
	return;
}

void _warning(const char *const function_name, const char *fmt, ...) {
	va_list args;

	if (*quiet)
		return;

	if (*verbose < 2)
		return;

	if (error_mutex_p != NULL)
		pthread_mutex_reltimedlock(error_mutex_p, 0, OUTPUT_LOCK_TIMEOUT);

	pthread_t thread = pthread_self();
	pid_t pid = getpid();
	outputmethod_t method = *outputmethod;

	outfunct[method](*debug ? "Warning (pid: %u; thread: %p): %s(): " : "Warning: ", pid, thread, function_name);
	va_start(args, fmt);
	voutfunct[method](fmt, args);
	va_end(args);
	flushfunct[method](LOG_WARNING);

	if (error_mutex_p != NULL)
		pthread_mutex_unlock(error_mutex_p);
	return;
}

#ifdef _DEBUG_SUPPORT
void _debug(int debug_level, const char *const function_name, const char *fmt, ...) {
	va_list args;

	if (*quiet)
		return;

	if (debug_level > *debug)
		return;

	if (error_mutex_p != NULL)
		pthread_mutex_reltimedlock(error_mutex_p, 0, OUTPUT_LOCK_TIMEOUT);

	pthread_t thread = pthread_self();
	pid_t pid = getpid();
	outputmethod_t method = *outputmethod;

	outfunct[method]("Debug%u (pid: %u; thread: %p): %s(): ", debug_level, pid, thread, function_name);
	va_start(args, fmt);
	voutfunct[method](fmt, args);
	va_end(args);
	flushfunct[method](LOG_DEBUG);

	if (error_mutex_p != NULL)
		pthread_mutex_unlock(error_mutex_p);
	return;
}
#endif

void error_init(void *_outputmethod, int *_quiet, int *_verbose, int *_debug) {
	outputmethod 	= _outputmethod;
	quiet		= _quiet;
	verbose		= _verbose;
	debug		= _debug;

	openlog(NULL, SYSLOG_FLAGS, SYSLOG_FACILITY);

	return;
}

ipc_type_t ipc_type;
void error_init_ipc(ipc_type_t _ipc_type) {
	static pthread_mutex_t error_mutex = PTHREAD_MUTEX_INITIALIZER;
	ipc_type = _ipc_type;

	switch (ipc_type) {
		case IPCT_SHARED:
			pthread_mutex_init_shared(&error_mutex_p);
			break;
		case IPCT_PRIVATE:
			error_mutex_p = &error_mutex;
			pthread_mutex_init(error_mutex_p, NULL);
			break;
		default:
			critical ("Unknown ipc_type: %i", ipc_type);
	}

	return;
}

void error_deinit() {
	switch (ipc_type) {
		case IPCT_SHARED:
			pthread_mutex_destroy_shared(error_mutex_p);
			error_mutex_p = NULL;
			break;
		case IPCT_PRIVATE:
			break;
	}

	return;
}

