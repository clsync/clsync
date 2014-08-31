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

#ifndef __CLSYNC_ERROR_H
#define __CLSYNC_ERROR_H

#define BACKTRACE_LENGTH	256

#ifdef _DEBUG_FORCE
#	define DEBUGLEVEL_LIMIT 255
#else
#	define DEBUGLEVEL_LIMIT 9
#endif

extern void _critical( const char *const function_name, const char *fmt, ...);
#define critical(...) 				_critical(__FUNCTION__, __VA_ARGS__)
#define critical_on(cond) {if (unlikely(cond)) {critical("Assert: "TOSTR(cond));}}

extern void _error(const char *const function_name, const char *fmt, ...);
#define error(...) 				_error(__FUNCTION__, __VA_ARGS__)
#define error_on(cond)	  {if (unlikely(cond)) {error("Error: ("TOSTR(cond)") != 0");}}

extern void _warning(const char *const function_name, const char *fmt, ...);
#define warning(...) 				_warning(__FUNCTION__, __VA_ARGS__)

extern void _info(const char *const function_name, const char *fmt, ...);
#define info(...) 				_info(__FUNCTION__, __VA_ARGS__)

#ifdef _DEBUG_SUPPORT
	extern void _debug(int debug_level, const char *const function_name, const char *fmt, ...);
#	define debug(debug_level, ...)			{if (debug_level < DEBUGLEVEL_LIMIT) _debug(debug_level, __FUNCTION__, __VA_ARGS__);}
#	define error_or_debug(debug_level, ...)		((debug_level)<0 ? _error(__FUNCTION__, __VA_ARGS__) : _debug(debug_level, __FUNCTION__, __VA_ARGS__))
#else
#	define debug(debug_level, ...)			{}
#	define error_or_debug(debug_level, ...)		((debug_level)<0 ? _error(__FUNCTION__, __VA_ARGS__) : (void)0)
#endif


extern void error_init(void *_outputmethod, int *_quiet, int *_verbose, int *_debug);

enum outputmethod {
	OM_STDERR = 0,
	OM_STDOUT,
	OM_SYSLOG,

	OM_MAX
};
typedef enum outputmethod outputmethod_t;

#endif

