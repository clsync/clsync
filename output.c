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

#include <syslog.h>

#include "common.h"
#include "output.h"

static int *flags;

printf_funct _printf_ddd=NULL;
printf_funct _printf_dd=NULL;
printf_funct _printf_d=NULL;
printf_funct _printf_v=NULL;
printf_funct printf_e=NULL;
write_funct _write_ddd=NULL;
write_funct _write_dd=NULL;
write_funct _write_d=NULL;
write_funct _write_v=NULL;
write_funct write_e=NULL;

int out_init(int *flags_init) {
	flags = flags_init;
//	static char buf[OUTPUT_BUFSIZE];
	if(!flags[QUIET]) {
		if(flags[SYSLOG]) {
			openlog(PROGRAM, LOG_PID, LOG_DAEMON);

			printf_e = printf_syslog_err;
			 write_e =  write_syslog_err;
			if(flags[SYSLOG]>0) {
				_printf_d   = printf_syslog_debug;
				 _write_d   =  write_syslog_debug;
			}
			if(flags[SYSLOG]>1) {
				_printf_dd  = printf_syslog_debug;
				 _write_dd  =  write_syslog_debug;
			}
			if(flags[SYSLOG]>2) {
				_printf_ddd = printf_syslog_debug;
				 _write_ddd =  write_syslog_debug;
			}
			if(flags[VERBOSE]) {
				_printf_v   = printf_syslog_info;
				 _write_v   =  write_syslog_info;
			}
		} else {
			printf_e = printf_stderr;
			write_e =  write_stderr;
			if(flags[DEBUG]>0) {
				_printf_d   = printf_e;
				 _write_d   = write_e;
			}
			if(flags[DEBUG]>1) {
				_printf_dd  = printf_e;
				 _write_dd  = write_e;
			}
			if(flags[DEBUG]>2) {
				_printf_ddd = printf_e;
				 _write_ddd = write_e;
			}
			if(flags[VERBOSE]) {
				_printf_v   = printf_e;
				 _write_v   = write_e;
			}
		}
	}

//	setvbuf(stdout, buf, _IOFBF, OUTPUT_BUFSIZE);
	return 0;
}

void out_deinit() {
	if(!flags[QUIET]) {
		if(flags[SYSLOG]) {
			closelog();
		}
	}
}

int debug_print_flags() {
	int flag=0;

	printf_d("Debug: current flags: ");
	while(flag < (1<<8)) {
		if(flags[flag]) {
			int i=0;
			while(i++ < flags[flag]) 
				printf_d("%c", flag);
		}
		flag++;
	}
	printf_d("\n");

	return 0;
}

int printf_syslog_info(const char *fmt, ...) {
	va_list args;

	va_start(args, fmt);
	vsyslog(LOG_INFO, fmt, args);
	va_end(args);

	return 0;
}

int printf_syslog_debug(const char *fmt, ...) {
	va_list args;

	va_start(args, fmt);
	vsyslog(LOG_DEBUG, fmt, args);
	va_end(args);

	return 0;
}

int printf_syslog_err(const char *fmt, ...) {
	va_list args;

	va_start(args, fmt);
	vsyslog(LOG_ERR, fmt, args);
	va_end(args);

	return 0;
}

int printf_stderr(const char *fmt, ...) {
	int ret_print;
	va_list args;

	va_start(args, fmt);
	ret_print = vfprintf(stderr, fmt, args);
	va_end(args);

	return ret_print;
}

int write_syslog_info(const char *buf, size_t len) {
	// TODO: Consider with "len"
	syslog(LOG_INFO, "%s", buf);
	return 0;
}

int write_syslog_debug(const char *buf, size_t len) {
	// TODO: Consider with "len"
	syslog(LOG_DEBUG, "%s", buf);
	return 0;
}

int write_syslog_err(const char *buf, size_t len) {
	// TODO: Consider with "len"
	syslog(LOG_ERR, "%s", buf);
	return 0;
}

int write_stderr(const char *buf, size_t len) {
	return fwrite(buf, len, 1, stderr);
}

int write_stdout(const char *buf, size_t len) {
	return fwrite(buf, len, 1, stdout);
}

int printf_stdout(const char *fmt, ...) {
	va_list args;

	va_start(args, fmt);
	int ret_print = vprintf(fmt, args);
	va_end(args);

	return ret_print;
}

void out_flush() {
	fflush(stdout);
}

void hexdump_e(const unsigned char *buf, size_t len) {
	size_t i=0;

	while(i<len)
		printf_e("%5p ", (void *)(unsigned long)buf[i++]);
	write_e("\n", 1);

	return;
}

void hexdump_d(const unsigned char *buf, size_t len) {
	if(flags[DEBUG]<1)
		return;

	hexdump_e(buf, len);
}

void hexdump_dd(const unsigned char *buf, size_t len) {
	if(flags[DEBUG]<2)
		return;

	hexdump_e(buf, len);
}

