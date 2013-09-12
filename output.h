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

extern int out_init(int *flags);
extern int debug_print_flags();

typedef int (*printf_funct)(const char *fmt, ...);
typedef int (*write_funct)(const char *buf, size_t len);

extern printf_funct _printf_ddd;
#define printf_ddd if(_printf_ddd!=NULL)_printf_ddd
extern printf_funct _printf_dd;
#define printf_dd if(_printf_dd!=NULL)_printf_dd
extern printf_funct _printf_d;
#define printf_d if(_printf_d!=NULL)_printf_d
extern printf_funct _printf_v;
#define printf_v if(_printf_v!=NULL)_printf_v
extern write_funct _write_ddd;
#define write_ddd if(_write_ddd!=null)_write_ddd
extern write_funct _write_dd;
#define write_dd if(_write_dd!=null)_write_dd
extern write_funct _write_d;
#define write_d if(_write_d!=NULL)_write_d
extern write_funct _write_v;
#define write_v if(_write_v!=NULL)_write_v

extern int printf_e(const char *fmt, ...);
extern int printf_out(const char *fmt, ...);
extern int write_e(const char *buf, size_t len);
extern int write_out(const char *buf, size_t len);
#define write_out_s(buf) write_out(buf, sizeof(buf)-1)
extern void out_flush();
extern void hexdump_e(const unsigned char *buf, size_t len);
extern void hexdump_d(const unsigned char *buf, size_t len);
extern void hexdump_dd(const unsigned char *buf, size_t len);

