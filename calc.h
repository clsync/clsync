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

#include <stdint.h>

#ifdef HAVE_MHASH
#include <mhash.h>

static inline uint32_t adler32_calc(const unsigned char *const data, uint32_t len) {
	uint32_t adler32;

	MHASH td = mhash_init(MHASH_ADLER32);
	mhash(td, data, len);
	mhash_deinit(td, &adler32);

	return adler32;
}
#else
extern uint32_t adler32_calc(const unsigned char *const data, uint32_t len);
#endif
