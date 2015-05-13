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

#include "calc.h"
#include "error.h"

#ifdef HAVE_MHASH
#include <mhash.h>
#endif

#ifndef HAVE_MHASH
/**
 * @brief 			Calculated Adler32 value for char array
 * 
 * @param[in]	date		Pointer to data
 * @param[in]	len		Length of the data
 * 
 * @retval	uint32_t	Adler32 value of data
 * 
 */

// Copied from http://en.wikipedia.org/wiki/Adler-32
uint32_t adler32_calc(const unsigned char *const data, uint32_t len) { // where data is the location of the data in physical
                                                                       // memory and len is the length of the data in bytes

/*
	if (len&3)
		warning("len [%i] & 3 == %i != 0. Wrong length (not a multiple of 4).", len, len&3);
*/

	debug(70, "%p, %i", data, len);

	const int MOD_ADLER = 65521;
	uint32_t a = 1, b = 0;
	int32_t index;
	
	// Process each byte of the data in order
	for (index = 0; index < len; ++index)
	{
		debug(80, "%5i: %02x %02x %02x", index, data[index], a, b);
		a = (a + data[index]) % MOD_ADLER;
		b = (b + a) % MOD_ADLER;
	}
	
	return (b << 16) | a;
}
#endif

