/*
    clsync - file tree sync utility based on inotify/kqueue/bsm

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

#include <stdlib.h>	// free()
#include <string.h>	// strtok_r()
#include <errno.h>	// errno

#include "malloc.h"
#include "error.h"

static int _str_splitargs(
		char *ptr,
		char **arg_start_p,
		int quotes,
		int (*handler)(char *, size_t, void *),
		char *additional_arg
) {
	char  *arg_start, *arg;
	size_t arg_len;
	int rc;

	 arg_start       = *arg_start_p;
	*arg_start_p     = &ptr[1];

	arg_len = ptr - arg_start;

	if (arg_len == 0)  // Skipping nearby spaces
		return 0;

	arg = xmalloc(arg_len+1);
	if (quotes) {
		int s, d;
		s = d = 0;
		while (s < arg_len) {
			if (arg_start[s])
				arg[d++] = arg_start[s];
			s++;
		}
		arg_len = d;
	} else
		memcpy(arg, arg_start, arg_len);

#ifdef _DEBUG
	debug(15, "%p %p %i: <%s>", arg_start, ptr, arg_len, arg);
#endif

	arg[arg_len] = 0;

	if ((rc = handler(arg, arg_len, additional_arg))) {
		free(arg);
		return rc;
	}
	return 0;
}

int str_splitargs(
		char *_instr,
		int (*handler)(char *, size_t, void *),
		void *arg
) {
	debug(9, "");
	char *arg_start, *ptr, *instr;
	int quotes = 0;

	instr     = strdup(_instr);
	ptr       = instr;
	arg_start = instr;
	while (1) {
		ptr = strpbrk(ptr, " \t\"\'");
#ifdef _DEBUG
		debug(10, "ptr == %p", ptr);
#endif
		if (ptr == NULL)
			break;

#ifdef _DEBUG
		debug(10, "*ptr == \"%c\" (%i)", *ptr, *ptr);
#endif
		switch (*(ptr++)) {
			case ' ':
			case '\t': {
				int rc;

				if ((rc = _str_splitargs(&ptr[-1], &arg_start, quotes, handler, arg)))
					return rc;
				quotes = 0;
				break;
			}
			case '"':
				ptr[-1] = 0;
				quotes++;
				while ((ptr = strchr(ptr, '"')) != NULL) {
					// Checking for escaping
					char *p;

					p = &ptr[-1];
					while (*p == '\\') {
						p--;
#ifdef PARANOID
						if (p < instr)
							critical("Dangerous internal error");
#endif
					}

					if ((ptr-p)%2)
						break;
				}
				if (ptr == NULL) {
					errno = EINVAL;
					error("Unterminated quote <\"> in string: <%s>", instr);
					return errno;
				}
				*ptr = 0;
				quotes++;
				ptr++;
				break;
			case '\'':
				ptr[-1] = 0;
				quotes++;
				ptr = strchr(ptr, '\'');
				if (ptr == NULL) {
					errno = EINVAL;
					error("Unterminated quote <'> in string: <%s>", instr);
					return errno;
				}
				*ptr = 0;
				quotes++;
				ptr++;
				break;
		}
	}

	int rc = _str_splitargs(strchr(arg_start, 0), &arg_start, quotes, handler, arg);
	free(instr);
	return rc;
}
