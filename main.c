/*
    fasync - sync utility based on fanotify

    Copyright (C) 2013  Dmitry Yu Okunev <xai@mephi.ru> 0x8E30679C

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
#include "output.h"
#include "fasync.h"
#include "malloc.h"

int flags[(1<<8)] = {0};
static struct option long_options[] =
{
	{"background",	no_argument,	&flags[BACKGROUND],	BACKGROUND},
	{"verbose",	no_argument,	&flags[VERBOSE],	VERBOSE},
	{"debug",	no_argument,	&flags[DEBUG],		DEBUG},
	{"quite",	no_argument,	&flags[QUITE],		QUITE},
	{"help",	no_argument,	NULL,			HELP},
	{0,		0,		0,			0}
};

int syntax() {
	printf("syntax: fasync [flags] <watch dir> <action script> [file with rules regexps]\npossible flags:\n");
	int i=0;
	while(long_options[i].name != NULL) {
		printf("\t--%-16s-%c\n", long_options[i].name, long_options[i].val);
		i++;
	}
	exit(0);
}

char *parse_arguments(int argc, char *argv[], char **actfpath, char **exfpath) {
	int c;
	int option_index = 0;
	while(1) {
		c = getopt_long (argc, argv, "bqvdh", long_options, &option_index);
	
		if (c == -1) break;
		switch (c) {
			case '?':
			case 'h':
				syntax();
				break;
			default:
				flags[c]++;
				break;
		}
	}
	if(optind+1 >= argc)
		syntax();

	*actfpath = argv[optind+1];
	if(optind+2 < argc)
		*exfpath = argv[optind+2];

	return argv[optind];
}

int parse_rules_fromfile(const char *exfpath, rule_t *rules) {
	char buf[BUFSIZ];
	char *line_buf=NULL;
	FILE *f = fopen(exfpath, "r");
	
	if(f == NULL) {
		printf_e("Error: Cannot open \"%s\" for reading: %s (errno: %i).\n", exfpath, strerror(errno), errno);
		return errno;
	}

	int i=0;
	size_t linelen, size=0;
	while((linelen = getline(&line_buf, &size, f)) != -1) {
		if(linelen>1) {
			char *line = line_buf;
			rule_t *rule;

			rule = &rules[i];
			line[--linelen] = 0; 
			switch(*line) {
				case '+':
					rule->action = RULE_ACCEPT;
					break;
				case '-':
					rule->action = RULE_REJECT;
					break;
				case '#':	// Comment?
					continue;
				default:
					printf_e("Error: Wrong rule action <%c>.\n", *line);
					return EINVAL;
			}

			line++;
			linelen--;

			*line |= 0x20;	// lower-casing
			switch(*line) {
				case '*':
					rule->objtype = 0;	// "0" - means "of any type"
					break;
				case 's':
					rule->objtype = S_IFSOCK;
					break;
				case 'l':
					rule->objtype = S_IFLNK;
					break;
				case 'f':
					rule->objtype = S_IFREG;
					break;
				case 'b':
					rule->objtype = S_IFBLK;
					break;
				case 'd':
					rule->objtype = S_IFDIR;
					break;
				case 'c':
					rule->objtype = S_IFCHR;
					break;
				case 'p':
					rule->objtype = S_IFIFO;
					break;
			}

			line++;
			linelen--;

			printf_d("Debug2: Rule <%c> <%c> pattern <%s> (length: %i).\n", line[-2], line[-1], line, linelen);
			int ret;
			if(i >= MAXRULES) {
				printf_e("Error: Too many rules (%i >= %i).\n", i, MAXRULES);
				rule->action = RULE_END;
				return ENOMEM;
			}
			if((ret = regcomp(&rule->expr, line, REG_EXTENDED | REG_NOSUB))) {
				regerror(ret, &rule->expr, buf, BUFSIZ);
				printf_e("Error: Invalid regexp pattern <%s>: %s (regex-errno: %i).\n", line, buf, ret);
				rule->action = RULE_END;
				return ret;
			}
			i++;
		}
	}
	if(size)
		free(line_buf);

	fclose(f);

	rules[i].action = RULE_END;	// Terminator. End of rules' chain.
	return 0;
}

int becomedaemon() {
	int pid;
	signal(SIGPIPE, SIG_IGN);
	switch((pid = fork())) {
		case -1:
			printf_e("Error: Cannot fork(): %s (errno: %i).\n", strerror(errno), errno);
			return(errno);
		case 0:
			setsid();
			break;
		default:
			printf_d("Debug: fork()-ed, pid is %i.\n", pid);
			exit(0);
	}
	return 0;
}

int main(int argc, char *argv[]) {
	int ret = 0;
	rule_t rules[MAXRULES];
	char *actfpath, *exfpath=NULL;
	char *dpath = parse_arguments(argc, argv, &actfpath, &exfpath);
	out_init();
	if(flags[DEBUG])
		debug_print_flags();

	if(exfpath != NULL)
		ret = parse_rules_fromfile(exfpath, rules);

	if(access(actfpath, X_OK) == -1) {
		printf_e("Error: \"%s\" is not executable: %s (errno: %i).\n", actfpath, strerror(errno), errno);
		ret = errno;
	}

	if(flags[BACKGROUND])
		ret = becomedaemon();

	if(ret == 0)
		ret = fasync_run(dpath, actfpath, rules);

	int i=0;
	while((i < MAXRULES) && (rules[i].action != RULE_END))
		regfree(&rules[i++].expr);

	out_flush();
	printf_d("Debug: finished, exitcode: %i.\n", ret);
	out_flush();
	return ret;
}


