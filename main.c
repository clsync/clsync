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

#include "common.h"
#include "output.h"
#include "sync.h"
#include "malloc.h"
#include "cluster.h"
#include "fileutils.h"

#include "revision.h"

static const struct option long_options[] =
{
	{"watch-dir",		required_argument,	NULL,	WATCHDIR},
	{"sync-handler",	required_argument,	NULL,	SYNCHANDLER},
	{"rules-file",		required_argument,	NULL,	RULESFILE},
	{"destination-dir",	required_argument,	NULL,	DESTDIR},
	{"mode",		required_argument,	NULL,	MODE},

	{"background",		optional_argument,	NULL,	BACKGROUND},
	{"config-file",		required_argument,	NULL,	CONFIGFILE},
	{"config-block",	required_argument,	NULL,	CONFIGBLOCK},
	{"pid-file",		required_argument,	NULL,	PIDFILE},
	{"uid",			required_argument,	NULL,	UID},
	{"gid",			required_argument,	NULL,	GID},
#ifdef HAVE_CAPABILITIES
	{"preserve-file-access",optional_argument,	NULL,	CAP_PRESERVE_FILEACCESS},
#endif
	{"pthread",		optional_argument,	NULL,	PTHREAD},
	{"syslog",		optional_argument,	NULL,	SYSLOG},
	{"one-file-system",	optional_argument,	NULL,	ONEFILESYSTEM},
	{"exclude-mount-points",optional_argument,	NULL,	EXCLUDEMOUNTPOINTS},
#ifdef CLUSTER_SUPPORT
	{"cluster-iface",	required_argument,	NULL,	CLUSTERIFACE},		// Not implemented, yet
	{"cluster-ip",		required_argument,	NULL,	CLUSTERMCASTIPADDR},	// Not implemented, yet
	{"cluster-port",	required_argument,	NULL,	CLUSTERMCASTIPPORT},	// Not implemented, yet
	{"cluster-timeout",	required_argument,	NULL,	CLUSTERTIMEOUT},	// Not implemented, yet
	{"cluster-node-name",	required_argument,	NULL,	CLUSTERNODENAME},	// Not implemented, yet
	{"cluster-hash-dl-min",	required_argument,	NULL,	CLUSTERHDLMIN},
	{"cluster-hash-dl-max",	required_argument,	NULL,	CLUSTERHDLMAX},
	{"cluster-scan-dl-max",	required_argument,	NULL,	CLUSTERSDLMAX},
#endif
	{"timeout-sync",	required_argument,	NULL,	SYNCTIMEOUT},
	{"delay-sync",		required_argument,	NULL,	SYNCDELAY},
	{"delay-collect",	required_argument,	NULL,	DELAY},
	{"delay-collect-bigfile",required_argument,	NULL,	BFILEDELAY},
	{"threshold-bigfile",	required_argument,	NULL,	BFILETHRESHOLD},
	{"lists-dir",		required_argument,	NULL,	OUTLISTSDIR},
	{"have-recursive-sync",	optional_argument,	NULL,	HAVERECURSIVESYNC},
	{"synclist-simplify",	optional_argument,	NULL,	SYNCLISTSIMPLIFY},
	{"auto-add-rules-w",	optional_argument,	NULL,	AUTORULESW},
	{"rsync-inclimit",	required_argument,	NULL,	RSYNCINCLIMIT},
	{"rsync-prefer-include",optional_argument,	NULL,	RSYNCPREFERINCLUDE},
	{"ignore-exitcode",	required_argument,	NULL,	IGNOREEXITCODE},
	{"dont-unlink-lists",	optional_argument,	NULL,	DONTUNLINK},
	{"full-initialsync",	optional_argument,	NULL,	INITFULL},
	{"verbose",		optional_argument,	NULL,	VERBOSE},
	{"debug",		optional_argument,	NULL,	DEBUG},
	{"quiet",		optional_argument,	NULL,	QUIET},
#ifdef FANOTIFY_SUPPORT
	{"fanotify",		optional_argument,	NULL,	FANOTIFY},
	{"inotify",		optional_argument,	NULL,	INOTIFY},
#endif
	{"label",		required_argument,	NULL,	LABEL},
	{"help",		optional_argument,	NULL,	HELP},
	{"version",		optional_argument,	NULL,	SHOW_VERSION},

	{NULL,			0,			NULL,	0}
};

static char *const modes[] = {
	[MODE_UNSET]		= "",
	[MODE_SIMPLE]		= "simple",
	[MODE_SHELL]		= "shell",
	[MODE_RSYNCSHELL]	= "rsyncshell",
	[MODE_RSYNCDIRECT]	= "rsyncdirect",
	[MODE_RSYNCSO]		= "rsyncso",
	[MODE_SO]		= "so",
	NULL
};

int syntax() {
	printf("possible options:\n");
	int i=0;
	while(long_options[i].name != NULL) {
		if(!(long_options[i].val & OPTION_CONFIGONLY))
			printf("\t--%-24s%c%c%s\n", long_options[i].name, 
				long_options[i].val & OPTION_LONGOPTONLY ? ' ' : '-', 
				long_options[i].val & OPTION_LONGOPTONLY ? ' ' : long_options[i].val, 
				(long_options[i].has_arg == required_argument ? " argument" : ""));
		i++;
	}
	exit(EINVAL);
}

int version() {
	printf(PROGRAM" v%i.%i"REVISION"\n\t"AUTHOR"\n", VERSION_MAJ, VERSION_MIN);
	exit(0);
}

static inline int parse_parameter(options_t *options_p, uint16_t param_id, char *arg, paramsource_t paramsource) {
#ifdef _DEBUG
	fprintf(stderr, "Force-Debug: parse_parameter(): %i: %i = \"%s\"\n", paramsource, param_id, arg);
#endif
	switch(paramsource) {
		case PS_ARGUMENT:
			if(param_id & OPTION_CONFIGONLY) {
				syntax();
				return 0;
			}
			options_p->flags_set[param_id] = 1;
			break;
		case PS_CONFIG:
			if(options_p->flags_set[param_id])
				return 0;
			break;
		default:
			printf_e("Warning: Unknown parameter #%i source (value \"%s\").\n", param_id, arg!=NULL ? arg : "");
			break;
	}
	switch(param_id) {
		case '?':
		case HELP:
			syntax();
			break;
		case CONFIGFILE:
			options_p->config_path  = arg;
			break;
		case CONFIGBLOCK:
			options_p->config_block = arg;
			break;
		case GID:
			options_p->gid = (unsigned int)atol(arg);
			options_p->flags[param_id]++;
			break;
		case UID:
			options_p->uid = (unsigned int)atol(arg);
			options_p->flags[param_id]++;
			break;
		case PIDFILE:
			options_p->pidfile             = arg;
			break;
#ifdef CLUSTER_SUPPORT
		case CLUSTERIFACE:
			options_p->cluster_iface       = arg;
			break;
		case CLUSTERMCASTIPADDR:
			options_p->cluster_mcastipaddr = arg;
			break;
		case CLUSTERMCASTIPPORT:
			options_p->cluster_mcastipport = (uint16_t)atoi(arg);
			break;
		case CLUSTERTIMEOUT:
			options_p->cluster_timeout     = (unsigned int)atol(arg);
			break;
		case CLUSTERNODENAME:
			options_p->cluster_nodename    = arg;
			break;
		case CLUSTERHDLMIN:
			options_p->cluster_hash_dl_min = (uint16_t)atoi(arg);
			break;
		case CLUSTERHDLMAX:
			options_p->cluster_hash_dl_max = (uint16_t)atoi(arg);
			break;
		case CLUSTERSDLMAX:
			options_p->cluster_scan_dl_max = (uint16_t)atoi(arg);
			break;
#endif
		case OUTLISTSDIR:
			options_p->listoutdir   = arg;
			break;
		case LABEL:
			options_p->label        = arg;
			break;
		case SYNCDELAY: 
			options_p->syncdelay  = (unsigned int)atol(arg);
			break;
		case DELAY:
			options_p->_queues[QUEUE_NORMAL].collectdelay = (unsigned int)atol(arg);
			break;
		case BFILEDELAY:
			options_p->_queues[QUEUE_BIGFILE].collectdelay = (unsigned int)atol(arg);
			break;
		case BFILETHRESHOLD:
			options_p->bfilethreshold = (unsigned long)atol(arg);
			break;
#ifdef FANOTIFY_SUPPORT
		case FANOTIFY:
			options_p->notifyengine = NE_FANOTIFY;
			break;
#endif
		case INOTIFY:
			options_p->notifyengine = NE_INOTIFY;
			break;
		case RSYNCINCLIMIT:
			options_p->rsyncinclimit = (unsigned int)atol(arg);
			break;
		case SYNCTIMEOUT:
			options_p->synctimeout = (unsigned int)atol(arg);
			break;
		case IGNOREEXITCODE: {
			unsigned char exitcode = (unsigned char)atoi(arg);
			if(exitcode == 0) {
				// flushing the setting
				int i = 0;
				while(i < 256)
					options_p->isignoredexitcode[i++] = 0;
			} else {
				options_p->isignoredexitcode[exitcode] = 1;
			}
			break;
		}
		case SHOW_VERSION:
			version();
			break;
		case WATCHDIR:
			options_p->watchdir	= arg;
			break;
		case SYNCHANDLER:
			options_p->handlerfpath	= arg;
			break;
		case RULESFILE:
			options_p->rulfpath	= arg;
			break;
		case DESTDIR:
			options_p->destdir	= arg;
			break;
		case MODE: {
			char *value;

			options_p->flags[MODE]  = getsubopt(&arg, modes, &value);
			if(options_p->flags[MODE] == -1) {
				fprintf(stderr, "Error: Wrong mode name entered: \"%s\"\n", arg);
				return EINVAL;
			}
			break;
		}
		default:
			if(arg == NULL)
				options_p->flags[param_id]++;
			else
				options_p->flags[param_id] = atoi(arg);
#ifdef _DEBUG
			fprintf(stderr, "Force-Debug: flag %i is set to %i\n", param_id&0xff, options_p->flags[param_id]);
#endif
			break;
	}
	return 0;
}

int arguments_parse(int argc, char *argv[], struct options *options_p) {
	int c;
	int option_index = 0;

	// Generating "optstring" (man 3 getopt_long) with using information from struct array "long_options"
	char *optstring     = alloca((('z'-'a'+1)*3 + '9'-'0'+1)*3 + 1);
	char *optstring_ptr = optstring;

	const struct option *lo_ptr = long_options;
	while(lo_ptr->name != NULL) {
		if(!(lo_ptr->val & (OPTION_CONFIGONLY|OPTION_LONGOPTONLY))) {
			*(optstring_ptr++) = lo_ptr->val & 0xff;

			if(lo_ptr->has_arg == required_argument)
				*(optstring_ptr++) = ':';

			if(lo_ptr->has_arg == optional_argument) {
				*(optstring_ptr++) = ':';
				*(optstring_ptr++) = ':';
			}
		}
		lo_ptr++;
	}
	*optstring_ptr = 0;
#ifdef _DEBUG
	fprintf(stderr, "Force-Debug: %s\n", optstring);
#endif

	// Parsing arguments
	while(1) {
		c = getopt_long(argc, argv, optstring, long_options, &option_index);
	
		if (c == -1) break;
		int ret = parse_parameter(options_p, c, optarg, PS_ARGUMENT);
		if(ret) return ret;
	}
	if(optind+1 < argc)
		syntax();
/*
	if(optind+1 >= argc)
		syntax();

	options_p->handlerfpath = argv[optind+1];

	if(optind+2 < argc) {
		options_p->rulfpath = argv[optind+2];
		if(!strcmp(options_p->rulfpath, ""))
			options_p->rulfpath = NULL;
	}

	if(optind+3 < argc) {
		options_p->destdir    = argv[optind+3];
		options_p->destdirlen = strlen(options_p->destdir);
	}

	options_p->watchdir    = argv[optind];
	options_p->watchdirlen = strlen(options_p->watchdir);*/
/*
	if(optind+0 < argc) {
		options_p->watchdir     = argv[optind];
		options_p->watchdirlen  = strlen(options_p->watchdir);
	} else {
		options_p->watchdir     = NULL;
		options_p->watchdirlen  = 0;
	}

	if(optind+1 < argc) {
		options_p->handlerfpath = argv[optind+1];
	} else {
		options_p->handlerfpath = NULL;
	}

	if(optind+2 < argc) {
		options_p->rulfpath = argv[optind+2];
		if(!strcmp(options_p->rulfpath, ""))
			options_p->rulfpath = NULL;
	} else {
		options_p->rulfpath = NULL;
	}

	if(optind+3 < argc) {
		options_p->destdir    = argv[optind+3];
		options_p->destdirlen = strlen(options_p->destdir);
	} else {
		options_p->destdir    = NULL;
		options_p->destdirlen = 0;
	}
*/

	return 0;
}

char *configs_parse_str[1<<10] = {0};

void gkf_parse(options_t *options_p, GKeyFile *gkf) {
	const struct option *lo_ptr = long_options;
	while(lo_ptr->name != NULL) {
		gchar *value = g_key_file_get_value(gkf, options_p->config_block, lo_ptr->name, NULL);
		if(value != NULL) {
			unsigned char val_char = lo_ptr->val&0xff;

			if(configs_parse_str[val_char])
				free(configs_parse_str[val_char]);

			configs_parse_str[val_char] = value;
			int ret = parse_parameter(options_p, lo_ptr->val, value, PS_CONFIG);
			if(ret) exit(ret);
		}
		lo_ptr++;
	}

	return;
}

int configs_parse(options_t *options_p) {
	GKeyFile *gkf;

	gkf = g_key_file_new();

	if(options_p->config_path) {
		printf_d("Debug: configs_parse(): Trying config-file \"%s\"\n", options_p->config_path);
		if(!g_key_file_load_from_file(gkf, options_p->config_path, G_KEY_FILE_NONE, NULL)) {
			printf_e("Error: configs_parse(): Cannot open/parse file \"%s\"\n", options_p->config_path);
			g_key_file_free(gkf);
			return -1;
		} else
			gkf_parse(options_p, gkf);

	} else {
		char *config_paths[] = CONFIG_PATHS;
		char **config_path_p = config_paths, *config_path_real = xmalloc(PATH_MAX);
		size_t config_path_real_size=PATH_MAX;

		char *homedir = getenv("HOME");
		size_t homedir_len = strlen(homedir);

		while(*config_path_p != NULL) {
			size_t config_path_len = strlen(*config_path_p);

			if(config_path_len+homedir_len+3 > config_path_real_size) {
				config_path_real_size = config_path_len+homedir_len+3;
				config_path_real      = xmalloc(config_path_real_size);
			}

			if(*config_path_p[0] != '/') {
				memcpy(config_path_real, homedir, homedir_len);
				config_path_real[homedir_len] = '/';
				memcpy(&config_path_real[homedir_len+1], *config_path_p, config_path_len+1);
			} else 
				memcpy(config_path_real, *config_path_p, config_path_len+1);

			printf_d("Debug: configs_parse(): Trying config-file \"%s\"\n", config_path_real);
			if(!g_key_file_load_from_file(gkf, config_path_real, G_KEY_FILE_NONE, NULL)) {
				printf_d("Debug: configs_parse(): Cannot open/parse file \"%s\"\n", config_path_real);
				config_path_p++;
				continue;
			}

			gkf_parse(options_p, gkf);

			break;
		}
		free(config_path_real);
	}

	g_key_file_free(gkf);

	return 0;
}

int configs_cleanup() {
	int i=0;

	while(i < (1<<10)) {
		if(configs_parse_str[i] != NULL) {
			free(configs_parse_str[i]);
			configs_parse_str[i] = NULL;
		}
		i++;
	}

	return 0;
}

int rule_complete(rule_t *rule_p, const char *expr) {
	printf_ddd("Debug3: rule_complete(): <%s>.\n", expr);
#ifdef VERYPARANOID
	if(rule_p->mask == RA_NONE) {
		printf_e("Error: rule_complete(): Received a rule with rule_p->mask == 0x00. Exit.\n");
		return EINVAL;
	}
#endif

	char buf[BUFSIZ];
	int ret = 0;
	if(rule_p->num >= MAXRULES) {
		printf_e("Error: Too many rules (%i >= %i).\n", rule_p->num, MAXRULES);
		return ENOMEM;
	}
	if((ret = regcomp(&rule_p->expr, expr, REG_EXTENDED | REG_NOSUB))) {
		regerror(ret, &rule_p->expr, buf, BUFSIZ);
		printf_e("Error: Invalid regexp pattern <%s>: %s (regex-errno: %i).\n", expr, buf, ret);
		return ret;
	}

	return ret;
}

int parse_rules_fromfile(options_t *options_p) {
	int ret = 0;
	char *rulfpath = options_p->rulfpath;
	rule_t *rules  = options_p->rules;

	char *line_buf=NULL;
	FILE *f = fopen(rulfpath, "r");
	
	if(f == NULL) {
		rules->mask   = RA_NONE;		// Terminator. End of rules' chain.
		rules->perm   = DEFAULT_RULES_PERM;
		printf_e("Error: Cannot open \"%s\" for reading: %s (errno: %i).\n", rulfpath, strerror(errno), errno);
		return errno;
	}

	GHashTable *autowrules_ht = g_hash_table_new_full(g_str_hash,	g_str_equal,	free,    0);

	int i=0;
	size_t linelen, size=0;
	while((linelen = getline(&line_buf, &size, f)) != -1) {
		if(linelen>1) {
			uint8_t sign = 0;
			char *line = line_buf;
			rule_t *rule;

			rule = &rules[i];
#ifdef VERYPARANOID
			memset(rule, 0, sizeof(*rule));
#endif
			rule->num = i++;
			line[--linelen] = 0; 


			// Parsing the first character of the line
			switch(*line) {
				case '+':
					sign = RS_PERMIT;
					break;
				case '-':
					sign = RS_REJECT;
					break;
				case '#':	// Comment?
					i--;	// Canceling new rule
					continue;
				default:
					printf_e("Error: Wrong rule action <%c>.\n", *line);
					return EINVAL;
			}

			line++;
			linelen--;

			// Parsing the second character of the line
			*line |= 0x20;	// lower-casing
			// Default rule->mask and rule->perm

			// rule->mask - sets bitmask of operations that are affected by the rule
			// rule->perm - sets bitmask of permit/reject for every operation. Effect have only bits specified by the rule->mask.

			rule->mask = RA_ALL;
			switch(sign) {
				case RS_REJECT:
					rule->perm = RA_NONE;
					break;
				case RS_PERMIT:
					rule->perm = RA_ALL;
					break;
			}

			switch(*line) {
				case '*':
					rule->objtype = 0;	// "0" - means "of any type"
					break;
#ifdef DETAILED_FTYPE
				case 's':
					rule->objtype = S_IFSOCK;
					break;
				case 'l':
					rule->objtype = S_IFLNK;
					break;
				case 'b':
					rule->objtype = S_IFBLK;
					break;
				case 'c':
					rule->objtype = S_IFCHR;
					break;
				case 'p':
					rule->objtype = S_IFIFO;
					break;
#endif
				case 'f':
					rule->objtype = S_IFREG;
					break;
				case 'd':
					rule->objtype = S_IFDIR;
					break;
				case 'w':	// accept or reject walking to directory
					if(
						(options_p->flags[MODE] == MODE_RSYNCDIRECT) ||
						(options_p->flags[MODE] == MODE_RSYNCSHELL)  ||
						(options_p->flags[MODE] == MODE_RSYNCSO)
					) {
						printf_e("parse_rules_fromfile(): Warning: Used \"w\" rule in \"--rsync\" case."
							" This may cause unexpected problems.\n");
					}
					rule->objtype = S_IFDIR;
					rule->mask    = RA_WALK;
					break;
				default:
					printf_e("parse_rules_fromfile(): Warning: Cannot parse the rule <%s>\n", &line[-1]);
					i--;	// Canceling new rule
					continue;
			}


			line++;
			linelen--;

			// Parsing the rest part of the line

			printf_d("Debug: parse_rules_fromfile(): Rule #%i <%c> <%c> pattern <%s> (length: %i).\n", rule->num, line[-2], line[-1], line, linelen);
			if((ret=rule_complete(rule, line)))
				goto l_parse_rules_fromfile_end;

			// Post-processing:

			line--;
			linelen++;

			if(*line != 'w') {
				// processing --auto-add-rules-w
				if(options_p->flags[AUTORULESW] && (sign == RS_PERMIT)) {
					// Preparing to add appropriate w-rules
					char skip = 0;
					char *expr = alloca(linelen+2);
					memcpy(expr, line, linelen+1);
					size_t exprlen = linelen;

					// Making expr to be starting with '^'
					if(line[1] == '^') {
						expr++;
						exprlen--;
					} else
						*expr = '^';

					char *end;

					if(*line == 'd' || *line == '*') {
						// "d" rule already doing what we need, so we can skip the last level

						end = &expr[exprlen];
						if(end[-1] != '$')
							*(end++) = '$';
						*end = 0;

//						printf_ddd("Debug3: parse_rules_fromfile(): Don't adding w-rule for \"%s\" due to [*d]-rule for \"%s\"\n",
//							expr, &line[1]);
						g_hash_table_insert(autowrules_ht, strdup(expr), GINT_TO_POINTER(1));

					}

					if(!skip) {

						do {
							// Decreasing directory level and make the '$' ending
							end = strrchr(expr, '/');
							if(end != NULL) {
								if(end[-1] != '$')
									*(end++) = '$';
								*end = 0;
								exprlen = (size_t)(end - expr);
							} else {
								expr[1] = '$';
								expr[2] = 0;
								exprlen = 2;
							}

							// Checking if it not already set
							if(!g_hash_table_lookup(autowrules_ht, expr)) {

								// Switching to next rule:

								rule = &rules[i];
								rule->num = i++;

								// Adding the rule

								rule->objtype = S_IFDIR;
								rule->mask    = RA_WALK;
								rule->perm    = RA_WALK;

								printf_d("Debug: parse_rules_fromfile(): Rule #%i <+> <w> pattern <%s> (length: %i) [auto].\n", 
									rule->num, expr, exprlen);
								if((ret=rule_complete(rule, expr)))
									goto l_parse_rules_fromfile_end;
								g_hash_table_insert(autowrules_ht, strdup(expr), GINT_TO_POINTER(1));

							}
						} while(end != NULL);
					}
				}
			}
		}
	}

l_parse_rules_fromfile_end:
	if(size)
		free(line_buf);

	fclose(f);

	printf_ddd("Debug3: parse_rules_fromfile(): Adding tail-rule #%u (effective #%u).\n", -1, i);

	rules[i].mask   = RA_NONE;		// Terminator. End of rules' chain.
	rules[i].perm   = DEFAULT_RULES_PERM;

	g_hash_table_destroy(autowrules_ht);
#ifdef _DEBUG
	printf_ddd("Debug3: parse_rules_fromfile(): Total (p == %p):\n", rules);
	i=0;
	do {
		printf_ddd("\t%i\t%i\t%p/%p\n", i, rules[i].objtype, (void *)(long)rules[i].perm, (void *)(long)rules[i].mask);
		i++;
	} while(rules[i].mask != RA_NONE);
#endif
	return ret;
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

int main_cleanup(options_t *options_p) {
	int i=0;
	while((i < MAXRULES) && (options_p->rules[i].mask != RA_NONE))
		regfree(&options_p->rules[i++].expr);

	printf_ddd("Debug3: main_cleanup(): %i %i %i %i\n", options_p->watchdirsize, options_p->watchdirwslashsize, options_p->destdirsize, options_p->destdirwslashsize);

	return 0;
}

int main_rehash(options_t *options_p) {
	printf_ddd("Debug3: main_rehash()\n");
	int ret=0;

	main_cleanup(options_p);

	if(options_p->rulfpath != NULL) {
		ret = parse_rules_fromfile(options_p);
		if(ret)
			printf_e("Error: main_rehash(): Got error from parse_rules_fromfile(): %s (errno: %i).\n", strerror(ret), ret);
	} else {
		options_p->rules[0].perm = DEFAULT_RULES_PERM;
		options_p->rules[0].mask = RA_NONE;		// Terminator. End of rules.
	}

	return ret;
}

int main(int argc, char *argv[]) {
	struct options options;
#ifdef CLUSTER_SUPPORT
	struct utsname utsname;
#endif
	memset(&options, 0, sizeof(options));
	int ret = 0, nret;
	options.notifyengine 			   = DEFAULT_NOTIFYENGINE;
	options.syncdelay 			   = DEFAULT_SYNCDELAY;
	options._queues[QUEUE_NORMAL].collectdelay = DEFAULT_COLLECTDELAY;
	options._queues[QUEUE_BIGFILE].collectdelay= DEFAULT_BFILECOLLECTDELAY;
	options._queues[QUEUE_INSTANT].collectdelay= COLLECTDELAY_INSTANT;
	options.bfilethreshold			   = DEFAULT_BFILETHRESHOLD;
	options.label				   = DEFAULT_LABEL;
	options.rsyncinclimit			   = DEFAULT_RSYNCINCLUDELINESLIMIT;
	options.synctimeout			   = DEFAULT_SYNCTIMEOUT;
#ifdef CLUSTER_SUPPORT
	options.cluster_hash_dl_min		   = DEFAULT_CLUSTERHDLMIN;
	options.cluster_hash_dl_max		   = DEFAULT_CLUSTERHDLMAX;
	options.cluster_scan_dl_max		   = DEFAULT_CLUSTERSDLMAX;
#endif
	options.config_block = DEFAULT_CONFIG_BLOCK;

	arguments_parse(argc, argv, &options);
	out_init(options.flags);
	nret = configs_parse(&options);
	if(nret) ret = nret;
	out_init(options.flags);

	if(options.flags[EXCLUDEMOUNTPOINTS])
		options.flags[ONEFILESYSTEM]=1;

	if(options.flags[MODE] == MODE_UNSET) {
		printf_e("Error: \"--mode\" is not set.\n");
		ret = EINVAL;
	}

	if(options.watchdir == NULL) {
		printf_e("Error: \"--watchdir\" is not set.\n");
		ret = EINVAL;
	}

	if(options.handlerfpath == NULL) {
		printf_e("Error: \"--sync-handler\" path is not set.\n");
		ret = EINVAL;
	}
/*
	if(options.flags[SYNCHANDLERSO] && options.flags[RSYNC]) {
		printf_e("Error: Option \"--rsync\" cannot be used in conjunction with \"--synchandler-so-module\".\n");
		ret = EINVAL;
	}
*/
//	if(options.flags[SYNCHANDLERSO] && (options.listoutdir != NULL))
//		printf_e("Warning: Option \"--dir-lists\" has no effect conjunction with \"--synchandler-so-module\".\n");

//	if(options.flags[SYNCHANDLERSO] && (options.destdir != NULL))
//		printf_e("Warning: Destination directory argument has no effect conjunction with \"--synchandler-so-module\".\n");

	if((options.flags[MODE] == MODE_RSYNCDIRECT) && (options.destdir == NULL)) {
		printf_e("Error: Mode \"rsyncdirect\" cannot be used without specifying \"destination directory\".\n");
		ret = EINVAL;
	}

#ifdef CLUSTER_SUPPORT
	if((options.flags[MODE] == MODE_RSYNCDIRECT ) && (options.cluster_iface != NULL)) {
		printf_e("Error: Mode \"rsyncdirect\" cannot be used in conjunction with \"--cluster-iface\".\n");
		ret = EINVAL;
	}

	if((options.cluster_iface == NULL) && ((options.cluster_mcastipaddr != NULL) || (options.cluster_nodename != NULL) || (options.cluster_timeout) || (options.cluster_mcastipport))) {
		printf_e("Error: Options \"--cluster-ip\", \"--cluster-node-name\", \"--cluster_timeout\" and/or \"cluster_ipport\" cannot be used without \"--cluster-iface\".\n");
		ret = EINVAL;
	}

	if(options.cluster_hash_dl_min > options.cluster_hash_dl_max) {
		printf_e("Error: \"--cluster-hash-dl-min\" cannot be greater than \"--cluster-hash-dl-max\".\n");
		ret = EINVAL;
	}

	if(options.cluster_hash_dl_max > options.cluster_scan_dl_max) {
		printf_e("Error: \"--cluster-hash-dl-max\" cannot be greater than \"--cluster-scan-dl-max\".\n");
		ret = EINVAL;
	}

	if(!options.cluster_timeout)
		options.cluster_timeout	    = DEFAULT_CLUSTERTIMEOUT;
	if(!options.cluster_mcastipport)
		options.cluster_mcastipport = DEFAULT_CLUSTERIPPORT;
	if(!options.cluster_mcastipaddr)
		options.cluster_mcastipaddr = DEFAULT_CLUSTERIPADDR;

	if(options.cluster_iface != NULL) {
#ifndef _DEBUG
		printf_e("Error: Cluster subsystem is not implemented, yet. Sorry.\n");
		ret = EINVAL;
#endif
		if(options.cluster_nodename == NULL) {

			if(!uname(&utsname))
				options.cluster_nodename = utsname.nodename;

			printf_d("Debug: cluster node name is: %s\n", options.cluster_nodename);
		}
		if(options.cluster_nodename == NULL) {
			printf_e("Error: Option \"--cluster-iface\" is set, but \"--cluster-node-name\" is not set and cannot get the nodename with uname().\n");
			ret = EINVAL;
		} else {
			options.cluster_nodename_len = strlen(options.cluster_nodename);
		}
	}
#endif // CLUSTER_SUPPORT

	{
		char *rwatchdir = realpath(options.watchdir, NULL);
		if(rwatchdir == NULL) {
			printf_e("Error: main(): Got error while realpath() on \"%s\": %s (errno: %i) [#0].\n", options.watchdir, strerror(errno), errno);
			ret = errno;
		}

		if(!ret) {
			options.watchdir     = rwatchdir;
			options.watchdirlen  = strlen(options.watchdir);
			options.watchdirsize = options.watchdirlen;

#ifdef VERYPARANOID
			if(options.watchdirlen == 1) {
				printf_e("Very-Paranoid: --watch-dir is supposed to be not \"/\".\n");
				ret = EINVAL;
			}
#endif
		}

		if(!ret) {
			if(options.watchdirlen == 1) {
				options.watchdirwslash     = options.watchdir;
				options.watchdirwslashsize = 0;
				options.watchdir_dirlevel  = 0;
			} else {
				size_t size = options.watchdirlen + 2;
				char *newwatchdir = xmalloc(size);
				memcpy( newwatchdir, options.watchdir, options.watchdirlen);
				options.watchdirwslash     = newwatchdir;
				options.watchdirwslashsize = size;
				memcpy(&options.watchdirwslash[options.watchdirlen], "/", 2);

				options.watchdir_dirlevel  = fileutils_calcdirlevel(options.watchdirwslash);
			}
		}
	}

	if(options.destdir != NULL) {
		char *rdestdir = realpath(options.destdir, NULL);
		if(rdestdir == NULL) {
			printf_e("Error: main(): Got error while realpath() on \"%s\": %s (errno: %i) [#1].\n", options.destdir, strerror(errno), errno);
			ret = errno;
		}

		if(!ret) {
			options.destdir     = rdestdir;
			options.destdirlen  = strlen(options.destdir);
			options.destdirsize = options.destdirlen;

			if(options.destdirlen == 1) {
				printf_e("Error: destdir is supposed to be not \"/\".\n");
				ret = EINVAL;
			}
		}

		if(!ret) {
			size_t size = options.destdirlen  + 2;
			char *newdestdir  = xmalloc(size);
			memcpy( newdestdir,  options.destdir,  options.destdirlen);
			options.destdirwslash     = newdestdir;
			options.destdirwslashsize = size;
			memcpy(&options.destdirwslash[options.destdirlen], "/", 2);
		}
	}

	printf_d("Debug: %s [%s] (%p) -> %s [%s]\n", options.watchdir, options.watchdirwslash, options.watchdirwslash, options.destdir?options.destdir:"", options.destdirwslash?options.destdirwslash:"");

	if(
		(
			(options.flags[MODE]==MODE_RSYNCDIRECT) || 
			(options.flags[MODE]==MODE_RSYNCSHELL)  ||
			(options.flags[MODE]==MODE_RSYNCSO)
		) && (options.listoutdir == NULL)
	) {
		printf_e("Error: Modes \"rsyncdirect\", \"rsyncshell\" and \"rsyncso\" cannot be used without \"--lists-dir\".\n");
		ret = EINVAL;
	}

	if(
		options.flags[RSYNCPREFERINCLUDE] && 
		!(
			options.flags[MODE] == MODE_RSYNCDIRECT ||
			options.flags[MODE] == MODE_RSYNCSHELL  ||
			options.flags[MODE] == MODE_RSYNCSO
		)
	)
		printf_e("Warning: Option \"--rsyncpreferinclude\" is useless if mode is not \"rsyncdirect\", \"rsyncshell\" or \"rsyncso\".\n");

	if(
		(
			options.flags[MODE] == MODE_RSYNCDIRECT ||
			options.flags[MODE] == MODE_RSYNCSHELL  ||
			options.flags[MODE] == MODE_RSYNCSO
		)
		&& options.flags[AUTORULESW]
	)
		printf_e("Warning: Option \"--auto-add-rules-w\" in modes \"rsyncdirect\", \"rsyncshell\" and \"rsyncso\" may cause unexpected problems.\n");

	if(options.flags[DEBUG])
		debug_print_flags();

	if(options.listoutdir != NULL) {
		struct stat st={0};
		errno = 0;
		if(stat(options.listoutdir, &st)) {
			if(errno == ENOENT) {
				printf_e("Warning: Directory \"%s\" doesn't exist. Creating it.\n", options.listoutdir);
				errno = 0;
				if(mkdir(options.listoutdir, S_IRWXU)) {
					printf_e("Error: main(): Cannot create directory \"%s\": %s (errno: %i).\n", options.listoutdir, strerror(errno), errno);
					ret = errno;
				}
			} else {
				printf_e("Error: main(): Got error while stat() on \"%s\": %s (errno: %i).\n", options.listoutdir, strerror(errno), errno);
				ret = errno;
			}
		}
		if(!errno)
			if(st.st_mode & (S_IRWXG|S_IRWXO)) {
#ifdef PARANOID
				printf_e("Error: Insecure: Others have access to directory \"%s\". Exit.\n", options.listoutdir);
				ret = EACCES;
#else
				printf_e("Warning: Insecure: Others have access to directory \"%s\".\n", options.listoutdir);
#endif
			}
	}

/*
	if(options.flags[HAVERECURSIVESYNC] && (options.listoutdir == NULL)) {
		printf_e("Error: main(): Option \"--dir-lists\" should be set to use option \"--have-recursive-sync\".\n");
		ret = EINVAL;
	}
*/

	if(
		options.flags[HAVERECURSIVESYNC] &&
		(
			options.flags[MODE] == MODE_RSYNCDIRECT ||
			options.flags[MODE] == MODE_RSYNCSHELL  ||
			options.flags[MODE] == MODE_RSYNCSO
		)
	) {
		printf_e("Error: main(): Option \"--have-recursive-sync\" with nodes \"rsyncdirect\", \"rsyncshell\" and \"rsyncso\" are incompatable.\n");
		ret = EINVAL;
	}

	if(options.flags[SYNCLISTSIMPLIFY] && (options.listoutdir == NULL)) {
		printf_e("Error: main(): Option \"--dir-lists\" should be set to use option \"--synclist-simplify\".\n");
		ret = EINVAL;
	}

	if(
		options.flags[SYNCLISTSIMPLIFY] && 
		(
			options.flags[MODE] == MODE_RSYNCDIRECT ||
			options.flags[MODE] == MODE_RSYNCSHELL  ||
			options.flags[MODE] == MODE_RSYNCSO
		)
	) {
		printf_e("Error: main(): Option \"--synclist-simplify\" with nodes \"rsyncdirect\" and \"rsyncshell\" are incompatable.\n");
		ret = EINVAL;
	}

#ifdef FANOTIFY_SUPPORT
	if(options.notifyengine != NE_INOTIFY) {
		printf_e("Warning: fanotify is not fully supported, yet!\n");
	}
#endif

	if(access(options.handlerfpath, X_OK) == -1) {
		printf_e("Error: \"%s\" is not executable: %s (errno: %i).\n", options.handlerfpath, strerror(errno), errno);
		ret = errno;
	}

	{
		struct stat64 stat64={0};
		if(lstat64(options.watchdir, &stat64)) {
			printf_e("Error: main(): Cannot lstat64() on \"%s\": %s (errno: %i)\n", options.watchdir, strerror(errno), errno);
			ret = errno;
		} else {
			if(options.flags[EXCLUDEMOUNTPOINTS])
				options.st_dev = stat64.st_dev;
#ifdef VERYPARANOID
			if((stat64.st_mode & S_IFMT) == S_IFLNK) {
				// The proplems may be due to FTS_PHYSICAL option of ftp_open() in sync_initialsync_rsync_walk(),
				// so if the "watch dir" is just a symlink it doesn't walk recursivly. For example, in "-R" case
				// it disables filters, because exclude-list will be empty.

				printf_e("Error: Watch dir cannot be symlink, but \"%s\" is a symlink.\n", options.watchdir);
				ret = EINVAL;
			}
#endif
		}
	}

	nret=main_rehash(&options);
	if(nret)
		ret = nret;

	if(options.flags[BACKGROUND]) {
		nret = becomedaemon();
		if(nret)
			ret = nret;
	}

#ifdef HAVE_CAPABILITIES
	if(options.flags[CAP_PRESERVE_FILEACCESS]) {
		// Doesn't work, yet :(
		//
		// Error: Cannot inotify_add_watch() on "/home/xaionaro/clsync/examples/testdir/from": Permission denied (errno: 13).

		printf_d("Debug: main(): Preserving access to files with using linux capabilites\n");

		struct __user_cap_header_struct	cap_hdr = {0};
		struct __user_cap_data_struct	cap_dat = {0};

		cap_hdr.version = _LINUX_CAPABILITY_VERSION;
		if(capget(&cap_hdr, &cap_dat) < 0) {
			printf_e("Error: main() cannot get capabilites with capget(): %s (errno: %i)\n", strerror(errno), errno);
			ret = errno;

			goto preserve_fileaccess_end;
		}

		// From "man 7 capabilities":
		// CAP_DAC_OVERRIDE    - Bypass file read, write, and execute permission checks. 
		// CAP_DAC_READ_SEARCH - Bypass file read permission checks and directory read and execute permission checks.

		cap_dat.effective    =  (CAP_TO_MASK(CAP_DAC_OVERRIDE)|CAP_TO_MASK(CAP_DAC_READ_SEARCH)|CAP_TO_MASK(CAP_FOWNER)|CAP_TO_MASK(CAP_SYS_ADMIN)|CAP_TO_MASK(CAP_SETUID));
		cap_dat.permitted    =  (CAP_TO_MASK(CAP_DAC_OVERRIDE)|CAP_TO_MASK(CAP_DAC_READ_SEARCH)|CAP_TO_MASK(CAP_FOWNER)|CAP_TO_MASK(CAP_SYS_ADMIN)|CAP_TO_MASK(CAP_SETUID));
		cap_dat.inheritable  = 0;

		printf_ddd("Debug3: main(): cap.eff == %p; cap.prm == %p.\n",
			(void *)(long)cap_dat.effective, (void *)(long)cap_dat.permitted);

		if(capset(&cap_hdr, &cap_dat) < 0) {
			printf_e("Error: main(): Cannot set capabilities with capset(): %s (errno: %i).\n", strerror(errno), errno);
			ret = errno;

			goto preserve_fileaccess_end;
		}

		// Tell kernel not clear capabilities when dropping root 
		if(prctl(PR_SET_KEEPCAPS, 1) < 0) {
			printf_e("Error: main(): Cannot prctl(PR_SET_KEEPCAPS, 1) to preserve capabilities: %s (errno: %i)\n",
				strerror(errno), errno);
			ret = errno;

			goto preserve_fileaccess_end;
		}
	}
preserve_fileaccess_end:
#endif

	if(options.flags[UID]) {
		if(setuid(options.uid)) {
			printf_e("Error: main(): Cannot setuid(%u): %s (errno: %i)\n", options.uid, strerror(errno), errno);
			ret = errno;
		}
	}

	if(options.flags[GID]) {
		if(setuid(options.gid)) {
			printf_e("Error: main(): Cannot setgid(%u): %s (errno: %i)\n", options.gid, strerror(errno), errno);
			ret = errno;
		}
	}

	if(options.pidfile != NULL) {
		pid_t pid = getpid();
		FILE *pidfile = fopen(options.pidfile, "w");
		if(pidfile == NULL) {
			printf_e("Error: main(): Cannot open file \"%s\" to write a pid there: %s (errno: %i)\n",
				options.pidfile, strerror(errno), errno);
			ret = errno;
		} else {
			if(fprintf(pidfile, "%u\n", pid) < 0) {
				printf_e("Error: main(): Cannot write pid into file \"%s\": %s (errno: %i)\n",
					options.pidfile, strerror(errno), errno);
				ret = errno;
			}
			fclose(pidfile);
		}
	}

	printf_ddd("Debug3: main(): Current errno is %i.\n", ret);

	if(ret == 0)
		ret = sync_run(&options);

	if(options.pidfile != NULL) {
		if(unlink(options.pidfile)) {
			printf_e("Error: main(): Cannot unlink pidfile \"%s\": %s (errno: %i)\n",
				options.pidfile, strerror(errno), errno);
			ret = errno;
		}
	}

	main_cleanup(&options);

	if(options.watchdirsize)
		free(options.watchdir);

	if(options.watchdirwslashsize)
		free(options.watchdirwslash);

	if(options.destdirsize)
		free(options.destdir);

	if(options.destdirwslashsize)
		free(options.destdirwslash);

	configs_cleanup();
	out_flush();
	printf_d("Debug: finished, exitcode: %i: %s.\n", ret, strerror(ret));
	out_flush();
	out_deinit();
	return ret;
}


