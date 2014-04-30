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

#include <pwd.h>	// For getpwnam()
#include <grp.h>	// For getgrnam()

#include "error.h"
#include "sync.h"
#include "malloc.h"
#include "cluster.h"
#include "fileutils.h"
#include "socket.h"

//#include "revision.h"

static const struct option long_glob[] =
{
	{"watch-dir",		required_argument,	NULL,	WATCHDIR},
	{"sync-handler",	required_argument,	NULL,	SYNCHANDLER},
	{"rules-file",		required_argument,	NULL,	RULESFILE},
	{"destination-dir",	required_argument,	NULL,	DESTDIR},
	{"mode",		required_argument,	NULL,	MODE},
	{"socket",		required_argument,	NULL,	SOCKETPATH},
	{"socket-auth",		required_argument,	NULL,	SOCKETAUTH},
	{"socket-mod",		required_argument,	NULL,	SOCKETMOD},
	{"socket-own",		required_argument,	NULL,	SOCKETOWN},
	{"status-file",		required_argument,	NULL,	STATUSFILE},

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
	{"retries",		optional_argument,	NULL,	RETRIES},
	{"output",		required_argument,	NULL,	OUTPUT_METHOD},
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
	{"max-iterations",	required_argument,	NULL,	MAXITERATIONS},
	{"standby-file",	required_argument,	NULL,	STANDBYFILE},
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
	{"only-initialsync",	optional_argument,	NULL,	ONLYINITSYNC},
	{"skip-initialsync",	optional_argument,	NULL,	SKIPINITSYNC},
	{"exit-on-no-events",	optional_argument,	NULL,	EXITONNOEVENTS},
	{"exit-hook",		required_argument,	NULL,	EXITHOOK},
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

static char *const socketauth[] = {
	[SOCKAUTH_UNSET]	= "",
	[SOCKAUTH_NULL]		= "null",
//	[SOCKAUTH_PAM]		= "pam",
	NULL
};

static char *const output_methods[] = {
	[OM_STDERR]		= "stderr",
	[OM_STDOUT]		= "stdout",
	[OM_SYSLOG]		= "syslog",
	NULL
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

static char *const status_descr[] = {
	[STATE_EXIT]		= "exiting",
	[STATE_STARTING]	= "starting",
	[STATE_RUNNING]		= "running",
	[STATE_REHASH]		= "rehashing",
	[STATE_TERM]		= "terminating",
	[STATE_PTHREAD_GC]	= "pthread gc",
	[STATE_INITSYNC]	= "initsync",
	NULL
};

int syntax() {
	info("possible glob:");
	int i=0;
	while(long_glob[i].name != NULL) {
		if(!(long_glob[i].val & OPTION_CONFIGONLY))
			info("\t--%-24s%c%c%s", long_glob[i].name, 
				long_glob[i].val & OPTION_LONGOPTONLY ? ' ' : '-', 
				long_glob[i].val & OPTION_LONGOPTONLY ? ' ' : long_glob[i].val, 
				(long_glob[i].has_arg == required_argument ? " argument" : ""));
		i++;
	}
	exit(EINVAL);
}

int version() {
	info(PROGRAM" v%i.%i"REVISION"\n\t"AUTHOR"", VERSION_MAJ, VERSION_MIN);
	exit(0);
}

int clsyncapi_getapiversion() {
	return CLSYNC_API_VERSION;
}

int parse_parameter(glob_t *glob_p, uint16_t param_id, char *arg, paramsource_t paramsource) {
#ifdef _DEBUG
	fprintf(stderr, "Force-Debug: parse_parameter(): %i: %i = \"%s\"\n", paramsource, param_id, arg);
#endif
	switch(paramsource) {
		case PS_ARGUMENT:
			if(param_id & OPTION_CONFIGONLY) {
				syntax();
				return 0;
			}
			glob_p->flags_set[param_id] = 1;
			break;
		case PS_CONFIG:
			if(glob_p->flags_set[param_id])
				return 0;
			break;
		default:
			error("Warning: Unknown parameter #%i source (value \"%s\").", param_id, arg!=NULL ? arg : "");
			break;
	}
	switch(param_id) {
		case '?':
		case HELP:
			syntax();
			break;
		case CONFIGFILE:
			glob_p->config_path  = *arg ? arg : NULL;
			break;
		case CONFIGBLOCK:
			glob_p->config_block = *arg ? arg : NULL;
			break;
		case GID:
			glob_p->gid = (unsigned int)atol(arg);
			glob_p->flags[param_id]++;
			break;
		case UID:
			glob_p->uid = (unsigned int)atol(arg);
			glob_p->flags[param_id]++;
			break;
		case PIDFILE:
			glob_p->pidfile		= arg;
			break;
		case RETRIES:
			glob_p->retries		= (unsigned int)atol(arg);
			break;
		case OUTPUT_METHOD: {
			char *value, *arg_orig = arg;

			outputmethod_t outputmethod = getsubopt(&arg, output_methods, &value);
			if(outputmethod == -1) {
				errno = EINVAL;
				error("Invalid log writing destination entered: \"%s\"", arg_orig);
				return EINVAL;
			}
			glob_p->flags[OUTPUT_METHOD] = outputmethod;
		}
#ifdef CLUSTER_SUPPORT
		case CLUSTERIFACE:
			glob_p->cluster_iface	= arg;
			break;
		case CLUSTERMCASTIPADDR:
			glob_p->cluster_mcastipaddr	= arg;
			break;
		case CLUSTERMCASTIPPORT:
			glob_p->cluster_mcastipport	= (uint16_t)atoi(arg);
			break;
		case CLUSTERTIMEOUT:
			glob_p->cluster_timeout	= (unsigned int)atol(arg);
			break;
		case CLUSTERNODENAME:
			glob_p->cluster_nodename	= arg;
			break;
		case CLUSTERHDLMIN:
			glob_p->cluster_hash_dl_min	= (uint16_t)atoi(arg);
			break;
		case CLUSTERHDLMAX:
			glob_p->cluster_hash_dl_max	= (uint16_t)atoi(arg);
			break;
		case CLUSTERSDLMAX:
			glob_p->cluster_scan_dl_max	= (uint16_t)atoi(arg);
			break;
#endif
		case OUTLISTSDIR:
			glob_p->listoutdir		= arg;
			break;
		case LABEL:
			glob_p->label		= arg;
			break;
		case STANDBYFILE:
			if(strlen(arg)) {
				glob_p->standbyfile		= arg;
				glob_p->flags[STANDBYFILE]	= 1;
			} else {
				glob_p->standbyfile		= NULL;
				glob_p->flags[STANDBYFILE]	= 0;
			}
			break;
		case SYNCDELAY: 
			glob_p->syncdelay		= (unsigned int)atol(arg);
			break;
		case DELAY:
			glob_p->_queues[QUEUE_NORMAL].collectdelay = (unsigned int)atol(arg);
			break;
		case BFILEDELAY:
			glob_p->_queues[QUEUE_BIGFILE].collectdelay = (unsigned int)atol(arg);
			break;
		case BFILETHRESHOLD:
			glob_p->bfilethreshold = (unsigned long)atol(arg);
			break;
#ifdef FANOTIFY_SUPPORT
		case FANOTIFY:
			glob_p->notifyengine = NE_FANOTIFY;
			break;
#endif
		case INOTIFY:
			glob_p->notifyengine = NE_INOTIFY;
			break;
		case RSYNCINCLIMIT:
			glob_p->rsyncinclimit = (unsigned int)atol(arg);
			break;
		case SYNCTIMEOUT:
			glob_p->synctimeout   = (unsigned int)atol(arg);
			break;
		case EXITHOOK:
			if(strlen(arg)) {
				glob_p->exithookfile		= arg;
				glob_p->flags[EXITHOOK]	= 1;
			} else {
				glob_p->exithookfile		= NULL;
				glob_p->flags[EXITHOOK]	= 0;
			}
			break;
		case IGNOREEXITCODE: {
			char *ptr = arg, *start = arg;
			unsigned char exitcode;
			do {
				switch(*ptr) {
					case 0:
					case ',':
//						*ptr=0;
						exitcode = (unsigned char)atoi(start);
						if(exitcode == 0) {
							// flushing the setting
							int i = 0;
							while(i < 256)
								glob_p->isignoredexitcode[i++] = 0;
#ifdef _DEBUG
							fprintf(stderr, "Force-Debug: parse_parameter(): Reset ignored exitcodes.\n");
#endif
						} else {
							glob_p->isignoredexitcode[exitcode] = 1;
#ifdef _DEBUG
							fprintf(stderr, "Force-Debug: parse_parameter(): Adding ignored exitcode %u.\n", exitcode);
#endif
						}
						start = ptr+1;
						break;
				}
			} while(*(ptr++));
			break;
		}
		case SHOW_VERSION:
			version();
			break;
		case WATCHDIR:
			glob_p->watchdir	= arg;
			break;
		case SYNCHANDLER:
			glob_p->handlerfpath	= arg;
			break;
		case RULESFILE:
			glob_p->rulfpath	= arg;
			break;
		case DESTDIR:
			glob_p->destdir	= arg;
			break;
		case SOCKETPATH:
			glob_p->socketpath	= arg;
			break;
		case SOCKETAUTH: {
			char *value;

			glob_p->flags[SOCKETAUTH] = getsubopt(&arg, socketauth, &value);
			if(glob_p->flags[SOCKETAUTH] == -1) {
				error("Wrong socket auth mech entered: \"%s\"", arg);
				return EINVAL;
			}
		}
		case SOCKETMOD:
			if(!sscanf(arg, "%o", &glob_p->socketmod)) {
				error("Non octal value passed to --socket-mod: \"%s\"", arg);
				return EINVAL;
			}
			glob_p->flags[param_id]++;
			break;
		case SOCKETOWN: {
			char *colon = strchr(arg, ':');
			uid_t uid;
			gid_t gid;

			if(colon == NULL) {
				struct passwd *pwent = getpwnam(arg);

				if(pwent == NULL) {
					error("Cannot find username \"%s\" (case #0)", 
						arg);
					return EINVAL;
				}

				uid = pwent->pw_uid;
				gid = pwent->pw_gid;

			} else {

				char user[USER_LEN+2], group[GROUP_LEN+2];

				memcpy(user, arg, MIN(USER_LEN, colon-arg));
				user[colon-arg] = 0;

				strncpy(group, &colon[1], GROUP_LEN);

				errno=0;
				struct passwd *pwent = getpwnam(user);
				if(pwent == NULL) {
					error("Cannot find username \"%s\" (case #1)", 
						user);
					return EINVAL;
				}

				errno=0;
				struct group  *grent = getgrnam(group);
				if(grent == NULL) {
					error("Cannot find group \"%s\"", 
						group);
					return EINVAL;
				}
	
				uid = pwent->pw_uid;
				gid = grent->gr_gid;
			}

			glob_p->socketuid = uid;
			glob_p->socketgid = gid;
			glob_p->flags[param_id]++;

			debug(2, "socket: uid == %u; gid == %u", uid, gid);

			break;
		}
		case STATUSFILE:
			glob_p->statusfile	= arg;
			break;
		case MODE: {
			char *value;

			glob_p->flags[MODE]  = getsubopt(&arg, modes, &value);
			if(glob_p->flags[MODE] == -1) {
				error("Wrong mode name entered: \"%s\"", arg);
				return EINVAL;
			}
			break;
		}
		default:
			if(arg == NULL)
				glob_p->flags[param_id]++;
			else
				glob_p->flags[param_id] = atoi(arg);
#ifdef _DEBUG
			fprintf(stderr, "Force-Debug: flag %i is set to %i\n", param_id&0xff, glob_p->flags[param_id]);
#endif
			break;
	}
	return 0;
}

int arguments_parse(int argc, char *argv[], struct glob *glob_p) {
	int c;
	int option_index = 0;

	// Generating "optstring" (man 3 getopt_long) with using information from struct array "long_glob"
	char *optstring     = alloca((('z'-'a'+1)*3 + '9'-'0'+1)*3 + 1);
	char *optstring_ptr = optstring;

	const struct option *lo_ptr = long_glob;
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
		c = getopt_long(argc, argv, optstring, long_glob, &option_index);
	
		if (c == -1) break;
		int ret = parse_parameter(glob_p, c, optarg, PS_ARGUMENT);
		if(ret) return ret;
	}
	if(optind+1 < argc)
		syntax();
/*
	if(optind+1 >= argc)
		syntax();

	glob_p->handlerfpath = argv[optind+1];

	if(optind+2 < argc) {
		glob_p->rulfpath = argv[optind+2];
		if(!strcmp(glob_p->rulfpath, ""))
			glob_p->rulfpath = NULL;
	}

	if(optind+3 < argc) {
		glob_p->destdir    = argv[optind+3];
		glob_p->destdirlen = strlen(glob_p->destdir);
	}

	glob_p->watchdir    = argv[optind];
	glob_p->watchdirlen = strlen(glob_p->watchdir);*/
/*
	if(optind+0 < argc) {
		glob_p->watchdir     = argv[optind];
		glob_p->watchdirlen  = strlen(glob_p->watchdir);
	} else {
		glob_p->watchdir     = NULL;
		glob_p->watchdirlen  = 0;
	}

	if(optind+1 < argc) {
		glob_p->handlerfpath = argv[optind+1];
	} else {
		glob_p->handlerfpath = NULL;
	}

	if(optind+2 < argc) {
		glob_p->rulfpath = argv[optind+2];
		if(!strcmp(glob_p->rulfpath, ""))
			glob_p->rulfpath = NULL;
	} else {
		glob_p->rulfpath = NULL;
	}

	if(optind+3 < argc) {
		glob_p->destdir    = argv[optind+3];
		glob_p->destdirlen = strlen(glob_p->destdir);
	} else {
		glob_p->destdir    = NULL;
		glob_p->destdirlen = 0;
	}
*/

	return 0;
}

char *configs_parse_str[1<<10] = {0};

void gkf_parse(glob_t *glob_p, GKeyFile *gkf) {
	const struct option *lo_ptr = long_glob;
	while(lo_ptr->name != NULL) {
		gchar *value = g_key_file_get_value(gkf, glob_p->config_block, lo_ptr->name, NULL);
		if(value != NULL) {
			unsigned char val_char = lo_ptr->val&0xff;

			if(configs_parse_str[val_char])
				free(configs_parse_str[val_char]);

			configs_parse_str[val_char] = value;
			int ret = parse_parameter(glob_p, lo_ptr->val, value, PS_CONFIG);
			if(ret) exit(ret);
		}
		lo_ptr++;
	}

	return;
}

int configs_parse(glob_t *glob_p) {
	GKeyFile *gkf;

	gkf = g_key_file_new();

	if (glob_p->config_path) {
		GError *g_error = NULL;

		if (!strcmp(glob_p->config_path, "/NULL/")) {
			debug(2, "Empty path to config file. Don't read any of config files.");
			return 0;
		}

		debug(1, "Trying config-file \"%s\"", glob_p->config_path);
		if (!g_key_file_load_from_file(gkf, glob_p->config_path, G_KEY_FILE_NONE, &g_error)) {
			error("Cannot open/parse file \"%s\" (g_error #%u.%u: %s)", glob_p->config_path, g_error->domain, g_error->code, g_error->message);
			g_key_file_free(gkf);
			return -1;
		} else
			gkf_parse(glob_p, gkf);

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

			debug(1, "Trying config-file \"%s\"", config_path_real);
			if(!g_key_file_load_from_file(gkf, config_path_real, G_KEY_FILE_NONE, NULL)) {
				debug(1, "Cannot open/parse file \"%s\"", config_path_real);
				config_path_p++;
				continue;
			}

			gkf_parse(glob_p, gkf);

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
	debug(3, "<%s>.", expr);
#ifdef VERYPARANOID
	if(rule_p->mask == RA_NONE) {
		error("Received a rule with rule_p->mask == 0x00. Exit.");
		return EINVAL;
	}
#endif

	char buf[BUFSIZ];
	int ret = 0;
	if(rule_p->num >= MAXRULES) {
		error("Too many rules (%i >= %i).", rule_p->num, MAXRULES);
		return ENOMEM;
	}
	if((ret = regcomp(&rule_p->expr, expr, REG_EXTENDED | REG_NOSUB))) {
		regerror(ret, &rule_p->expr, buf, BUFSIZ);
		error("Invalid regexp pattern <%s>: %s (regex-errno: %i).", expr, buf, ret);
		return ret;
	}

	return ret;
}

int parse_rules_fromfile(glob_t *glob_p) {
	int ret = 0;
	char *rulfpath = glob_p->rulfpath;
	rule_t *rules  = glob_p->rules;

	char *line_buf=NULL;
	FILE *f = fopen(rulfpath, "r");
	
	if(f == NULL) {
		rules->mask   = RA_NONE;		// Terminator. End of rules' chain.
		rules->perm   = DEFAULT_RULES_PERM;
		error("Cannot open \"%s\" for reading.", rulfpath);
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
					error("Wrong rule action <%c>.", *line);
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
						(glob_p->flags[MODE] == MODE_RSYNCDIRECT) ||
						(glob_p->flags[MODE] == MODE_RSYNCSHELL)  ||
						(glob_p->flags[MODE] == MODE_RSYNCSO)
					) {
						error("Warning: Used \"w\" rule in \"--rsync\" case."
							" This may cause unexpected problems.");
					}
					rule->objtype = S_IFDIR;
					rule->mask    = RA_WALK;
					break;
				default:
					error("Warning: Cannot parse the rule <%s>", &line[-1]);
					i--;	// Canceling new rule
					continue;
			}


			line++;
			linelen--;

			// Parsing the rest part of the line

			debug(1, "Rule #%i <%c> <%c> pattern <%s> (length: %i).", rule->num, line[-2], line[-1], line, linelen);
			if((ret=rule_complete(rule, line)))
				goto l_parse_rules_fromfile_end;

			// Post-processing:

			line--;
			linelen++;

			if(*line != 'w') {
				// processing --auto-add-rules-w
				if(glob_p->flags[AUTORULESW] && (sign == RS_PERMIT)) {
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

//						debug(3, "Don't adding w-rule for \"%s\" due to [*d]-rule for \"%s\"",
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

								debug(1, "Rule #%i <+> <w> pattern <%s> (length: %i) [auto].", 
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

	debug(3, "Adding tail-rule #%u (effective #%u).", -1, i);

	rules[i].mask   = RA_NONE;		// Terminator. End of rules' chain.
	rules[i].perm   = DEFAULT_RULES_PERM;

	g_hash_table_destroy(autowrules_ht);
#ifdef _DEBUG
	debug(3, "Total (p == %p):", rules);
	i=0;
	do {
		debug(4, "\t%i\t%i\t%p/%p", i, rules[i].objtype, (void *)(long)rules[i].perm, (void *)(long)rules[i].mask);
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
			error("Cannot fork().");
			return(errno);
		case 0:
			setsid();
			break;
		default:
			debug(1, "fork()-ed, pid is %i.", pid);
			errno=0;
			exit(0);
	}
	return 0;
}

int main_cleanup(glob_t *glob_p) {
	int i=0;
	while((i < MAXRULES) && (glob_p->rules[i].mask != RA_NONE))
		regfree(&glob_p->rules[i++].expr);

	debug(3, "%i %i %i %i", glob_p->watchdirsize, glob_p->watchdirwslashsize, glob_p->destdirsize, glob_p->destdirwslashsize);

	return 0;
}

int main_rehash(glob_t *glob_p) {
	debug(3, "main_rehash()");
	int ret=0;

	main_cleanup(glob_p);

	if(glob_p->rulfpath != NULL) {
		ret = parse_rules_fromfile(glob_p);
		if(ret)
			error("Got error from parse_rules_fromfile().");
	} else {
		glob_p->rules[0].perm = DEFAULT_RULES_PERM;
		glob_p->rules[0].mask = RA_NONE;		// Terminator. End of rules.
	}

	return ret;
}

int main_status_update(glob_t *glob_p, state_t state) {
	static state_t state_old = STATE_UNKNOWN;

	if(state == state_old) {
		debug(3, "main_status_update: State unchanged: %u == %u", state, state_old);
		return 0;
	}

#ifdef VERYPARANOID
	if(status_descr[state] == NULL) {
		error("status_descr[%u] == NULL.", state);
		return EINVAL;
	}
#endif

	setenv("CLSYNC_STATUS", status_descr[state], 1);

	if(glob_p->statusfile == NULL)
		return 0;

	FILE *f = fopen(glob_p->statusfile, "w");
	if(f == NULL) {
		error("Cannot open file \"%s\" for writing: %s (errno: %u).", 
			glob_p->statusfile);
		return errno;
	}

	debug(3, "Setting status to %i: %s.", state, status_descr[state]);
	state_old=state;

	int ret = 0;

	if(fprintf(f, "%s", status_descr[state]) <= 0) {	// TODO: check output length
		error("Cannot write to file \"%s\": %s (errno: %u).",
			glob_p->statusfile);
		ret = errno;
	}

	if(fclose(f)) {
		error("Cannot close file \"%s\": %s (errno: %u).", 
			glob_p->statusfile);
		ret = errno;
	}

	return ret;
}

int main(int argc, char *argv[]) {
	struct glob glob;
#ifdef CLUSTER_SUPPORT
	struct utsname utsname;
#endif
	memset(&glob, 0, sizeof(glob));

	int ret = 0, nret;
	glob.notifyengine 			 = DEFAULT_NOTIFYENGINE;
	glob.syncdelay 				 = DEFAULT_SYNCDELAY;
	glob._queues[QUEUE_NORMAL].collectdelay  = DEFAULT_COLLECTDELAY;
	glob._queues[QUEUE_BIGFILE].collectdelay = DEFAULT_BFILECOLLECTDELAY;
	glob._queues[QUEUE_INSTANT].collectdelay = COLLECTDELAY_INSTANT;
	glob.bfilethreshold			 = DEFAULT_BFILETHRESHOLD;
	glob.label				 = DEFAULT_LABEL;
	glob.rsyncinclimit			 = DEFAULT_RSYNCINCLUDELINESLIMIT;
	glob.synctimeout			 = DEFAULT_SYNCTIMEOUT;
#ifdef CLUSTER_SUPPORT
	glob.cluster_hash_dl_min		 = DEFAULT_CLUSTERHDLMIN;
	glob.cluster_hash_dl_max		 = DEFAULT_CLUSTERHDLMAX;
	glob.cluster_scan_dl_max		 = DEFAULT_CLUSTERSDLMAX;
#endif
	glob.config_block			 = DEFAULT_CONFIG_BLOCK;
	glob.retries				 = DEFAULT_RETRIES;
	glob.flags[VERBOSE]			 = DEFAULT_VERBOSE;

	error_init(&glob.flags[OUTPUT_METHOD], &glob.flags[QUIET], &glob.flags[VERBOSE], &glob.flags[DEBUG]);

	nret = arguments_parse(argc, argv, &glob);
	if(nret) ret = nret;

	if(!ret) {
		nret = configs_parse(&glob);
		if(nret) ret = nret;
	}

	debug(4, "debugging flags: %u %u %u %u", glob.flags[OUTPUT_METHOD], glob.flags[QUIET], glob.flags[VERBOSE], glob.flags[DEBUG]);

	main_status_update(&glob, STATE_STARTING);

	if(glob.socketpath != NULL) {
#ifndef ENABLE_SOCKET
		ret = EINVAL;
		error("clsync is compiled without control socket support, option \"--socket\" cannot be used.");
#endif
		if(glob.flags[SOCKETAUTH] == SOCKAUTH_UNSET)
			glob.flags[SOCKETAUTH] = SOCKAUTH_NULL;
	}

	if((glob.flags[SOCKETOWN]) && (glob.socketpath == NULL)) {
		ret = errno = EINVAL;
		error("\"--socket-own\" is useless without \"--socket\"");
	}

	if((glob.flags[SOCKETMOD]) && (glob.socketpath == NULL)) {
		ret = errno = EINVAL;
		error("\"--socket-mod\" is useless without \"--socket\"");
	}

	if((glob.flags[SOCKETAUTH]) && (glob.socketpath == NULL)) {
		ret = errno = EINVAL;
		error("\"--socket-auth\" is useless without \"--socket\"");
	}

#ifdef VERYPARANOID
	if((glob.retries != 1) && glob.flags[PTHREAD]) {
		ret = errno = EINVAL;
		error("\"--retries\" values should be equal to \"1\" for \"--pthread\" mode.");
	}
#endif

	if(glob.flags[STANDBYFILE] && (glob.flags[MODE] == MODE_SIMPLE)) {
		ret = errno = EINVAL;
		error("Sorry but option \"--standby-file\" cannot be used in mode \"simple\", yet.");
	}

	if(glob.flags[PTHREAD] && glob.flags[ONLYINITSYNC]) {
		ret = errno = EINVAL;
		error("Conflicting glob: \"--pthread\" and \"--only-initialsync\" cannot be used together.");
	}

	if(glob.flags[PTHREAD] && glob.flags[EXITONNOEVENTS]) {
		ret = errno = EINVAL;
		error("Conflicting glob: \"--pthread\" and \"--exit-on-no-events\" cannot be used together.");
	}
	if(glob.flags[PTHREAD] && glob.flags[MAXITERATIONS]) {
		ret = errno = EINVAL;
		error("Conflicting glob: \"--pthread\" and \"--max-iterations\" cannot be used together.");
	}
	if(glob.flags[SKIPINITSYNC] && glob.flags[EXITONNOEVENTS]) {
		ret = errno = EINVAL;
		error("Conflicting glob: \"--skip-initialsync\" and \"--exit-on-no-events\" cannot be used together.");
	}
	if(glob.flags[ONLYINITSYNC] && glob.flags[EXITONNOEVENTS]) {
		ret = errno = EINVAL;
		error("Conflicting glob: \"--only-initialsync\" and \"--exit-on-no-events\" cannot be used together.");
	}

	if(glob.flags[SKIPINITSYNC] && glob.flags[ONLYINITSYNC]) {
		ret = errno = EINVAL;
		error("Conflicting glob: \"--skip-initialsync\" and \"--only-initialsync\" cannot be used together.");
	}

	if(glob.flags[INITFULL] && glob.flags[SKIPINITSYNC]) {
		ret = errno = EINVAL;
		error("Conflicting glob: \"--full-initialsync\" and \"--skip-initialsync\" cannot be used together.");
	}

	if(glob.flags[EXCLUDEMOUNTPOINTS])
		glob.flags[ONEFILESYSTEM]=1;

	if(glob.flags[MODE] == MODE_UNSET) {
		ret = errno = EINVAL;
		error("\"--mode\" is not set.");
	}

	if(glob.watchdir == NULL) {
		ret = errno = EINVAL;
		error("\"--watchdir\" is not set.");
	}

	if(glob.handlerfpath == NULL) {
		ret = errno = EINVAL;
		error("\"--sync-handler\" path is not set.");
	}
/*
	if(glob.flags[SYNCHANDLERSO] && glob.flags[RSYNC]) {
		ret = EINVAL;
		ret = errno = EINVAL;
		error("Option \"--rsync\" cannot be used in conjunction with \"--synchandler-so-module\".");
	}
*/
//	if(glob.flags[SYNCHANDLERSO] && (glob.listoutdir != NULL))
//		error("Warning: Option \"--dir-lists\" has no effect conjunction with \"--synchandler-so-module\".");

//	if(glob.flags[SYNCHANDLERSO] && (glob.destdir != NULL))
//		error("Warning: Destination directory argument has no effect conjunction with \"--synchandler-so-module\".");

	if((glob.flags[MODE] == MODE_RSYNCDIRECT) && (glob.destdir == NULL)) {
		ret = errno = EINVAL;
		error("Mode \"rsyncdirect\" cannot be used without specifying \"destination directory\".");
	}

#ifdef CLUSTER_SUPPORT
	if((glob.flags[MODE] == MODE_RSYNCDIRECT ) && (glob.cluster_iface != NULL)) {
		ret = errno = EINVAL;
		error("Mode \"rsyncdirect\" cannot be used in conjunction with \"--cluster-iface\".");
	}

	if((glob.cluster_iface == NULL) && ((glob.cluster_mcastipaddr != NULL) || (glob.cluster_nodename != NULL) || (glob.cluster_timeout) || (glob.cluster_mcastipport))) {
		ret = errno = EINVAL;
		error("glob \"--cluster-ip\", \"--cluster-node-name\", \"--cluster_timeout\" and/or \"cluster_ipport\" cannot be used without \"--cluster-iface\".");
	}

	if(glob.cluster_hash_dl_min > glob.cluster_hash_dl_max) {
		ret = errno = EINVAL;
		error("\"--cluster-hash-dl-min\" cannot be greater than \"--cluster-hash-dl-max\".");
	}

	if(glob.cluster_hash_dl_max > glob.cluster_scan_dl_max) {
		ret = errno = EINVAL;
		error("\"--cluster-hash-dl-max\" cannot be greater than \"--cluster-scan-dl-max\".");
	}

	if(!glob.cluster_timeout)
		glob.cluster_timeout	    = DEFAULT_CLUSTERTIMEOUT;
	if(!glob.cluster_mcastipport)
		glob.cluster_mcastipport = DEFAULT_CLUSTERIPPORT;
	if(!glob.cluster_mcastipaddr)
		glob.cluster_mcastipaddr = DEFAULT_CLUSTERIPADDR;

	if(glob.cluster_iface != NULL) {
#ifndef _DEBUG
		ret = errno = EINVAL;
		error("Cluster subsystem is not implemented, yet. Sorry.");
#endif
		if(glob.cluster_nodename == NULL) {

			if(!uname(&utsname))
				glob.cluster_nodename = utsname.nodename;

			debug(1, "cluster node name is: %s", glob.cluster_nodename);
		}
		if(glob.cluster_nodename == NULL) {
			ret = errno = EINVAL;
			error("Option \"--cluster-iface\" is set, but \"--cluster-node-name\" is not set and cannot get the nodename with uname().");
		} else {
			glob.cluster_nodename_len = strlen(glob.cluster_nodename);
		}
	}
#endif // CLUSTER_SUPPORT

	{
		char *rwatchdir = realpath(glob.watchdir, NULL);
		if(rwatchdir == NULL) {
			error("Got error while realpath() on \"%s\" [#0].", glob.watchdir);
			ret = errno;
		}

		struct stat64 stat64={0};
		if(lstat64(glob.watchdir, &stat64)) {
			error("Cannot lstat64() on \"%s\"", glob.watchdir);
			if(!ret)
				ret = errno;
		} else {
			if(glob.flags[EXCLUDEMOUNTPOINTS])
				glob.st_dev = stat64.st_dev;
			if((stat64.st_mode & S_IFMT) == S_IFLNK) {
				// The proplems may be due to FTS_PHYSICAL option of ftp_open() in sync_initialsync_rsync_walk(),
				// so if the "watch dir" is just a symlink it doesn't walk recursivly. For example, in "-R" case
				// it disables filters, because exclude-list will be empty.
#ifdef VERYPARANOID
				error("Watch dir cannot be symlink, but \"%s\" is a symlink.", glob.watchdir);
				ret = EINVAL;
#else
				char *watchdir_resolved_part = alloca(PATH_MAX+1);
				ssize_t r = readlink(glob.watchdir, watchdir_resolved_part, PATH_MAX+1);
	
				if(r>=PATH_MAX) {	// TODO: check if it's possible
					ret = errno = EINVAL;
					error("Too long file path resolved from symbolic link \"%s\"", glob.watchdir);
				} else
				if(r<0) {
					error("Cannot resolve symbolic link \"%s\": readlink() error", glob.watchdir);
					ret = EINVAL;
				} else {
					char *watchdir_resolved;
#ifdef VERYPARANOID
					if(glob.watchdirsize)
						if(glob.watchdir != NULL)
							free(glob.watchdir);
#endif

					size_t watchdir_resolved_part_len = strlen(watchdir_resolved_part);
					glob.watchdirsize = watchdir_resolved_part_len+1;	// Not true for case of relative symlink
					if(*watchdir_resolved_part == '/') {
						// Absolute symlink
						watchdir_resolved = malloc(glob.watchdirsize);
						memcpy(watchdir_resolved, watchdir_resolved_part, glob.watchdirsize);
					} else {
						// Relative symlink :(
						char *rslash = strrchr(glob.watchdir, '/');

						char *watchdir_resolved_rel  = alloca(PATH_MAX+1);
						size_t watchdir_resolved_rel_len = rslash-glob.watchdir + 1;
						memcpy(watchdir_resolved_rel, glob.watchdir, watchdir_resolved_rel_len);
						memcpy(&watchdir_resolved_rel[watchdir_resolved_rel_len], watchdir_resolved_part, watchdir_resolved_part_len+1);

						watchdir_resolved = realpath(watchdir_resolved_rel, NULL);
					}

					
					debug(1, "Symlink resolved: watchdir \"%s\" -> \"%s\"", glob.watchdir, watchdir_resolved);
					glob.watchdir = watchdir_resolved;
				}
#endif
			}
		}

		if(!ret) {
			glob.watchdir     = rwatchdir;
			glob.watchdirlen  = strlen(glob.watchdir);
			glob.watchdirsize = glob.watchdirlen;

#ifdef VERYPARANOID
			if(glob.watchdirlen == 1) {
				ret = errno = EINVAL;
				error("Very-Paranoid: --watch-dir is supposed to be not \"/\".");
			}
#endif
		}

		if(!ret) {
			if(glob.watchdirlen == 1) {
				glob.watchdirwslash     = glob.watchdir;
				glob.watchdirwslashsize = 0;
				glob.watchdir_dirlevel  = 0;
			} else {
				size_t size = glob.watchdirlen + 2;
				char *newwatchdir = xmalloc(size);
				memcpy( newwatchdir, glob.watchdir, glob.watchdirlen);
				glob.watchdirwslash     = newwatchdir;
				glob.watchdirwslashsize = size;
				memcpy(&glob.watchdirwslash[glob.watchdirlen], "/", 2);

				glob.watchdir_dirlevel  = fileutils_calcdirlevel(glob.watchdirwslash);
			}
		}
	}

	if(glob.destdir != NULL) {
		char *rdestdir = realpath(glob.destdir, NULL);
		if(rdestdir == NULL) {
			error("Got error while realpath() on \"%s\" [#1].", glob.destdir);
			ret = errno;
		}

		if(!ret) {
			glob.destdir     = rdestdir;
			glob.destdirlen  = strlen(glob.destdir);
			glob.destdirsize = glob.destdirlen;

			if(glob.destdirlen == 1) {
				ret = errno = EINVAL;
				error("destdir is supposed to be not \"/\".");
			}
		}

		if(!ret) {
			size_t size = glob.destdirlen  + 2;
			char *newdestdir  = xmalloc(size);
			memcpy( newdestdir,  glob.destdir,  glob.destdirlen);
			glob.destdirwslash     = newdestdir;
			glob.destdirwslashsize = size;
			memcpy(&glob.destdirwslash[glob.destdirlen], "/", 2);
		}
	}

	debug(1, "%s [%s] (%p) -> %s [%s]", glob.watchdir, glob.watchdirwslash, glob.watchdirwslash, glob.destdir?glob.destdir:"", glob.destdirwslash?glob.destdirwslash:"");

	if(
		(
			(glob.flags[MODE]==MODE_RSYNCDIRECT) || 
			(glob.flags[MODE]==MODE_RSYNCSHELL)  ||
			(glob.flags[MODE]==MODE_RSYNCSO)
		) && (glob.listoutdir == NULL)
	) {
		ret = errno = EINVAL;
		error("Modes \"rsyncdirect\", \"rsyncshell\" and \"rsyncso\" cannot be used without \"--lists-dir\".");
	}

	if(
		glob.flags[RSYNCPREFERINCLUDE] && 
		!(
			glob.flags[MODE] == MODE_RSYNCDIRECT ||
			glob.flags[MODE] == MODE_RSYNCSHELL  ||
			glob.flags[MODE] == MODE_RSYNCSO
		)
	)
		warning("Option \"--rsyncpreferinclude\" is useless if mode is not \"rsyncdirect\", \"rsyncshell\" or \"rsyncso\".");

	if(
		(
			glob.flags[MODE] == MODE_RSYNCDIRECT ||
			glob.flags[MODE] == MODE_RSYNCSHELL  ||
			glob.flags[MODE] == MODE_RSYNCSO
		)
		&& glob.flags[AUTORULESW]
	)
		warning("Option \"--auto-add-rules-w\" in modes \"rsyncdirect\", \"rsyncshell\" and \"rsyncso\" may cause unexpected problems.");

	if(glob.listoutdir != NULL) {
		struct stat st={0};
		errno = 0;
		if(stat(glob.listoutdir, &st)) {
			if(errno == ENOENT) {
				warning("Directory \"%s\" doesn't exist. Creating it.", glob.listoutdir);
				errno = 0;
				if(mkdir(glob.listoutdir, S_IRWXU)) {
					error("Cannot create directory \"%s\".", glob.listoutdir);
					ret = errno;
				}
			} else {
				error("Got error while stat() on \"%s\".", glob.listoutdir);
				ret = errno;
			}
		}
		if(!errno)
			if(st.st_mode & (S_IRWXG|S_IRWXO)) {
#ifdef PARANOID
				ret = errno = EACCES;
				error("Insecure: Others have access to directory \"%s\". Exit.", glob.listoutdir);
#else
				warning("Insecure: Others have access to directory \"%s\".", glob.listoutdir);
#endif
			}
	}

/*
	if(glob.flags[HAVERECURSIVESYNC] && (glob.listoutdir == NULL)) {
		error("Option \"--dir-lists\" should be set to use option \"--have-recursive-sync\".");
		ret = EINVAL;
	}
*/

	if(
		glob.flags[HAVERECURSIVESYNC] &&
		(
			glob.flags[MODE] == MODE_RSYNCDIRECT ||
			glob.flags[MODE] == MODE_RSYNCSHELL  ||
			glob.flags[MODE] == MODE_RSYNCSO
		)
	) {
		ret = errno = EINVAL;
		error("Option \"--have-recursive-sync\" with nodes \"rsyncdirect\", \"rsyncshell\" and \"rsyncso\" are incompatible.");
	}

	if(glob.flags[SYNCLISTSIMPLIFY] && (glob.listoutdir == NULL)) {
		ret = errno = EINVAL;
		error("Option \"--dir-lists\" should be set to use option \"--synclist-simplify\".");
	}

	if(
		glob.flags[SYNCLISTSIMPLIFY] && 
		(
			glob.flags[MODE] == MODE_RSYNCDIRECT ||
			glob.flags[MODE] == MODE_RSYNCSHELL  ||
			glob.flags[MODE] == MODE_RSYNCSO
		)
	) {
		ret = errno = EINVAL;
		error("Option \"--synclist-simplify\" with nodes \"rsyncdirect\" and \"rsyncshell\" are incompatible.");
	}

#ifdef FANOTIFY_SUPPORT
	if(glob.notifyengine != NE_INOTIFY) {
		warning("fanotify is not supported, now!");
	}
#endif

	if(glob.flags[EXITHOOK]) {
#ifdef VERYPARANOID
		if(glob.exithookfile == NULL) {
			ret = errno = EINVAL;
			error("glob.exithookfile == NULL");
		} else 
#endif
		{
			if(access(glob.exithookfile, X_OK) == -1) {
				error("\"%s\" is not executable.", glob.exithookfile);
				if(!ret)
					ret = errno;
			}
		}
	}

	if(access(glob.handlerfpath, X_OK) == -1) {
		error("\"%s\" is not executable.", glob.handlerfpath);
		if(!ret)
			ret = errno;
	}

	nret=main_rehash(&glob);
	if(nret)
		ret = nret;

	if(glob.flags[BACKGROUND]) {
		nret = becomedaemon();
		if(nret)
			ret = nret;
	}

#ifdef HAVE_CAPABILITIES
	if(glob.flags[CAP_PRESERVE_FILEACCESS]) {
		// Doesn't work, yet :(
		//
		// Error: Cannot inotify_add_watch() on "/home/xaionaro/clsync/examples/testdir/from": Permission denied (errno: 13).

		debug(1, "Preserving access to files with using linux capabilites");

		struct __user_cap_header_struct	cap_hdr = {0};
		struct __user_cap_data_struct	cap_dat = {0};

		cap_hdr.version = _LINUX_CAPABILITY_VERSION;
		if(capget(&cap_hdr, &cap_dat) < 0) {
			error("main() cannot get capabilites with capget()");
			ret = errno;

			goto preserve_fileaccess_end;
		}

		// From "man 7 capabilities":
		// CAP_DAC_OVERRIDE    - Bypass file read, write, and execute permission checks. 
		// CAP_DAC_READ_SEARCH - Bypass file read permission checks and directory read and execute permission checks.

		cap_dat.effective    =  (CAP_TO_MASK(CAP_DAC_OVERRIDE)|CAP_TO_MASK(CAP_DAC_READ_SEARCH)|CAP_TO_MASK(CAP_FOWNER)|CAP_TO_MASK(CAP_SYS_ADMIN)|CAP_TO_MASK(CAP_SETUID));
		cap_dat.permitted    =  (CAP_TO_MASK(CAP_DAC_OVERRIDE)|CAP_TO_MASK(CAP_DAC_READ_SEARCH)|CAP_TO_MASK(CAP_FOWNER)|CAP_TO_MASK(CAP_SYS_ADMIN)|CAP_TO_MASK(CAP_SETUID));
		cap_dat.inheritable  = 0;

		debug(3, "cap.eff == %p; cap.prm == %p.",
			(void *)(long)cap_dat.effective, (void *)(long)cap_dat.permitted);

		if(capset(&cap_hdr, &cap_dat) < 0) {
			error("Cannot set capabilities with capset().");
			ret = errno;

			goto preserve_fileaccess_end;
		}

		// Tell kernel not clear capabilities when dropping root 
		if(prctl(PR_SET_KEEPCAPS, 1) < 0) {
			error("Cannot prctl(PR_SET_KEEPCAPS, 1) to preserve capabilities");
			ret = errno;

			goto preserve_fileaccess_end;
		}
	}
preserve_fileaccess_end:
#endif

	if(glob.flags[UID]) {
		if(setuid(glob.uid)) {
			error("Cannot setuid(%u)", glob.uid);
			ret = errno;
		}
	}

	if(glob.flags[GID]) {
		if(setuid(glob.gid)) {
			error("Cannot setgid(%u)", glob.gid);
			ret = errno;
		}
	}

	if(glob.pidfile != NULL) {
		pid_t pid = getpid();
		FILE *pidfile = fopen(glob.pidfile, "w");
		if(pidfile == NULL) {
			error("Cannot open file \"%s\" to write a pid there",
				glob.pidfile);
			ret = errno;
		} else {
			if(fprintf(pidfile, "%u", pid) < 0) {
				error("Cannot write pid into file \"%s\"",
					glob.pidfile);
				ret = errno;
			}
			fclose(pidfile);
		}
	}

	debug(3, "Current errno is %i.", ret);

	// == RUNNING ==
	if(ret == 0)
		ret = sync_run(&glob);
	// == RUNNING ==

	if(glob.pidfile != NULL) {
		if(unlink(glob.pidfile)) {
			error("Cannot unlink pidfile \"%s\"",
				glob.pidfile);
			ret = errno;
		}
	}

	if(glob.statusfile != NULL) {
		if(unlink(glob.statusfile)) {
			error("Cannot unlink status file \"%s\"",
				glob.statusfile);
			ret = errno;
		}
	}

	main_cleanup(&glob);

	if(glob.watchdirsize)
		free(glob.watchdir);

	if(glob.watchdirwslashsize)
		free(glob.watchdirwslash);

	if(glob.destdirsize)
		free(glob.destdir);

	if(glob.destdirwslashsize)
		free(glob.destdirwslash);

	configs_cleanup();
	debug(1, "finished, exitcode: %i: %s.", ret, strerror(ret));
	return ret;
}


