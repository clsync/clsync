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


#include "common.h"

#ifdef CAPABILITIES_SUPPORT
#	include <sys/capability.h>	// for capset()/capget() for --preserve-file-access
#	include <sys/prctl.h>		// for prctl() for --preserve-fil-access
#endif

#include "port-hacks.h"

#include <pwd.h>	// getpwnam()
#include <grp.h>	// getgrnam()

#ifdef GETMNTENT_SUPPORT
#	include <mntent.h>	// getmntent()
#	include <sched.h>	// unshare()
#	include <sys/mount.h>	// umount2()
#endif

#include "error.h"
#include "stringex.h"
#include "sync.h"
#include "malloc.h"
#include "cluster.h"
#include "fileutils.h"
#include "socket.h"

//#include "revision.h"

static const struct option long_options[] =
{
	{"watch-dir",		required_argument,	NULL,	WATCHDIR},
	{"sync-handler",	required_argument,	NULL,	SYNCHANDLER},
	{"--",			required_argument,	NULL,	SYNCHANDLERARGS0},
	{"---",			required_argument,	NULL,	SYNCHANDLERARGS1},
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
	{"config-block-inherits",required_argument,	NULL,	CONFIGBLOCKINHERITS},
	{"custom-signals",	required_argument,	NULL,	CUSTOMSIGNALS},
	{"pid-file",		required_argument,	NULL,	PIDFILE},
	{"uid",			required_argument,	NULL,	UID},
	{"gid",			required_argument,	NULL,	GID},
	{"chroot",		required_argument,	NULL,	CHROOT},
#ifdef GETMNTENT_SUPPORT
	{"mountpoints",		optional_argument,	NULL,	MOUNTPOINTS},
#endif
#ifdef CAPABILITIES_SUPPORT
	{"preserve-file-access",optional_argument,	NULL,	CAP_PRESERVE_FILEACCESS},
#endif
	{"threading",		required_argument,	NULL,	THREADING},
	{"retries",		optional_argument,	NULL,	RETRIES},
	{"ignore-failures",	optional_argument,	NULL,	IGNOREFAILURES},
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
	{"pre-exit-hook",	required_argument,	NULL,	PREEXITHOOK},
	{"verbose",		optional_argument,	NULL,	VERBOSE},
	{"debug",		optional_argument,	NULL,	DEBUG},
	{"dump-dir",		required_argument,	NULL,	DUMPDIR},
	{"quiet",		optional_argument,	NULL,	QUIET},
	{"monitor",		required_argument,	NULL,	MONITOR},
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

static char *const threading_modes[] = {
	[PM_OFF]		= "off",
	[PM_SAFE]		= "safe",
	[PM_FULL]		= "full",
	NULL
};

static char *const notify_engines[] = {
	[NE_UNDEFINED]		= "",
	[NE_INOTIFY]		= "inotify",
	[NE_KQUEUE]		= "kqueue",
	[NE_FANOTIFY]		= "fanotify",
	[NE_BSM]		= "bsm",
	[NE_DTRACEPIPE]		= "dtracepipe",
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
	[MODE_DIRECT]		= "direct",
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
	[STATE_THREAD_GC]	= "thread gc",
	[STATE_INITSYNC]	= "initsync",
	NULL
};

int syntax() {
	info("possible options:");
	int i=-1;
	while (long_options[++i].name != NULL) {
		switch (long_options[i].val) {
			case SYNCHANDLERARGS0:
			case SYNCHANDLERARGS1:
				continue;
		}
		if (long_options[i].val & OPTION_CONFIGONLY)
			continue;

		info("\t--%-24s%c%c%s", long_options[i].name, 
				long_options[i].val & OPTION_LONGOPTONLY ? ' ' : '-', 
				long_options[i].val & OPTION_LONGOPTONLY ? ' ' : long_options[i].val, 
			(long_options[i].has_arg == required_argument ? " argument" : ""));
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

/**
 * @brief 			Gets raw (string) an option value by an option name
 * 
 * @param[in]	_ctx_p		Context
 @ @param[in]	variable_name	The name of the option
 * 
 * @retval	char *		Pointer to newly allocated string, if successful
 * @retval	NULL		On error
 * 
 */
const char *parameter_get(const char *variable_name, void *_ctx_p) {
	const ctx_t *ctx_p = _ctx_p;
	const struct option *long_option_p = long_options;
	int param_id = -1;

	while (long_option_p->name != NULL) {
		if (!strcmp(long_option_p->name, variable_name)) {
			param_id = long_option_p->val;
			break;
		}

		long_option_p++;
	}

	if (param_id == -1) {
		errno = ENOENT;
		return NULL;
	}

	return ctx_p->flags_values_raw[param_id];
}

/**
 * @brief 			Gets raw (string) an option value by an option name and
 * 				updates ctx_p->synchandler_argf
 * 
 * @param[in]	_ctx_p		Context
 @ @param[in]	variable_name	The name of the option
 * 
 * @retval	char *		Pointer to newly allocated string, if successful
 * @retval	NULL		On error
 * 
 */
const char *parameter_get_wmacro(const char *variable_name, void *_ctx_p) {
	ctx_t *ctx_p = _ctx_p;
	static struct dosync_arg dosync_arg = {0};
	debug(9, "(\"%s\", %p)", variable_name, _ctx_p);

	if (*variable_name < 'A' || *variable_name > 'Z')
		return parameter_get(variable_name, _ctx_p);

	if (!strcmp(variable_name, "RSYNC-ARGS")) {
		ctx_p->synchandler_argf |= SHFL_RSYNC_ARGS;
		return NULL;
	}
	if (!strcmp(variable_name, "INCLUDE-LIST")) {
		ctx_p->synchandler_argf |= SHFL_INCLUDE_LIST;
		return NULL;
	}

	const char *r = sync_parameter_get(variable_name, &dosync_arg);

	if (r == dosync_arg.outf_path) {
		ctx_p->synchandler_argf |= SHFL_INCLUDE_LIST_PATH;
		return NULL;
	}

	if (r == dosync_arg.excf_path) {
		ctx_p->synchandler_argf |= SHFL_EXCLUDE_LIST_PATH;
		return NULL;
	}

	errno = ENOENT;
	return NULL;
}

/**
 * @brief 			Expands option values, e. g. "/var/log/clsync-%label%.pid" -> "/var/log/clsync-clone.pid"
 * 
 * @param[in]	ctx_p		Context
 * @param[in]	arg		An allocated string with unexpanded value. Will be free'd
 * @param[out]	macro_count_p	A pointer to count of found macro-s
 * @param[out]	expand_count_p	A pointer to count of expanded macro-s
 * @param[in]	parameter_get	A function to resolve macro-s
 * @param[in]	parameter_get_arg An argument to the function
 * 
 * @retval	char *		Pointer to newly allocated string, if successful
 * @retval	NULL		On error
 * 
 */
char *parameter_expand(
		ctx_t *ctx_p,
		char *arg,
		int exceptionflags,
		int *macro_count_p,
		int *expand_count_p,
		const char *(*parameter_get)(const char *variable_name, void *arg),
		void *parameter_get_arg
) {
	debug(9, "(ctx_p, \"%s\" [%p], ...)", arg, arg);
	char *ret = NULL;
	size_t ret_size = 0, ret_len = 0;

#ifdef PARANOID
	if (arg == NULL) {
		errno = EINVAL;
		return NULL;
	}
#endif

	if (macro_count_p != NULL)
		*macro_count_p  = 0;
	if (expand_count_p != NULL)
		*expand_count_p = 0;

	char *ptr = &arg[-1];
	while (1) {
		ptr++;

		switch (*ptr) {
			case 0:
				if (ret == NULL) {
					debug(3, "Expanding value \"%s\" to \"%s\" (case #1)", arg, arg);
					return arg;
				}
				ret[ret_len] = 0;
				debug(3, "Expanding value \"%s\" to \"%s\" (case #0)", arg, ret);
				free(arg);
				return ret;
			case '%': {
				if (ptr[1] == '%') {
					ret[ret_len++] = *(ptr++);
					break;
				}

				char nest_searching = 1;
				char *ptr_nest = ptr;
				while (nest_searching) {
					ptr_nest++;

					switch (*ptr_nest) {
						case 0:
							ret[ret_len] = 0;
							if (!(exceptionflags&1))
								warning("Unexpected end of macro-substitution \"%s\" in value \"%s\"; result value is \"%s\"", ptr, arg, ret);
							free(arg);
							return ret;
						case '%': {
							char       *variable_name;
							const char *variable_value;
							size_t      variable_value_len;

							if (macro_count_p != NULL)
								(*macro_count_p)++;

							nest_searching = 0;
							if (ptr[1] >= 'A' && ptr[1] <= 'Z' && (exceptionflags&4)) {	// Lazy substitution, preserving the value
								variable_value     =  ptr;
								variable_value_len = (ptr_nest - ptr + 1);
								*ptr_nest = 0;
								variable_name  = &ptr[1];
								parameter_get(variable_name, parameter_get_arg);
								*ptr_nest = '%';
							} else {							// Substituting
								*ptr_nest = 0;
								variable_name  = &ptr[1];
								variable_value = parameter_get(variable_name, parameter_get_arg);
								if (variable_value == NULL) {
									if (!(exceptionflags&2))
										warning("Variable \"%s\" is not set (%s)", variable_name, strerror(errno));
									*ptr_nest = '%';
									errno = 0;
									break;
								}
								*ptr_nest = '%';
								variable_value_len = strlen(variable_value);

								if (expand_count_p != NULL)
									(*expand_count_p)++;
							}
							if (ret_len+variable_value_len+1 >= ret_size) {
								ret_size = ret_len+variable_value_len+1 + ALLOC_PORTION;
								ret      = xrealloc(ret, ret_size);
							}
							memcpy(&ret[ret_len], variable_value, variable_value_len);
							ret_len += variable_value_len;
							break;
						}
					}
				}
				ptr = ptr_nest;
				break;
			}
			default: {
				if (ret_len+2 >= ret_size) {
					ret_size += ALLOC_PORTION+2;
					ret       = xrealloc(ret, ret_size);
				}
				ret[ret_len++] = *ptr;
				break;
			}
		}
	}
	error("Unknown internal error");
	return arg;
}

static inline int synchandler_arg(char *arg, size_t arg_len, void *_ctx_p, enum shargsid shargsid) {
	ctx_t *ctx_p = _ctx_p;
	debug(9, "(\"%s\" [%p], %u, %p, %u)", arg, arg, arg_len, _ctx_p, shargsid);

	if (!strcmp(arg, "%RSYNC-ARGS%")) {
		char *args_e[] = RSYNC_ARGS_E, *args_i[] = RSYNC_ARGS_I, **args_p;
		free(arg);

		args_p = ctx_p->flags[RSYNCPREFERINCLUDE] ? args_i : args_e;

		while (*args_p != NULL) {
#ifdef VERYPARANOID
			if (!strcmp(*args_p, "%RSYNC-ARGS%")) {
				errno = EINVAL;
				critical("Infinite recursion detected");
			}
#endif
			if (synchandler_arg(strdup(*args_p), strlen(*args_p), ctx_p, shargsid))
				return errno;
			args_p++;
		}
		return 0;
	}

	if (ctx_p->synchandler_args[shargsid].c >= MAXARGUMENTS-2) {
		errno = E2BIG;
		error("There're too many sync-handler arguments "
			"(%u > "XTOSTR(MAXARGUMENTS-2)"; arg == \"%s\").",
			arg);
		return errno;
	}

#ifdef _DEBUG
	debug(14, "ctx_p->synchandler_args[%u].v[%u] = %p", shargsid, ctx_p->synchandler_args[shargsid].c, arg);
#endif
	ctx_p->synchandler_args[shargsid].v[ctx_p->synchandler_args[shargsid].c++] = arg;

	return 0;
}

static int synchandler_arg0(char *arg, size_t arg_len, void *_ctx_p) {
	return synchandler_arg(arg, arg_len, _ctx_p, SHARGS_PRIMARY);
}

static int synchandler_arg1(char *arg, size_t arg_len, void *_ctx_p) {
	return synchandler_arg(arg, arg_len, _ctx_p, SHARGS_INITIAL);
}

int parse_customsignals(ctx_t *ctx_p, char *arg) {
	char *ptr = arg, *start = arg;
	unsigned int signal;
	do {
		switch (*ptr) {
			case 0:
			case ',':
			case ':':
				signal = (unsigned int)atoi(start);
				if (signal == 0) {
					// flushing the setting
					int i = 0;
					while (i < 256) {
						if (ctx_p->customsignal[i]) {
							free(ctx_p->customsignal[i]);
							ctx_p->customsignal[i] = NULL;
						}
						i++;
					}
#ifdef _DEBUG
					fprintf(stderr, "Force-Debug: parse_parameter(): Reset custom signals.\n");
#endif
				} else {
					if (*ptr != ':') {
						char ch = *ptr;

						*ptr = 0;
							errno = EINVAL;
							error("Expected \":\" in \"%s\"", start);
						*ptr = ch;
						return errno;
					}

					{
						char ch, *end;
						ptr++;

						end = ptr;
						while (*end && *end != ',') end++;

						if (end == ptr) {
							errno = EINVAL;
							error("Empty config block name on signal \"%u\"", signal);
							return errno;
						}

						if (signal > MAXSIGNALNUM) {
							errno = EINVAL;
							error("Too high value of the signal: \"%u\" > "XTOSTR(MAXSIGNALNUM)"", signal);
							return errno;
						}

						ch = *end; *end = 0;
						ctx_p->customsignal[signal] = strdup(ptr);
						*end = ch;
#ifdef _DEBUG
						fprintf(stderr, "Force-Debug: parse_parameter(): Adding custom signal %u.\n", signal);
#endif
						ptr = end;
					}
				}
				start = ptr+1;
				break;
			case '0' ... '9':
				break;
			default:
				errno = EINVAL;
				error("Expected a digit, comma (or colon) but got \"%c\"", *ptr);
				return errno;
		}
	} while (*(ptr++));

	return 0;
}

int parse_parameter(ctx_t *ctx_p, uint16_t param_id, char *arg, paramsource_t paramsource) {
#ifdef _DEBUG
	fprintf(stderr, "Force-Debug: parse_parameter(): %i: %i = \"%s\"\n", paramsource, param_id, arg);
#endif
	switch (paramsource) {
		case PS_CONTROL:
		case PS_ARGUMENT:
			if (param_id & OPTION_CONFIGONLY) {
				syntax();
				return 0;
			}
			ctx_p->flags_set[param_id] = 1;
			break;
		case PS_CONFIG:
			if (ctx_p->flags_set[param_id])
				return 0;
			ctx_p->flags_set[param_id] = 1;
			break;
		case PS_DEFAULTS:
#ifdef VERYPARANOID
			if (ctx_p->flags_set[param_id]) {
				error("Parameter #%i is already set. No need in setting the default value.", param_id);
				return 0;
			}
#endif
			break;
		default:
			error("Unknown parameter #%i source (value \"%s\").", param_id, arg!=NULL ? arg : "");
			break;
	}

	if (arg != NULL) {
		if (param_id != SYNCHANDLERARGS0 && param_id != SYNCHANDLERARGS1)
			arg = parameter_expand(ctx_p, arg, 0, NULL, NULL, parameter_get, ctx_p);

		if (ctx_p->flags_values_raw[param_id] != NULL)
			free(ctx_p->flags_values_raw[param_id]);
		ctx_p->flags_values_raw[param_id] = arg;
	}

	switch(param_id) {
		case '?':
		case HELP:
			syntax();
			break;
		case CONFIGFILE:
			ctx_p->config_path    = *arg ? arg : NULL;
			break;
		case CONFIGBLOCK:
			ctx_p->config_block   = *arg ? arg : NULL;
			break;
		case CONFIGBLOCKINHERITS:
			break;
		case CUSTOMSIGNALS:
			if (paramsource == PS_CONTROL) {
				warning("Cannot change \"custom-signal\" in run-time. Ignoring.");
				return 0;
			}

			if (parse_customsignals(ctx_p, arg))
				return errno;
			break;
		case UID: {
			struct passwd *pwd = getpwnam(arg);
			ctx_p->flags[param_id]++;

			if (pwd == NULL) {
				ctx_p->uid = (unsigned int)atol(arg);
				break;
			}

			ctx_p->uid = pwd->pw_uid;
			break;
		}
		case GID: {
			struct group *grp = getgrnam(arg);
			ctx_p->flags[param_id]++;

			if (grp == NULL) {
				ctx_p->gid = (unsigned int)atol(arg);
				break;
			}

			ctx_p->gid = grp->gr_gid;
			break;
		}
		case CHROOT:
			if (paramsource == PS_CONTROL) {
				warning("Cannot change \"chroot\" in run-time. Ignoring.");
				return 0;
			}
			ctx_p->chroot_dir	= arg;
			break;
#ifdef GETMNTENT_SUPPORT
		case MOUNTPOINTS: {
			char *ptr;
			if (paramsource == PS_CONTROL) {
				warning("Cannot change \"mountpoints\" in run-time. Ignoring.");
				return 0;
			}

			while (ctx_p->mountpoints)
				free(ctx_p->mountpoint[--ctx_p->mountpoints]);

			ptr = arg;
			while (1) {
				char *end = strchr(ptr, ',');
				if (end == NULL)
					break;

				*end =  0;

				if (!*ptr) {
					while (ctx_p->mountpoints)
						free(ctx_p->mountpoint[--ctx_p->mountpoints]);
					ptr = &end[1];
					continue;
				}

				ctx_p->mountpoint[ctx_p->mountpoints++] = strdup(ptr);
				*end = ',';

				ptr = &end[1];
			}
		}
#endif
		case PIDFILE:
			if (paramsource == PS_CONTROL) {
				warning("Cannot change \"pid-file\" in run-time. Ignoring.");
				return 0;
			}
			ctx_p->pidfile		= arg;
			break;
		case RETRIES:
			ctx_p->retries		= (unsigned int)atol(arg);
			break;
		case THREADING: {
			char *value, *arg_orig = arg;

			if (!*arg) {
				ctx_p->flags_set[param_id] = 0;
				return 0;
			}

			threadingmode_t threadingmode = getsubopt(&arg, threading_modes, &value);
			if((int)threadingmode == -1) {
				errno = EINVAL;
				error("Invalid threading mode entered: \"%s\"", arg_orig);
				return EINVAL;
			}
			ctx_p->flags[THREADING] = threadingmode;

			break;
		}
		case OUTPUT_METHOD: {
			char *value, *arg_orig = arg;

			if (!*arg) {
				ctx_p->flags_set[param_id] = 0;
				return 0;
			}

			outputmethod_t outputmethod = getsubopt(&arg, output_methods, &value);
			if((int)outputmethod == -1) {
				errno = EINVAL;
				error("Invalid log writing destination entered: \"%s\"", arg_orig);
				return EINVAL;
			}
			ctx_p->flags[OUTPUT_METHOD] = outputmethod;

			break;
		}
#ifdef CLUSTER_SUPPORT
		case CLUSTERIFACE:
			ctx_p->cluster_iface		= arg;
			break;
		case CLUSTERMCASTIPADDR:
			ctx_p->cluster_mcastipaddr	= arg;
			break;
		case CLUSTERMCASTIPPORT:
			ctx_p->cluster_mcastipport	= (uint16_t)atoi(arg);
			break;
		case CLUSTERTIMEOUT:
			ctx_p->cluster_timeout		= (unsigned int)atol(arg);
			break;
		case CLUSTERNODENAME:
			ctx_p->cluster_nodename		= arg;
			break;
		case CLUSTERHDLMIN:
			ctx_p->cluster_hash_dl_min	= (uint16_t)atoi(arg);
			break;
		case CLUSTERHDLMAX:
			ctx_p->cluster_hash_dl_max	= (uint16_t)atoi(arg);
			break;
		case CLUSTERSDLMAX:
			ctx_p->cluster_scan_dl_max	= (uint16_t)atoi(arg);
			break;
#endif
		case OUTLISTSDIR:
			ctx_p->listoutdir		= arg;
			break;
		case LABEL:
			ctx_p->label			= arg;
			break;
		case STANDBYFILE:
			if(strlen(arg)) {
				ctx_p->standbyfile		= arg;
				ctx_p->flags[STANDBYFILE]	= 1;
			} else {
				ctx_p->standbyfile		= NULL;
				ctx_p->flags[STANDBYFILE]	= 0;
			}
			break;
		case SYNCDELAY: 
			ctx_p->syncdelay		= (unsigned int)atol(arg);
			break;
		case DELAY:
			ctx_p->_queues[QUEUE_NORMAL].collectdelay = (unsigned int)atol(arg);
			break;
		case BFILEDELAY:
			ctx_p->_queues[QUEUE_BIGFILE].collectdelay = (unsigned int)atol(arg);
			break;
		case BFILETHRESHOLD:
			ctx_p->bfilethreshold = (unsigned long)atol(arg);
			break;
		case MONITOR: {
			char *value, *arg_orig = arg;
			if (paramsource == PS_CONTROL) {
				warning("Cannot change \"monitor\" in run-time. Ignoring.");
				return 0;
			}

			if (!*arg) {
				ctx_p->flags_set[param_id] = 0;
				return 0;
			}

			notifyengine_t notifyengine = getsubopt(&arg, notify_engines, &value);
			if((int)notifyengine == -1) {
				errno = EINVAL;
				error("Invalid FS monitor subsystem entered: \"%s\"", arg_orig);
				return EINVAL;
			}

			switch (notifyengine) {
#ifdef FANOTIFY_SUPPORT
				case NE_FANOTIFY:
#endif
#ifdef INOTIFY_SUPPORT
				case NE_INOTIFY:
#endif
#ifdef KQUEUE_SUPPORT
				case NE_KQUEUE:
#endif
#ifdef BSM_SUPPORT
				case NE_BSM:
#endif
#ifdef DTRACEPIPE_SUPPORT
				case NE_DTRACEPIPE:
#endif
					break;
				default:
					error(PROGRAM" is compiled without %s subsystem support. Recompile with option \"--with-%s\" if you're planning to use it.", arg_orig, arg_orig);
					return EINVAL;
			}

			ctx_p->flags[MONITOR] = notifyengine;

			break;
		}
		case RSYNCINCLIMIT:
			ctx_p->rsyncinclimit = (unsigned int)atol(arg);
			break;
		case SYNCTIMEOUT:
			ctx_p->synctimeout   = (unsigned int)atol(arg);
			break;
		case PREEXITHOOK:
			if (strlen(arg)) {
				ctx_p->preexithookfile		= arg;
				ctx_p->flags[PREEXITHOOK]	= 1;
			} else {
				ctx_p->preexithookfile		= NULL;
				ctx_p->flags[PREEXITHOOK]	= 0;
			}
			break;
		case EXITHOOK:
			if (strlen(arg)) {
				ctx_p->exithookfile		= arg;
				ctx_p->flags[EXITHOOK]		= 1;
			} else {
				ctx_p->exithookfile		= NULL;
				ctx_p->flags[EXITHOOK]		= 0;
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
						if (exitcode == 0) {
							// flushing the setting
							int i = 0;
							while (i < 256)
								ctx_p->isignoredexitcode[i++] = 0;
#ifdef _DEBUG
							fprintf(stderr, "Force-Debug: parse_parameter(): Reset ignored exitcodes.\n");
#endif
						} else {
							ctx_p->isignoredexitcode[exitcode] = 1;
#ifdef _DEBUG
							fprintf(stderr, "Force-Debug: parse_parameter(): Adding ignored exitcode %u.\n", exitcode);
#endif
						}
						start = ptr+1;
						break;
					case '0' ... '9':
						break;
					default:
						errno = EINVAL;
						error("Expected a digit or comma but got \"%c\"", *ptr);
						return errno;
				}
			} while(*(ptr++));
			break;
		}
		case SHOW_VERSION:
			version();
			break;
		case WATCHDIR:
			if (paramsource == PS_CONTROL) {
				warning("Cannot change \"watch-dir\" in run-time. Ignoring.");
				return 0;
			}
			ctx_p->watchdir		= arg;
			break;
		case SYNCHANDLER:
			ctx_p->handlerfpath	= arg;
			break;
		case RULESFILE:
			ctx_p->rulfpath		= arg;
			break;
		case DESTDIR: {
			char *sep = strstr(arg, "://");

			if (ctx_p->destproto != NULL) {
				free(ctx_p->destproto);
				ctx_p->destproto = NULL;
			}

			if (sep != NULL) {
				char *ptr = arg;
				while (ptr < sep) {
					if (*ptr<'a' || *ptr>'z')
						break;
					ptr++;
				}
				if (ptr == sep) {
					size_t len = (ptr-arg)+1;
					ctx_p->destproto = xmalloc(len+1);
					memcpy(ctx_p->destproto, arg, len);
					ctx_p->destproto[len] = 0;
				}
			}

			ctx_p->destdir	 = arg;
			break;
		}
		case SOCKETPATH:
			ctx_p->socketpath	= arg;
			break;
		case SOCKETAUTH: {
			char *value;

			ctx_p->flags[SOCKETAUTH] = getsubopt(&arg, socketauth, &value);
			if (ctx_p->flags[SOCKETAUTH] == -1) {
				error("Wrong socket auth mech entered: \"%s\"", arg);
				return EINVAL;
			}
		}
		case SOCKETMOD:
			if (!sscanf(arg, "%o", (unsigned int *)&ctx_p->socketmod)) {
				error("Non octal value passed to --socket-mod: \"%s\"", arg);
				return EINVAL;
			}
			ctx_p->flags[param_id]++;
			break;
		case SOCKETOWN: {
			char *colon = strchr(arg, ':');
			uid_t uid;
			gid_t gid;

			if (colon == NULL) {
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

			ctx_p->socketuid = uid;
			ctx_p->socketgid = gid;
			ctx_p->flags[param_id]++;

			debug(2, "socket: uid == %u; gid == %u", uid, gid);

			break;
		}
		case STATUSFILE:
			ctx_p->statusfile	= arg;
			break;
		case DUMPDIR:
			ctx_p->dump_path	= arg;
			break;
		case MODE: {
			char *value;

			ctx_p->flags[MODE]  = getsubopt(&arg, modes, &value);
			if (ctx_p->flags[MODE] == -1) {
				error("Wrong mode name entered: \"%s\"", arg);
				return EINVAL;
			}
			break;
		}
		case SYNCHANDLERARGS0:
			str_splitargs(arg, synchandler_arg0, ctx_p);
			break;
		case SYNCHANDLERARGS1:
			str_splitargs(arg, synchandler_arg1, ctx_p);
			break;
		default:
			if (arg == NULL)
				ctx_p->flags[param_id]++;
			else
				ctx_p->flags[param_id] = atoi(arg);
#ifdef _DEBUG
			fprintf(stderr, "Force-Debug: flag %i is set to %i\n", param_id&0xff, ctx_p->flags[param_id]);
#endif
			break;
	}
	return 0;
}

int arguments_parse(int argc, char *argv[], struct ctx *ctx_p) {
	int c;
	int option_index = 0;

	// Generating "optstring" (man 3 getopt_long) with using information from struct array "long_options"
	char *optstring     = alloca((('z'-'a'+1)*3 + '9'-'0'+1)*3 + 1);
	char *optstring_ptr = optstring;

	const struct option *lo_ptr = long_options;
	while (lo_ptr->name != NULL) {
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
	while (1) {
		c = getopt_long(argc, argv, optstring, long_options, &option_index);
	
		if (c == -1) break;
		int ret = parse_parameter(ctx_p, c, optarg == NULL ? NULL : strdup(optarg), PS_ARGUMENT);
		if (ret) return ret;
	}

	if (optind < argc) {
		synchandler_args_t *args_p = &ctx_p->synchandler_args[SHARGS_PRIMARY];

		while (args_p->c)
			free(args_p->v[--args_p->c]);

		if ((optind+1 != argc) || (*argv[optind])) {	// If there's only "" after the "--", just reset "synchandler_argc" to "0", otherwise:
			do {
				if (synchandler_arg0(strdup(argv[optind++]), 0, ctx_p))
					return errno;
			} while (optind < argc);
		}
	}

	return 0;
}

void gkf_parse(ctx_t *ctx_p, GKeyFile *gkf, paramsource_t paramsource) {
	debug(9, "");
	char *config_block = (char *)ctx_p->config_block;
	do {
		const struct option *lo_ptr = long_options;

		if (config_block != ctx_p->config_block) {
			ctx_p->flags_values_raw[CONFIGBLOCKINHERITS] = NULL;
			ctx_p->flags_set[CONFIGBLOCKINHERITS] = 0;
		}
		while(lo_ptr->name != NULL) {
			gchar *value = g_key_file_get_value(gkf, config_block, lo_ptr->name, NULL);
			if(value != NULL) {
				int ret = parse_parameter(ctx_p, lo_ptr->val, value, paramsource);
				if(ret) exit(ret);
			}
			lo_ptr++;
		}

		if (config_block != ctx_p->config_block)
			free(config_block);

		config_block = ctx_p->flags_values_raw[CONFIGBLOCKINHERITS];

		if (config_block != NULL)
			debug(2, "Next block is: %s", config_block);
	} while (config_block != NULL);

	return;
}

int configs_parse(ctx_t *ctx_p, paramsource_t paramsource) {
	GKeyFile *gkf;

	gkf = g_key_file_new();

	if (ctx_p->config_path) {
		GError *g_error = NULL;

		if (!strcmp(ctx_p->config_path, "/NULL/")) {
			debug(2, "Empty path to config file. Don't read any of config files.");
			return 0;
		}

		debug(1, "Trying config-file \"%s\" (case #0)", ctx_p->config_path);
		if (!g_key_file_load_from_file(gkf, ctx_p->config_path, G_KEY_FILE_NONE, &g_error)) {
			error("Cannot open/parse file \"%s\" (g_error #%u.%u: %s)", ctx_p->config_path, g_error->domain, g_error->code, g_error->message);
			g_key_file_free(gkf);
			return -1;
		} else
			gkf_parse(ctx_p, gkf, paramsource);

	} else {
		char  *config_paths[] = CONFIG_PATHS;
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

			debug(1, "Trying config-file \"%s\" (case #1)", config_path_real);
			if(!g_key_file_load_from_file(gkf, config_path_real, G_KEY_FILE_NONE, NULL)) {
				debug(1, "Cannot open/parse file \"%s\"", config_path_real);
				config_path_p++;
				continue;
			}

			gkf_parse(ctx_p, gkf, paramsource);

			break;
		}
		free(config_path_real);
	}

	g_key_file_free(gkf);

	return 0;
}

int ctx_check(ctx_t *ctx_p) {
	int ret = 0;
#ifdef CLUSTER_SUPPORT
	struct utsname utsname;
#endif

	if (ctx_p->socketpath != NULL) {
#ifndef ENABLE_SOCKET
		ret = EINVAL;
		error("clsync is compiled without control socket support, option \"--socket\" cannot be used.");
#endif
		if (ctx_p->flags[SOCKETAUTH] == SOCKAUTH_UNSET)
			ctx_p->flags[SOCKETAUTH] = SOCKAUTH_NULL;
	}

	if ((ctx_p->flags[SOCKETOWN]) && (ctx_p->socketpath == NULL)) {
		ret = errno = EINVAL;
		error("\"--socket-own\" is useless without \"--socket\"");
	}

	if ((ctx_p->flags[SOCKETMOD]) && (ctx_p->socketpath == NULL)) {
		ret = errno = EINVAL;
		error("\"--socket-mod\" is useless without \"--socket\"");
	}

	if ((ctx_p->flags[SOCKETAUTH]) && (ctx_p->socketpath == NULL)) {
		ret = errno = EINVAL;
		error("\"--socket-auth\" is useless without \"--socket\"");
	}

#ifdef VERYPARANOID
	if ((ctx_p->retries != 1) && ctx_p->flags[THREADING]) {
		ret = errno = EINVAL;
		error("\"--retries\" values should be equal to \"1\" for this \"--threading\" value.");
	}
#endif

	if (ctx_p->flags[STANDBYFILE] && (ctx_p->flags[MODE] == MODE_SIMPLE)) {
		ret = errno = EINVAL;
		error("Sorry but option \"--standby-file\" cannot be used in mode \"simple\", yet.");
	}

	if (ctx_p->flags[THREADING] && ctx_p->flags[ONLYINITSYNC]) {
		ret = errno = EINVAL;
		error("Conflicting options: This value of \"--threading\" cannot be used in conjunction with \"--only-initialsync\".");
	}

	if (ctx_p->flags[THREADING] && ctx_p->flags[EXITONNOEVENTS]) {
		ret = errno = EINVAL;
		error("Conflicting options: This value of \"--threading\" cannot be used in conjunction with \"--exit-on-no-events\".");
	}
	if (ctx_p->flags[THREADING] && ctx_p->flags[MAXITERATIONS]) {
		ret = errno = EINVAL;
		error("Conflicting options: This value of \"--threading\" cannot be used in conjunction with \"--max-iterations\".");
	}
	if (ctx_p->flags[THREADING] && ctx_p->flags[PREEXITHOOK]) {
		ret = errno = EINVAL;
		error("Conflicting options: This value of \"--threading\" cannot be used in conjunction with \"--pre-exit-hook\".");
	}
	if (ctx_p->flags[SKIPINITSYNC] && ctx_p->flags[EXITONNOEVENTS]) {
		ret = errno = EINVAL;
		error("Conflicting options: \"--skip-initialsync\" and \"--exit-on-no-events\" cannot be used together.");
	}
	if (ctx_p->flags[ONLYINITSYNC] && ctx_p->flags[EXITONNOEVENTS]) {
		ret = errno = EINVAL;
		error("Conflicting options: \"--only-initialsync\" and \"--exit-on-no-events\" cannot be used together.");
	}

	if (ctx_p->flags[SKIPINITSYNC] && ctx_p->flags[ONLYINITSYNC]) {
		ret = errno = EINVAL;
		error("Conflicting options: \"--skip-initialsync\" and \"--only-initialsync\" cannot be used together.");
	}

	if (ctx_p->flags[INITFULL] && ctx_p->flags[SKIPINITSYNC]) {
		ret = errno = EINVAL;
		error("Conflicting options: \"--full-initialsync\" and \"--skip-initialsync\" cannot be used together.");
	}

	if (ctx_p->flags[EXCLUDEMOUNTPOINTS])
		ctx_p->flags[ONEFILESYSTEM]=1;

	if (ctx_p->flags[MODE] == MODE_UNSET) {
		ret = errno = EINVAL;
		error("\"--mode\" is not set.");
	}

	if (ctx_p->watchdir == NULL) {
		ret = errno = EINVAL;
		error("\"--watch-dir\" is not set.");
	}

	if (ctx_p->handlerfpath == NULL) {
		switch (ctx_p->flags[MODE]) {
			case MODE_DIRECT:
				ctx_p->handlerfpath = DEFAULT_CP_PATH;
				break;
			case MODE_RSYNCDIRECT:
				ctx_p->handlerfpath = DEFAULT_RSYNC_PATH;
				break;
			default:
				ret = errno = EINVAL;
				error("\"--sync-handler\" path is not set.");
		}
	}
/*
	if (ctx_p->flags[SYNCHANDLERSO] && ctx_p->flags[RSYNC]) {
		ret = EINVAL;
		ret = errno = EINVAL;
		error("Option \"--rsync\" cannot be used in conjunction with \"--synchandler-so-module\".");
	}
*/
//	if (ctx_p->flags[SYNCHANDLERSO] && (ctx_p->listoutdir != NULL))
//		error("Warning: Option \"--dir-lists\" has no effect conjunction with \"--synchandler-so-module\".");

//	if (ctx_p->flags[SYNCHANDLERSO] && (ctx_p->destdir != NULL))
//		error("Warning: Destination directory argument has no effect conjunction with \"--synchandler-so-module\".");

	if ((ctx_p->flags[MODE] == MODE_RSYNCDIRECT) && (ctx_p->destdir == NULL)) {
		ret = errno = EINVAL;
		error("Mode \"rsyncdirect\" cannot be used without specifying \"--dest-dir\".");
	}

#ifdef CLUSTER_SUPPORT
	if ((ctx_p->flags[MODE] == MODE_RSYNCDIRECT ) && (ctx_p->cluster_iface != NULL)) {
		ret = errno = EINVAL;
		error("Mode \"rsyncdirect\" cannot be used in conjunction with \"--cluster-iface\".");
	}

	if ((ctx_p->cluster_iface == NULL) && ((ctx_p->cluster_mcastipaddr != NULL) || (ctx_p->cluster_nodename != NULL) || (ctx_p->cluster_timeout) || (ctx_p->cluster_mcastipport))) {
		ret = errno = EINVAL;
		error("ctx \"--cluster-ip\", \"--cluster-node-name\", \"--cluster_timeout\" and/or \"cluster_ipport\" cannot be used without \"--cluster-iface\".");
	}

	if (ctx_p->cluster_hash_dl_min > ctx_p->cluster_hash_dl_max) {
		ret = errno = EINVAL;
		error("\"--cluster-hash-dl-min\" cannot be greater than \"--cluster-hash-dl-max\".");
	}

	if (ctx_p->cluster_hash_dl_max > ctx_p->cluster_scan_dl_max) {
		ret = errno = EINVAL;
		error("\"--cluster-hash-dl-max\" cannot be greater than \"--cluster-scan-dl-max\".");
	}

	if (!ctx_p->cluster_timeout)
		ctx_p->cluster_timeout	    = DEFAULT_CLUSTERTIMEOUT;
	if (!ctx_p->cluster_mcastipport)
		ctx_p->cluster_mcastipport = DEFAULT_CLUSTERIPPORT;
	if (!ctx_p->cluster_mcastipaddr)
		ctx_p->cluster_mcastipaddr = DEFAULT_CLUSTERIPADDR;

	if (ctx_p->cluster_iface != NULL) {
#ifndef _DEBUG
		ret = errno = EINVAL;
		error("Cluster subsystem is not implemented, yet. Sorry.");
#endif
		if (ctx_p->cluster_nodename == NULL) {

			if(!uname(&utsname))
				ctx_p->cluster_nodename = utsname.nodename;

			debug(1, "cluster node name is: %s", ctx_p->cluster_nodename);
		}
		if (ctx_p->cluster_nodename == NULL) {
			ret = errno = EINVAL;
			error("Option \"--cluster-iface\" is set, but \"--cluster-node-name\" is not set and cannot get the nodename with uname().");
		} else {
			ctx_p->cluster_nodename_len = strlen(ctx_p->cluster_nodename);
		}
	}
#endif // CLUSTER_SUPPORT

	if (ctx_p->watchdir != NULL) {
		char *rwatchdir = realpath(ctx_p->watchdir, NULL);
		if (rwatchdir == NULL) {
			error("Got error while realpath() on \"%s\" [#0].", ctx_p->watchdir);
			ret = errno;
		}

		stat64_t stat64={0};
		if (lstat64(ctx_p->watchdir, &stat64)) {
			error("Cannot lstat64() on \"%s\"", ctx_p->watchdir);
			if (!ret)
				ret = errno;
		} else {
			if (ctx_p->flags[EXCLUDEMOUNTPOINTS])
				ctx_p->st_dev = stat64.st_dev;
			if ((stat64.st_mode & S_IFMT) == S_IFLNK) {
				// The proplems may be due to FTS_PHYSICAL option of ftp_open() in sync_initialsync_rsync_walk(),
				// so if the "watch dir" is just a symlink it doesn't walk recursivly. For example, in "-R" case
				// it disables filters, because exclude-list will be empty.
#ifdef VERYPARANOID
				error("Watch dir cannot be symlink, but \"%s\" is a symlink.", ctx_p->watchdir);
				ret = EINVAL;
#else
				char *watchdir_resolved_part = xcalloc(1, PATH_MAX+2);
				ssize_t r = readlink(ctx_p->watchdir, watchdir_resolved_part, PATH_MAX+1);
	
				if (r>=PATH_MAX) {	// TODO: check if it's possible
					ret = errno = EINVAL;
					error("Too long file path resolved from symbolic link \"%s\"", ctx_p->watchdir);
				} else
				if (r<0) {
					error("Cannot resolve symbolic link \"%s\": readlink() error", ctx_p->watchdir);
					ret = EINVAL;
				} else {
					char *watchdir_resolved;
#ifdef VERYPARANOID
					if (ctx_p->watchdirsize)
						if (ctx_p->watchdir != NULL)
							free(ctx_p->watchdir);
#endif

					size_t watchdir_resolved_part_len = strlen(watchdir_resolved_part);
					ctx_p->watchdirsize = watchdir_resolved_part_len+1;	// Not true for case of relative symlink
					if (*watchdir_resolved_part == '/') {
						// Absolute symlink
						watchdir_resolved = malloc(ctx_p->watchdirsize);
						memcpy(watchdir_resolved, watchdir_resolved_part, ctx_p->watchdirsize);
					} else {
						// Relative symlink :(
						char *rslash = strrchr(ctx_p->watchdir, '/');

						char *watchdir_resolved_rel  = xmalloc(PATH_MAX+2);
						size_t watchdir_resolved_rel_len = rslash-ctx_p->watchdir + 1;
						memcpy(watchdir_resolved_rel, ctx_p->watchdir, watchdir_resolved_rel_len);
						memcpy(&watchdir_resolved_rel[watchdir_resolved_rel_len], watchdir_resolved_part, watchdir_resolved_part_len+1);

						watchdir_resolved = realpath(watchdir_resolved_rel, NULL);

						free(watchdir_resolved_rel);
					}

					
					debug(1, "Symlink resolved: watchdir \"%s\" -> \"%s\"", ctx_p->watchdir, watchdir_resolved);
					ctx_p->watchdir = watchdir_resolved;
				}
				free(watchdir_resolved_part);
#endif // VERYPARANOID else
			}
		}

		if (!ret) {
			ctx_p->watchdir     = rwatchdir;
			ctx_p->watchdirlen  = strlen(ctx_p->watchdir);
			ctx_p->watchdirsize = ctx_p->watchdirlen;

#ifdef VERYPARANOID
			if (ctx_p->watchdirlen == 1) {
				ret = errno = EINVAL;
				error("Very-Paranoid: --watch-dir is supposed to be not \"/\".");
			}
#endif
		}

		if (!ret) {
			if (ctx_p->watchdirlen == 1) {
				ctx_p->watchdirwslash     = ctx_p->watchdir;
				ctx_p->watchdirwslashsize = 0;
				ctx_p->watchdir_dirlevel  = 0;
			} else {
				size_t size = ctx_p->watchdirlen + 2;
				char *newwatchdir = xmalloc(size);
				memcpy( newwatchdir, ctx_p->watchdir, ctx_p->watchdirlen);
				ctx_p->watchdirwslash     = newwatchdir;
				ctx_p->watchdirwslashsize = size;
				memcpy(&ctx_p->watchdirwslash[ctx_p->watchdirlen], "/", 2);

				ctx_p->watchdir_dirlevel  = fileutils_calcdirlevel(ctx_p->watchdirwslash);
			}
		}
	}

	if ((ctx_p->destdir != NULL) && (ctx_p->destproto == NULL)) {	// "ctx_p->destproto == NULL" means "no protocol"/"local directory"
		char *rdestdir = realpath(ctx_p->destdir, NULL);
		if(rdestdir == NULL) {
			error("Got error while realpath() on \"%s\" [#1].", ctx_p->destdir);
			ret = errno;
		}

		if (!ret) {
			ctx_p->destdir     = rdestdir;
			ctx_p->destdirlen  = strlen(ctx_p->destdir);
			ctx_p->destdirsize = ctx_p->destdirlen;

			if(ctx_p->destdirlen == 1) {
				ret = errno = EINVAL;
				error("destdir is supposed to be not \"/\".");
			}
		}

		if (!ret) {
			size_t size = ctx_p->destdirlen  + 2;
			char *newdestdir  = xmalloc(size);
			memcpy( newdestdir,  ctx_p->destdir,  ctx_p->destdirlen);
			ctx_p->destdirwslash     = newdestdir;
			ctx_p->destdirwslashsize = size;
			memcpy(&ctx_p->destdirwslash[ctx_p->destdirlen], "/", 2);
		}
	} else
	if (ctx_p->destproto != NULL)
		ctx_p->destdirwslash = ctx_p->destdir;

	debug(1, "%s [%s] (%p) -> %s [%s]", ctx_p->watchdir, ctx_p->watchdirwslash, ctx_p->watchdirwslash, ctx_p->destdir?ctx_p->destdir:"", ctx_p->destdirwslash?ctx_p->destdirwslash:"");

	switch (ctx_p->flags[MODE]) {
		case MODE_RSYNCSO:
			ctx_p->synchandler_argf |= SHFL_EXCLUDE_LIST_PATH;
			ctx_p->synchandler_argf |= SHFL_INCLUDE_LIST_PATH;
			break;
	}

	if (
		ctx_p->flags[RSYNCPREFERINCLUDE] && 
		!(
			ctx_p->flags[MODE] == MODE_RSYNCDIRECT ||
			ctx_p->flags[MODE] == MODE_RSYNCSHELL  ||
			ctx_p->flags[MODE] == MODE_RSYNCSO
		)
	)
		warning("Option \"--rsyncpreferinclude\" is useless if mode is not \"rsyncdirect\", \"rsyncshell\" or \"rsyncso\".");

	if (
		(
			ctx_p->flags[MODE] == MODE_RSYNCDIRECT ||
			ctx_p->flags[MODE] == MODE_RSYNCSHELL  ||
			ctx_p->flags[MODE] == MODE_RSYNCSO
		)
		&& ctx_p->flags[AUTORULESW]
	)
		warning("Option \"--auto-add-rules-w\" in modes \"rsyncdirect\", \"rsyncshell\" and \"rsyncso\" may cause unexpected problems.");

/*
	if(ctx_p->flags[HAVERECURSIVESYNC] && (ctx_p->listoutdir == NULL)) {
		error("Option \"--dir-lists\" should be set to use option \"--have-recursive-sync\".");
		ret = EINVAL;
	}
*/

	if (
		ctx_p->flags[HAVERECURSIVESYNC] &&
		(
			ctx_p->flags[MODE] == MODE_RSYNCDIRECT ||
			ctx_p->flags[MODE] == MODE_RSYNCSHELL  ||
			ctx_p->flags[MODE] == MODE_RSYNCSO
		)
	) {
		ret = errno = EINVAL;
		error("Option \"--have-recursive-sync\" with nodes \"rsyncdirect\", \"rsyncshell\" and \"rsyncso\" are incompatible.");
	}

	if (ctx_p->flags[SYNCLISTSIMPLIFY] && (ctx_p->listoutdir == NULL)) {
		ret = errno = EINVAL;
		error("Option \"--dir-lists\" should be set to use option \"--synclist-simplify\".");
	}

	if (
		ctx_p->flags[SYNCLISTSIMPLIFY] && 
		(
			ctx_p->flags[MODE] == MODE_RSYNCDIRECT ||
			ctx_p->flags[MODE] == MODE_RSYNCSHELL  ||
			ctx_p->flags[MODE] == MODE_RSYNCSO
		)
	) {
		ret = errno = EINVAL;
		error("Option \"--synclist-simplify\" with nodes \"rsyncdirect\" and \"rsyncshell\" are incompatible.");
	}

#ifdef FANOTIFY_SUPPORT
	if (ctx_p->flags[MONITOR] == NE_FANOTIFY)
		critical("fanotify is not supported, now!");
	else
#endif
	switch (ctx_p->flags[MONITOR]) {
#ifdef INOTIFY_SUPPORT
		case NE_INOTIFY:
#endif
#ifdef FANOTIFY_SUPPORT
		case NE_FANOTIFY:
#endif
#ifdef KQUEUE_SUPPORT
		case NE_KQUEUE:
#endif
#ifdef BSM_SUPPORT
		case NE_BSM:
#endif
#ifdef DTRACEPIPE_SUPPORT
		case NE_DTRACEPIPE:
#endif
			break;
		default:
			ret = errno = EINVAL;
			error("Required one of the next options:"
#ifdef INOTIFY_SUPPORT
				" \"--monitor=inotify\""
#endif
#ifdef FANOTIFY_SUPPORT
				" \"--monitor=fanotify\""
#endif
#ifdef KQUEUE_SUPPORT
				" \"--monitor=kqueue\""
#endif
#ifdef BSM_SUPPORT
				" \"--monitor=bsm\""
#endif
#ifdef DTRACEPIPE_SUPPORT
				" \"--monitor=dtracepipe\""
#endif
			);
	}

	if (ctx_p->flags[EXITHOOK]) {
#ifdef VERYPARANOID
		if (ctx_p->exithookfile == NULL) {
			ret = errno = EINVAL;
			error("ctx_p->exithookfile == NULL");
		} else 
#endif
		{
			if (access(ctx_p->exithookfile, X_OK) == -1) {
				error("\"%s\" is not executable.", ctx_p->exithookfile);
				if (!ret)
					ret = errno;
			}
		}
	}

#if 0
	if (ctx_p->handlerfpath != NULL)
		if (access(ctx_p->handlerfpath, X_OK) == -1) {
			error("\"%s\" is not executable.", ctx_p->handlerfpath);
			if (!ret)
				ret = errno;
		}
#endif

	return ret;
}

int config_block_parse(ctx_t *ctx_p, const char *const config_block_name)
{
	int rc;
	debug(1, "(ctx_p, \"%s\")", config_block_name);

	ctx_p->config_block = config_block_name;
	rc = configs_parse(ctx_p, PS_CONTROL);

	if (!rc)
		rc = ctx_check(ctx_p);

	return errno = rc;
}

int ctx_set(ctx_t *ctx_p, const char *const parameter_name, const char *const parameter_value)
{
	int ret = ENOENT;
	const struct option *lo_ptr = long_options;

	while (lo_ptr->name != NULL) {
		if (!strcmp(lo_ptr->name, parameter_name)) {
			ret = parse_parameter(ctx_p, lo_ptr->val, strdup(parameter_value), PS_CONTROL);
			break;
		}
		lo_ptr++;
	}

	ret = ctx_check(ctx_p);
	if (ret)
		critical("Cannot continue with this setup");

	return ret;
}

void ctx_cleanup(ctx_t *ctx_p) {
	int i=0;
	debug(9, "");

	while (i < OPTION_FLAGS) {
		if (ctx_p->flags_values_raw[i] != NULL) {
			free(ctx_p->flags_values_raw[i]);
			ctx_p->flags_values_raw[i] = NULL;
		}
		i++;
	}

	{
		int n = 0;
		while (n < SHARGS_MAX) {
			int i = 0,  e = ctx_p->synchandler_args[n].c;
			while (i < e) {
#ifdef _DEBUG
				debug(14, "synchandler args: %u, %u: free(%p)", n, i, ctx_p->synchandler_args[n].v[i]);
#endif
				free(ctx_p->synchandler_args[n].v[i]);
				ctx_p->synchandler_args[n].v[i] = NULL;
				i++;
			}
			ctx_p->synchandler_args[n].c = 0;
			n++;
		}
	}

	return;
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

int parse_rules_fromfile(ctx_t *ctx_p) {
	int ret = 0;
	char *rulfpath = ctx_p->rulfpath;
	rule_t *rules  = ctx_p->rules;

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
						(ctx_p->flags[MODE] == MODE_RSYNCDIRECT) ||
						(ctx_p->flags[MODE] == MODE_RSYNCSHELL)  ||
						(ctx_p->flags[MODE] == MODE_RSYNCSO)
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

			debug(1, "Rule #%i <%c>[0x%02x 0x%02x] <%c>[0x%04x] pattern <%s> (length: %i).", rule->num, line[-2], rule->perm, rule->mask, line[-1], rule->objtype, line, linelen);
			if((ret=rule_complete(rule, line)))
				goto l_parse_rules_fromfile_end;

			// Post-processing:

			line--;
			linelen++;

			if(*line != 'w') {
				// processing --auto-add-rules-w
				if(ctx_p->flags[AUTORULESW] && (sign == RS_PERMIT)) {
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

int main_cleanup(ctx_t *ctx_p) {
	int i=0;
	while((i < MAXRULES) && (ctx_p->rules[i].mask != RA_NONE))
		regfree(&ctx_p->rules[i++].expr);

	debug(3, "%i %i %i %i", ctx_p->watchdirsize, ctx_p->watchdirwslashsize, ctx_p->destdirsize, ctx_p->destdirwslashsize);

	return 0;
}

int main_rehash(ctx_t *ctx_p) {
	debug(3, "");
	int ret=0;

	main_cleanup(ctx_p);

	if(ctx_p->rulfpath != NULL) {
		ret = parse_rules_fromfile(ctx_p);
		if(ret)
			error("Got error from parse_rules_fromfile().");
	} else {
		ctx_p->rules[0].perm = DEFAULT_RULES_PERM;
		ctx_p->rules[0].mask = RA_NONE;		// Terminator. End of rules.
	}

	return ret;
}

int main_status_update(ctx_t *ctx_p) {
	static state_t state_old = STATE_UNKNOWN;
	state_t        state     = ctx_p->state;

	debug(4, "%u", state);

	if(state == state_old) {
		debug(3, "State unchanged: %u == %u", state, state_old);
		return 0;
	}

#ifdef VERYPARANOID
	if(status_descr[state] == NULL) {
		error("status_descr[%u] == NULL.", state);
		return EINVAL;
	}
#endif

	setenv("CLSYNC_STATUS", status_descr[state], 1);

	if(ctx_p->statusfile == NULL)
		return 0;

	FILE *f = fopen(ctx_p->statusfile, "w");
	if(f == NULL) {
		error("Cannot open file \"%s\" for writing.", 
			ctx_p->statusfile);
		return errno;
	}

	debug(3, "Setting status to %i: %s.", state, status_descr[state]);
	state_old=state;

	int ret = 0;

	if(fprintf(f, "%s", status_descr[state]) <= 0) {	// TODO: check output length
		error("Cannot write to file \"%s\".",
			ctx_p->statusfile);
		ret = errno;
	}

	if(fclose(f)) {
		error("Cannot close file \"%s\".", 
			ctx_p->statusfile);
		ret = errno;
	}

	return ret;
}

int main(int argc, char *argv[]) {
	struct ctx *ctx_p = xcalloc(1, sizeof(*ctx_p));

	int ret = 0, nret, rm_listoutdir = 0;
	ctx_p->flags[MONITOR]			 = DEFAULT_NOTIFYENGINE;
	ctx_p->syncdelay 			 = DEFAULT_SYNCDELAY;
	ctx_p->_queues[QUEUE_NORMAL].collectdelay   = DEFAULT_COLLECTDELAY;
	ctx_p->_queues[QUEUE_BIGFILE].collectdelay  = DEFAULT_BFILECOLLECTDELAY;
	ctx_p->_queues[QUEUE_INSTANT].collectdelay  = COLLECTDELAY_INSTANT;
	ctx_p->_queues[QUEUE_LOCKWAIT].collectdelay = COLLECTDELAY_INSTANT;
	ctx_p->bfilethreshold			 = DEFAULT_BFILETHRESHOLD;
	ctx_p->label				 = DEFAULT_LABEL;
	ctx_p->rsyncinclimit			 = DEFAULT_RSYNCINCLUDELINESLIMIT;
	ctx_p->synctimeout			 = DEFAULT_SYNCTIMEOUT;
#ifdef CLUSTER_SUPPORT
	ctx_p->cluster_hash_dl_min		 = DEFAULT_CLUSTERHDLMIN;
	ctx_p->cluster_hash_dl_max		 = DEFAULT_CLUSTERHDLMAX;
	ctx_p->cluster_scan_dl_max		 = DEFAULT_CLUSTERSDLMAX;
#endif
	ctx_p->config_block			 = DEFAULT_CONFIG_BLOCK;
	ctx_p->retries				 = DEFAULT_RETRIES;
	ctx_p->flags[VERBOSE]			 = DEFAULT_VERBOSE;

	error_init(&ctx_p->flags[OUTPUT_METHOD], &ctx_p->flags[QUIET], &ctx_p->flags[VERBOSE], &ctx_p->flags[DEBUG]);

	nret = arguments_parse(argc, argv, ctx_p);
	if (nret) ret = nret;

	if (!ret) {
		nret = configs_parse(ctx_p, PS_CONFIG);
		if(nret) ret = nret;
	}

	if (ctx_p->dump_path == NULL) {
		ctx_p->dump_path = parameter_expand(ctx_p, strdup(DEFAULT_DUMPDIR), 2, NULL, NULL, parameter_get, ctx_p);
		ctx_p->flags_values_raw[DUMPDIR] = ctx_p->dump_path;
	}

	if (!ctx_p->synchandler_args[SHARGS_PRIMARY].c) {
		char *args_line0 = NULL, *args_line1 = NULL;
		switch (ctx_p->flags[MODE]) {
			case MODE_SIMPLE:
				args_line0 = DEFAULT_SYNCHANDLER_ARGS_SIMPLE;
				break;
			case MODE_DIRECT:
				args_line0 = DEFAULT_SYNCHANDLER_ARGS_DIRECT;
				break;
			case MODE_SHELL:
				args_line0 = DEFAULT_SYNCHANDLER_ARGS_SHELL_NR;
				args_line1 = DEFAULT_SYNCHANDLER_ARGS_SHELL_R;
				break;
			case MODE_RSYNCDIRECT:
				args_line0 = (ctx_p->flags[RSYNCPREFERINCLUDE]) ? DEFAULT_SYNCHANDLER_ARGS_RDIRECT_I : DEFAULT_SYNCHANDLER_ARGS_RDIRECT_E;
				break;
			case MODE_RSYNCSHELL:
				args_line0 = (ctx_p->flags[RSYNCPREFERINCLUDE]) ? DEFAULT_SYNCHANDLER_ARGS_RSHELL_I  : DEFAULT_SYNCHANDLER_ARGS_RSHELL_E;
				break;
		}

		if (args_line0 != NULL)
			parse_parameter(ctx_p, SYNCHANDLERARGS0, strdup(args_line0), PS_DEFAULTS);

		if (args_line1 != NULL)
			parse_parameter(ctx_p, SYNCHANDLERARGS1, strdup(args_line1), PS_DEFAULTS);
	}

	{
		int n = 0;
		while (n < SHARGS_MAX) {
			synchandler_args_t *args_p = &ctx_p->synchandler_args[n++];
			debug(9, "Custom arguments %u count: %u", n-1, args_p->c);
			int i = 0;
			while (i < args_p->c) {
				int macros_count, expanded;

				args_p->v[i] = parameter_expand(ctx_p, args_p->v[i], 4, &macros_count, &expanded, parameter_get_wmacro, ctx_p);

				debug(12, "args_p->v[%u] == \"%s\" (t: %u; e: %u)", i, args_p->v[i], macros_count, expanded);
				if (macros_count == expanded)
					args_p->isexpanded[i]++;
				i++;
			}
		}
	}

	debug(4, "debugging flags: %u %u %u %u", ctx_p->flags[OUTPUT_METHOD], ctx_p->flags[QUIET], ctx_p->flags[VERBOSE], ctx_p->flags[DEBUG]);

	ctx_p->state = STATE_STARTING;
	main_status_update(ctx_p);

	if (ctx_p->chroot_dir != NULL) {
		if (chroot(ctx_p->chroot_dir)) {
			error("Got error while chroot(\"%s\")", ctx_p->chroot_dir);
			ret = errno;
		}

		if (chdir(ctx_p->chroot_dir)) {
			error("Got error while chdir(\"%s\")", ctx_p->chroot_dir);
			ret = errno;
		}
	}

#ifdef GETMNTENT_SUPPORT
	if (ctx_p->mountpoints) {
		struct mntent *ent;
		FILE *f;

		// Detaching from current FS namespace
		unshare(CLONE_FS);

		// Scanning mountpoints
		f = setmntent("/proc/mounts", "r");
		if (f == NULL) {
			perror("setmntent");
			exit(1);
		}
		while (NULL != (ent = getmntent(f))) {
			int i;

			i=0;
			while (i < ctx_p->mountpoints) {
				if (!strcmp(ent->mnt_dir, ctx_p->mountpoint[i]))
					break;

				i++;
			}

			if (i >= ctx_p->mountpoints) {
				debug(1, "umount2(\"%s\", MNT_DETACH)", ent->mnt_dir);
				if (umount2(ent->mnt_dir, MNT_DETACH))
					warning("Cannot umount2(\"%s\", MNT_DETACH): %s", ent->mnt_dir, strerror(errno));
			}
		}
		endmntent(f);
	}
#endif

#ifdef CAPABILITIES_SUPPORT
	if (ctx_p->flags[CAP_PRESERVE_FILEACCESS]) {
		debug(1, "Preserving Linux capabilites");

		// Tell kernel not clear capabilities when dropping root 
		if (prctl(PR_SET_KEEPCAPS, 1) < 0) {
			error("Cannot prctl(PR_SET_KEEPCAPS, 1) to preserve capabilities");
			ret = errno;
		}
	}
#endif

	if (ctx_p->flags[GID]) {
		debug(3, "Dropping gid to %i", ctx_p->gid);
		if (setgid(ctx_p->gid)) {
			error("Cannot setgid(%u)", ctx_p->gid);
			ret = errno;
		}
	}

	if (ctx_p->flags[UID]) {
		debug(3, "Dropping uid to %i", ctx_p->uid);
		if (setuid(ctx_p->uid)) {
			error("Cannot setuid(%u)", ctx_p->uid);
			ret = errno;
		}
	}

#ifdef CAPABILITIES_SUPPORT
	if (ctx_p->flags[CAP_PRESERVE_FILEACCESS]) {
		// Doesn't work, yet :(
		//
		// Error: Cannot inotify_add_watch() on "/home/xaionaro/clsync/examples/testdir/from": Permission denied (errno: 13).
		debug(1, "Dropping all Linux capabilites but CAP_DAC_READ_SEARCH");

		struct __user_cap_header_struct	cap_hdr = {0};
		struct __user_cap_data_struct	cap_dat = {0};

		cap_hdr.version = _LINUX_CAPABILITY_VERSION;
		if (capget(&cap_hdr, &cap_dat) < 0) {
			error("Cannot get capabilites with capget()");
			ret = errno;

			goto preserve_fileaccess_end;
		}

		// From "man 7 capabilities":
		// CAP_DAC_OVERRIDE    - Bypass file read, write, and execute permission checks. 
		// CAP_DAC_READ_SEARCH - Bypass file read permission checks and directory read and execute permission checks.

		cap_dat.effective    = CAP_TO_MASK(CAP_DAC_READ_SEARCH);
		cap_dat.permitted    = cap_dat.effective;
		cap_dat.inheritable  = cap_dat.effective;

		debug(3, "cap.eff == 0x%04x; cap.prm == 0x%04x; cap.inh == 0x%04x.",
			cap_dat.effective, cap_dat.permitted, cap_dat.inheritable);

		if (capset(&cap_hdr, &cap_dat) < 0) {
			error("Cannot set capabilities with capset().");
			ret = errno;
		}
	}
preserve_fileaccess_end:
#endif

	ret = ctx_check(ctx_p);

	if (
		(ctx_p->listoutdir == NULL) && 
		(
			ctx_p->synchandler_argf & 
			(
				SHFL_INCLUDE_LIST_PATH |
				SHFL_EXCLUDE_LIST_PATH
			)
		)
	) {
		char *template = strdup(TMPDIR_TEMPLATE);

		ctx_p->listoutdir = mkdtemp(template);

		if (ctx_p->listoutdir == NULL) {
			ret = errno;
			error("Cannot create temporary dir for list files");
		} else
			rm_listoutdir = 2;
	}

	if (ctx_p->listoutdir != NULL) {
		struct stat st={0};
		errno = 0;
		if (stat(ctx_p->listoutdir, &st)) {
			if (errno == ENOENT) {
				warning("Directory \"%s\" doesn't exist. Creating it.", ctx_p->listoutdir);
				errno = 0;
				if (mkdir(ctx_p->listoutdir, S_IRWXU)) {
					error("Cannot create directory \"%s\".", ctx_p->listoutdir);
					ret = errno;
				} else
					rm_listoutdir = 1;
			} else {
				error("Got error while stat() on \"%s\".", ctx_p->listoutdir);
				ret = errno;
			}
		}
		if (!errno)
			if (st.st_mode & (S_IRWXG|S_IRWXO)) {
#ifdef PARANOID
				ret = errno = EACCES;
				error("Insecure: Others have access to directory \"%s\". Exit.", ctx_p->listoutdir);
#else
				warning("Insecure: Others have access to directory \"%s\".", ctx_p->listoutdir);
#endif
			}
	}

	nret=main_rehash(ctx_p);
	if (nret)
		ret = nret;

	if (ctx_p->flags[BACKGROUND]) {
		nret = becomedaemon();
		if (nret)
			ret = nret;
	}

	if (ctx_p->pidfile != NULL) {
		pid_t pid = getpid();
		FILE *pidfile = fopen(ctx_p->pidfile, "w");
		if (pidfile == NULL) {
			error("Cannot open file \"%s\" to write a pid there",
				ctx_p->pidfile);
			ret = errno;
		} else {
			if (fprintf(pidfile, "%u", pid) < 0) {
				error("Cannot write pid into file \"%s\"",
					ctx_p->pidfile);
				ret = errno;
			}
			fclose(pidfile);
		}
	}

	debug(3, "Current errno is %i.", ret);

	// == RUNNING ==
	if (ret == 0)
	         ret = sync_run(ctx_p);
	// == /RUNNING ==

	if (ctx_p->pidfile != NULL) {
	         if (unlink(ctx_p->pidfile)) {
	         	error("Cannot unlink pidfile \"%s\"",
	         		ctx_p->pidfile);
	         	ret = errno;
	         }
	}

	if (ctx_p->statusfile != NULL) {
		if (unlink(ctx_p->statusfile)) {
			error("Cannot unlink status file \"%s\"",
				ctx_p->statusfile);
			ret = errno;
		}
	}

	if ((!ctx_p->flags[DONTUNLINK]) && (ctx_p->listoutdir != NULL) && rm_listoutdir) {
		debug(2, "rmdir(\"%s\")", ctx_p->listoutdir);
		if (rmdir(ctx_p->listoutdir))
			error("Cannot rmdir(\"%s\")", ctx_p->listoutdir);
		if (rm_listoutdir == 2)
			free(ctx_p->listoutdir);
	}

	main_cleanup(ctx_p);

	if (ctx_p->watchdirsize)
	         free(ctx_p->watchdir);

	if (ctx_p->watchdirwslashsize)
	         free(ctx_p->watchdirwslash);

	if (ctx_p->destdirsize)
	         free(ctx_p->destdir);

	if (ctx_p->destdirwslashsize)
		free(ctx_p->destdirwslash);

	ctx_cleanup(ctx_p);
	debug(1, "finished, exitcode: %i: %s.", ret, strerror(ret));
	free(ctx_p);
	return ret;
}


