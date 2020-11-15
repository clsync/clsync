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
#endif
#if defined(__linux__) | defined(CAPABILITIES_SUPPORT)
#	include <sys/prctl.h>		// for prctl() for --preserve-fil-access
#endif

#include <pwd.h>	// getpwnam()
#include <grp.h>	// getgrnam()
#include <glib.h>	// gkf


#ifdef UNSHARE_SUPPORT
#	include <sched.h>	// unshare()
#endif
#ifdef GETMNTENT_SUPPORT
#	include <mntent.h>	// getmntent()
#	include <sys/mount.h>	// umount2()
#endif

#include "error.h"
#include "stringex.h"
#include "sync.h"
#include "malloc.h"
#include "cluster.h"
#include "fileutils.h"
#include "socket.h"
#include "syscalls.h"
#include "rules.h"
#if CGROUP_SUPPORT
#	include "cgroup.h"
#endif
#include "posix-hacks.h"

//#include "revision.h"

static const struct option long_options[] = {
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
	{"config-block-inherits", required_argument,	NULL,	CONFIGBLOCKINHERITS},
	{"custom-signals",	required_argument,	NULL,	CUSTOMSIGNALS},
	{"pid-file",		required_argument,	NULL,	PIDFILE},
	{"uid",			required_argument,	NULL,	UID},
	{"gid",			required_argument,	NULL,	GID},
	{"privileged-uid",	required_argument,	NULL,	PRIVILEGEDUID},
	{"privileged-gid",	required_argument,	NULL,	PRIVILEGEDGID},
	{"sync-handler-uid",	required_argument,	NULL,	SYNCHANDLERUID},
	{"sync-handler-gid",	required_argument,	NULL,	SYNCHANDLERGID},
	{"chroot",		required_argument,	NULL,	CHROOT},
#ifdef PIVOTROOT_OPT_SUPPORT
	{"pivot-root",		required_argument,	NULL,	PIVOT_ROOT},
#endif
#ifdef UNSHARE_SUPPORT
	{"detach-network",	required_argument,	NULL,	DETACH_NETWORK},
	{"detach-ipc",		required_argument,	NULL,	DETACH_IPC},
	{"detach-miscellanea",	optional_argument,	NULL,	DETACH_MISCELLANEA},
#endif
#ifdef CAPABILITIES_SUPPORT
# ifdef SECCOMP_SUPPORT
	{"secure-splitting",	no_argument,		NULL,	SECURESPLITTING},
# endif
	{"splitting",		required_argument,	NULL,	SPLITTING},
	{"check-execvp-arguments", optional_argument,	NULL,	CHECK_EXECVP_ARGS},
	{"add-permitted-hook-files", required_argument,	NULL,	ADDPERMITTEDHOOKFILES},
# ifdef SECCOMP_SUPPORT
	{"seccomp-filter",	optional_argument,	NULL,	SECCOMP_FILTER},
# endif
	{"forget-privthread-info", optional_argument,	NULL,	FORGET_PRIVTHREAD_INFO},
	{"permit-mprotect",	optional_argument,	NULL,	PERMIT_MPROTECT},
	{"shm-mprotect",	optional_argument,	NULL,	SHM_MPROTECT},
#endif
#ifdef UNSHARE_SUPPORT
# ifdef GETMNTENT_SUPPORT
	{"mountpoints",		required_argument,	NULL,	MOUNTPOINTS},
# endif
#endif
#ifdef CAPABILITIES_SUPPORT
	{"preserve-capabilities", required_argument,	NULL,	CAP_PRESERVE},
	{"inherit-capabilities", optional_argument,	NULL,	CAPS_INHERIT},
#endif
#ifdef CGROUP_SUPPORT
	{"forbid-devices",	optional_argument,	NULL,	FORBIDDEVICES},
	{"cgroup-group-name",	required_argument,	NULL,	CG_GROUPNAME},
#endif
#ifdef THREADING_SUPPORT
	{"threading",		required_argument,	NULL,	THREADING},
#endif
	{"retries",		required_argument,	NULL,	RETRIES},
	{"ignore-failures",	optional_argument,	NULL,	IGNOREFAILURES},
	{"exit-on-sync-skipping", optional_argument,	NULL,	EXITONSYNCSKIP},
	{"output",		required_argument,	NULL,	OUTPUT_METHOD},
	{"one-file-system",	optional_argument,	NULL,	ONEFILESYSTEM},
	{"exclude-mount-points", optional_argument,	NULL,	EXCLUDEMOUNTPOINTS},
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
	{"modification-signature", required_argument,	NULL,	MODSIGN},
	{"timeout-sync",	required_argument,	NULL,	SYNCTIMEOUT},
	{"delay-sync",		required_argument,	NULL,	SYNCDELAY},
	{"delay-collect",	required_argument,	NULL,	DELAY},
	{"delay-collect-bigfile", required_argument,	NULL,	BFILEDELAY},
	{"threshold-bigfile",	required_argument,	NULL,	BFILETHRESHOLD},
	{"cancel-syscalls",	required_argument,	NULL,	CANCEL_SYSCALLS},
	{"lists-dir",		required_argument,	NULL,	OUTLISTSDIR},
	{"have-recursive-sync",	optional_argument,	NULL,	HAVERECURSIVESYNC},
	{"synclist-simplify",	optional_argument,	NULL,	SYNCLISTSIMPLIFY},
#ifdef AUTORULESW
	{"auto-add-rules-w",	optional_argument,	NULL,	AUTORULESW},
#endif
	{"rsync-inclimit",	required_argument,	NULL,	RSYNCINCLIMIT},
	{"rsync-prefer-include", optional_argument,	NULL,	RSYNCPREFERINCLUDE},
	{"ignore-exitcode",	required_argument,	NULL,	IGNOREEXITCODE},
	{"dont-unlink-lists",	optional_argument,	NULL,	DONTUNLINK},
	{"fts-experimental-optimization", optional_argument,	NULL,	FTS_EXPERIMENTAL_OPTIMIZATION},
	{"full-initialsync",	optional_argument,	NULL,	INITFULL},
	{"only-initialsync",	optional_argument,	NULL,	ONLYINITSYNC},
	{"skip-initialsync",	optional_argument,	NULL,	SKIPINITSYNC},
	{"exit-on-no-events",	optional_argument,	NULL,	EXITONNOEVENTS},
	{"exit-hook",		required_argument,	NULL,	EXITHOOK},
	{"pre-exit-hook",	required_argument,	NULL,	PREEXITHOOK},
	{"sync-on-quit",	optional_argument,	NULL,	SOFTEXITSYNC},
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

#ifdef UNSHARE_SUPPORT
static char *const detachnetworkways[] = {
	[DN_OFF]		= "off",
	[DN_NONPRIVILEGED]	= "non-privileged",
	[DN_EVERYWHERE]		= "everywhere",
	NULL,
};
#endif

#ifdef PIVOTROOT_OPT_SUPPORT
static char *const pivotrootways[] = {
	[PW_OFF]	= "off",
	[PW_DIRECT]	= "direct",
	[PW_AUTO]	= "auto",
	[PW_AUTORO]	= "auto-ro",
	NULL,
};
#endif

enum xstatfield {
	X_STAT_FIELD_RESET = 0,
	X_STAT_FIELD_DEV,
	X_STAT_FIELD_INO,
	X_STAT_FIELD_MODE,
	X_STAT_FIELD_NLINK,
	X_STAT_FIELD_UID,
	X_STAT_FIELD_GID,
	X_STAT_FIELD_RDEV,
	X_STAT_FIELD_SIZE,
	X_STAT_FIELD_BLKSIZE,
	X_STAT_FIELD_BLOCKS,
	X_STAT_FIELD_ATIME,
	X_STAT_FIELD_MTIME,
	X_STAT_FIELD_CTIME,
	X_STAT_FIELD_ALL,
};

uint32_t xstatfield_to_statfield[] = {
	[X_STAT_FIELD_RESET]		= STAT_FIELD_RESET,
	[X_STAT_FIELD_DEV]		= STAT_FIELD_DEV,
	[X_STAT_FIELD_INO]		= STAT_FIELD_INO,
	[X_STAT_FIELD_MODE]		= STAT_FIELD_MODE,
	[X_STAT_FIELD_NLINK]		= STAT_FIELD_NLINK,
	[X_STAT_FIELD_UID]		= STAT_FIELD_UID,
	[X_STAT_FIELD_GID]		= STAT_FIELD_GID,
	[X_STAT_FIELD_RDEV]		= STAT_FIELD_RDEV,
	[X_STAT_FIELD_SIZE]		= STAT_FIELD_SIZE,
	[X_STAT_FIELD_BLKSIZE]		= STAT_FIELD_BLKSIZE,
	[X_STAT_FIELD_BLOCKS]		= STAT_FIELD_BLOCKS,
	[X_STAT_FIELD_ATIME]		= STAT_FIELD_ATIME,
	[X_STAT_FIELD_MTIME]		= STAT_FIELD_MTIME,
	[X_STAT_FIELD_CTIME]		= STAT_FIELD_CTIME,
	[X_STAT_FIELD_ALL]		= STAT_FIELD_ALL,
};

static char *const stat_fields[] = {
	[X_STAT_FIELD_RESET]		= "",
	[X_STAT_FIELD_DEV]		= "dev",
	[X_STAT_FIELD_INO]		= "ino",
	[X_STAT_FIELD_MODE]		= "mode",
	[X_STAT_FIELD_NLINK]		= "nlink",
	[X_STAT_FIELD_UID]		= "uid",
	[X_STAT_FIELD_GID]		= "gid",
	[X_STAT_FIELD_RDEV]		= "rdev",
	[X_STAT_FIELD_SIZE]		= "size",
	[X_STAT_FIELD_BLKSIZE]		= "blksize",
	[X_STAT_FIELD_BLOCKS]		= "blocks",
	[X_STAT_FIELD_ATIME]		= "atime",
	[X_STAT_FIELD_MTIME]		= "mtime",
	[X_STAT_FIELD_CTIME]		= "ctime",
	[X_STAT_FIELD_ALL]		= "*",
	NULL
};

enum x_csc_bm {
	X_CSC_RESET = 0,
	X_CSC_MON_STAT,
};

uint32_t xcsc_to_csc[] = {
	[X_CSC_RESET]			= CSC_RESET,
	[X_CSC_MON_STAT]		= CSC_MON_STAT,
};

static char *const syscalls_bitmask[] = {
	[X_CSC_RESET]			= "",
	[X_CSC_MON_STAT]		= "mon_stat",	// disable {l,}stat{,64}()-s in mon_*.c
	NULL
};

#ifdef CAPABILITIES_SUPPORT

enum x_capabilities {
	X_CAP_RESET = 0,
	X_CAP_DAC_READ_SEARCH,
	X_CAP_SETUID,
	X_CAP_SETGID,
	X_CAP_KILL,

	X_CAP_MAX
};
__u32 xcap_to_cap[] = {
	[X_CAP_DAC_READ_SEARCH] = CAP_DAC_READ_SEARCH,
	[X_CAP_SETUID] 		= CAP_SETUID,
	[X_CAP_SETGID] 		= CAP_SETGID,
	[X_CAP_KILL] 		= CAP_KILL,
};
static char *const capabilities[] = {
	[X_CAP_RESET]		= "",
	[X_CAP_DAC_READ_SEARCH]	= "CAP_DAC_READ_SEARCH",
	[X_CAP_SETUID]		= "CAP_SETUID",
	[X_CAP_SETGID]		= "CAP_SETGID",
	[X_CAP_KILL]		= "CAP_KILL",
	NULL
};
#define XCAP_TO_CAP(x) (xcap_to_cap[x])

static char *const capsinherits[] = {
	[CI_PERMITTED]		= "permittied",
	[CI_DONTTOUCH]		= "dont-touch",
	[CI_CLSYNC]		= "clsync",
	[CI_EMPTY]		= "empty",
};

#endif

static char *const socketauth[] = {
	[SOCKAUTH_UNSET]	= "",
	[SOCKAUTH_NULL]		= "null",
//	[SOCKAUTH_PAM]		= "pam",
	NULL
};

#ifdef THREADING_SUPPORT
static char *const threading_modes[] = {
	[PM_OFF]		= "off",
	[PM_SAFE]		= "safe",
	[PM_FULL]		= "full",
	NULL
};
#endif

#ifdef CAPABILITIES_SUPPORT
static char *const splitting_modes[] = {
	[SM_OFF]		= "off",
	[SM_THREAD]		= "thread",
	[SM_PROCESS]		= "process",
	NULL
};
#endif

static char *const notify_engines[] = {
	[NE_UNDEFINED]		= "",
	[NE_INOTIFY]		= "inotify",
	[NE_KQUEUE]		= "kqueue",
	[NE_FANOTIFY]		= "fanotify",
	[NE_BSM]		= "bsm",
	[NE_BSM_PREFETCH]	= "bsm_prefetch",
	[NE_DTRACEPIPE]		= "dtracepipe",
	[NE_GIO]		= "gio",
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

int syntax()
{
	info ( "possible options:" );
	int i = -1;

	while ( long_options[++i].name != NULL ) {
		switch ( long_options[i].val ) {
			case SYNCHANDLERARGS0:
			case SYNCHANDLERARGS1:
				continue;
		}

		if ( long_options[i].val & OPTION_CONFIGONLY )
			continue;

		info ( "\t--%-24s%c%c%s", long_options[i].name,
		       long_options[i].val & OPTION_LONGOPTONLY ? ' ' : '-',
		       long_options[i].val & OPTION_LONGOPTONLY ? ' ' : long_options[i].val,
		       ( long_options[i].has_arg == required_argument ? " argument" : "" ) );
	}

	exit ( EINVAL );
}

int ncpus;
pid_t parent_pid = 0;

pid_t waitpid_timed ( pid_t child_pid, int *status_p, long sec, long nsec )
{
	struct timespec ts;
	int status;
	ts.tv_sec  = sec;
	ts.tv_nsec = nsec;

	while ( ts.tv_sec >= 0 ) {
		if ( waitpid ( child_pid, &status, WNOHANG ) < 0 ) {
			if ( errno == ECHILD )
				return child_pid;

			return -1;
		} else if ( status_p != NULL )
			*status_p = status;

		ts.tv_nsec -= WAITPID_TIMED_GRANULARITY;

		if ( ts.tv_nsec < 0 ) {
			ts.tv_nsec += 1000 * 1000 * 1000;
			ts.tv_sec--;
		}
	}

	return 0;
}

int parent_isalive()
{
	int rc;
	debug ( 12, "parent_pid == %u", parent_pid );

	if ( ( rc = kill ( parent_pid, 0 ) ) ) {
		if ( errno == ESRCH ) {
			debug ( 1, "kill(%u, 0) => %i; errno => %s", parent_pid, rc, strerror ( errno ) );
			return 0;
		}
	}

	return 1;
}

void child_sigchld()
{
	if ( getppid() != 1 )
		return;

	debug ( 1, "Got SIGCHLD (parent ended). Exit." );
	exit ( -1 );
	return;
}

int sethandler_sigchld ( void ( *handler ) () )
{
	struct sigaction sa;
	sa.sa_handler = handler;
	sigemptyset ( &sa.sa_mask );
	sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
	critical_on ( sigaction ( SIGCHLD, &sa, 0 ) == -1 );
	return 0;
}

# ifndef __linux__
void *watchforparent ( void *parent_pid_p )
{
	while ( 1 ) {
		child_sigchld();
		sleep ( SLEEP_SECONDS );
	}

	return NULL;
}
# endif

pthread_t pthread_watchforparent;
pid_t fork_helper()
{
	pid_t pid = fork();

	if ( !pid ) {	// is child?
		parent_pid = getppid();
		// Anti-zombie:
# ifdef __linux__
		// Linux have support of "prctl(PR_SET_PDEATHSIG, signal);"
		sethandler_sigchld ( child_sigchld );
		prctl ( PR_SET_PDEATHSIG, SIGCHLD );
# else
		pthread_create ( &pthread_watchforparent, NULL, watchforparent, &parent_pid );
# endif
		debug ( 20, "parent_pid == %u", parent_pid );
		return 0;
	}

	return pid;
}

int version()
{
	char flags[] =
#ifdef _DEBUG_SUPPORT
	    " -D_DEBUG_SUPPORT"
#endif
#ifdef _DEBUG_FORCE
	    " -D_DEBUG_FORCE"
#endif
#ifdef KQUEUE_SUPPORT
	    " -DKQUEUE_SUPPORT"
#endif
#ifdef INOTIFY_SUPPORT
	    " -DINOTIFY_SUPPORT"
#endif
#ifdef INOTIFY_OLD
	    " -DINOTIFY_OLD"
#endif
#ifdef FANOTIFY_SUPPORT
	    " -DFANOTIFY_SUPPORT"
#endif
#ifdef BSM_SUPPORT
	    " -DBSM_SUPPORT"
#endif
#ifdef GIO_SUPPORT
	    " -DGIO_SUPPORT"
#endif
#ifdef DTRACEPIPE_SUPPORT
	    " -DDTRACEPIPE_SUPPORT"
#endif
#ifdef BACKTRACE_SUPPORT
	    " -DBACKTRACE_SUPPORT"
#endif
#ifdef CAPABILITIES_SUPPORT
	    " -DCAPABILITIES_SUPPORT"
#endif
#ifdef SECCOMP_SUPPORT
	    " -DSECCOMP_SUPPORT"
#endif
#ifdef GETMNTENT_SUPPORT
	    " -DGETMNTENT_SUPPORT"
#endif
#ifdef UNSHARE_SUPPORT
	    " -DUNSHARE_SUPPORT"
#endif
#ifdef PIVOTROOT_OPT_SUPPORT
	    " -DPIVOTROOT_OPT_SUPPORT"
#endif
#ifdef CGROUP_SUPPORT
	    " -DCGROUP_SUPPORT"
#endif
#ifdef TRE_SUPPORT
	    " -DTRE_SUPPORT"
#endif
#ifdef THREADING_SUPPORT
	    " -DTHREADING_SUPPORT"
#endif
#ifdef HL_LOCKS
	    " -DHL_LOCKS"
#endif
	    ;
	info ( PROGRAM" v%i.%i.%i"REVISION"\n\t"AUTHOR"\n\t"URL"\n\nCompiled with options: %s"
	       , VERSION_MAJ, VERSION_MID, VERSION_MIN, flags );
	exit ( 0 );
}

int clsyncapi_getapiversion()
{
	return CLSYNC_API_VERSION;
}

/**
 * @brief 			Gets raw (string) an option value by an option name
 *
 * @param[in]	_ctx_p		Context
 * @param[in]	variable_name	The name of the option
 *
 * @retval	char *		Pointer to constant string, if successful
 * @retval	NULL		On error
 *
 */
const char *parameter_get ( const char *variable_name, void *_ctx_p )
{
	const ctx_t *ctx_p = _ctx_p;
	const struct option *long_option_p = long_options;
	int param_id = -1;
	debug ( 8, "(\"%s\", %p)", variable_name, ctx_p );

	while ( long_option_p->name != NULL ) {
		if ( !strcmp ( long_option_p->name, variable_name ) ) {
			param_id = long_option_p->val;
			break;
		}

		long_option_p++;
	}

	if ( param_id == -1 ) {
		errno = ENOENT;
		return NULL;
	}

	debug ( 9, "ctx_p->flags_values_raw[%i] == \"%s\"", param_id, ctx_p->flags_values_raw[param_id] );
	return ctx_p->flags_values_raw[param_id];
}

/**
 * @brief 			Gets the name of the parameter by it's id
 *
 * @param[in]	param_id	The id of the parameter
 *
 * @retval	char *		Pointer to a constant string, if successful
 * @retval	NULL		On error
 *
 */
const char *parameter_get_name_by_id ( const uint16_t param_id )
{
	const struct option *long_option_p = long_options;
	const char *param_name = NULL;
	debug ( 8, "(%u)", param_id );

	while ( long_option_p->name != NULL ) {
		if ( long_option_p->val == param_id ) {
			param_name = long_option_p->name;
			break;
		}

		long_option_p++;
	}

	if ( param_name == NULL ) {
		errno = ENOENT;
		return NULL;
	}

	debug ( 9, "param: %u -> \"%s\"", param_id, param_name );
	return param_name;
}

/**
 * @brief 			Gets raw (string) an option value by an option name and
 * 				updates ctx_p->synchandler_argf
 *
 * @param[in]	_ctx_p		Context
 * @param[in]	variable_name	The name of the option
 *
 * @retval	char *		Pointer to newly allocated string, if successful
 * @retval	NULL		On error
 *
 */
const char *parameter_get_wmacro ( const char *variable_name, void *_ctx_p )
{
	ctx_t *ctx_p = _ctx_p;
	static struct dosync_arg dosync_arg = {0};
	debug ( 9, "(\"%s\", %p)", variable_name, _ctx_p );

	if ( *variable_name < 'A' || *variable_name > 'Z' )
		return parameter_get ( variable_name, _ctx_p );

	if ( !strcmp ( variable_name, "RSYNC-ARGS" ) ) {
		ctx_p->synchandler_argf |= SHFL_RSYNC_ARGS;
		return NULL;
	}

	if ( !strcmp ( variable_name, "INCLUDE-LIST" ) ) {
		ctx_p->synchandler_argf |= SHFL_INCLUDE_LIST;
		return NULL;
	}

	const char *r = sync_parameter_get ( variable_name, &dosync_arg );

	if ( r == dosync_arg.outf_path ) {
		ctx_p->synchandler_argf |= SHFL_INCLUDE_LIST_PATH;
		return NULL;
	}

	if ( r == dosync_arg.excf_path ) {
		ctx_p->synchandler_argf |= SHFL_EXCLUDE_LIST_PATH;
		return NULL;
	}

	errno = ENOENT;
	return NULL;
}

/* Parameter exception flags */
#define PEF_NONE                0
#define PEF_UNEXPECTED_END      1
#define PEF_UNSET_VARIABLE      2
#define PEF_LAZY_SUBSTITUTION   4
/**
 * @brief 			Expands option values, e. g. "/var/log/clsync-%label%.pid" -> "/var/log/clsync-clone.pid"
 *
 * @param[in]	ctx_p		Context
 * @param[in]	arg		An allocated string with unexpanded value. Will be free'd
 * @param[in]	exceptionflags	A bit field of allowed exceptions during parameter expansion:
 *        - PEF_NONE                No exceptions are allowed
 *        - PEF_UNEXPECTED_END      Do not warn about unexpected end of macro-substitution
 *        - PEF_UNSET_VARIABLE      Do not warn about unset variable
 *        - PEF_LAZY_SUBSTITUTION   Perform lazy substitution preserving original value
 * @param[out]	macro_count_p	A pointer to count of found macro-s
 * @param[out]	expand_count_p	A pointer to count of expanded macro-s
 * @param[in]	parameter_get	A function to resolve macro-s
 * @param[in]	parameter_get_arg An argument to the function
 *
 * @retval	char *		Pointer to newly allocated string, if successful
 * @retval	NULL		On error
 *
 */
char *parameter_expand (
    ctx_t *ctx_p,
    char *arg,
    int exceptionflags,
    int *macro_count_p,
    int *expand_count_p,
    const char * ( *parameter_get ) ( const char *variable_name, void *arg ),
    void *parameter_get_arg
)
{
	debug ( 9, "(ctx_p, \"%s\" [%p], ...)", arg, arg );
	char *ret = NULL;
	size_t ret_size = 0, ret_len = 0;
#ifdef PARANOID

	if ( arg == NULL ) {
		errno = EINVAL;
		return NULL;
	}

#endif

	if ( macro_count_p != NULL )
		*macro_count_p  = 0;

	if ( expand_count_p != NULL )
		*expand_count_p = 0;

	char *ptr = &arg[-1];

	while ( 1 ) {
		ptr++;

		switch ( *ptr ) {
			case 0:
				if ( ret == NULL ) {
					debug ( 3, "Expanding value \"%s\" to \"%s\" (case #1)", arg, arg );
					return arg;
				}

				ret[ret_len] = 0;
				debug ( 3, "Expanding value \"%s\" to \"%s\" (case #0)", arg, ret );
				free ( arg );
				return ret;

			case '%': {
					// If "%%" keep only single "%"
					if ( ptr[1] == '%' ) {
						debug ( 20, "Replacing %%%% as plain %%");
						if (unlikely( ret == NULL ))
						{
							ret_size = ALLOC_PORTION + 2;
							ret      = xrealloc ( ret, ret_size );
						}
						ret[ret_len++] = '%';
						ptr++;
						break;
					}

					debug ( 25, "A macro" );
					char nest_searching = 1;
					char *ptr_nest = ptr;

					while ( nest_searching ) {
						ptr_nest++;

						switch ( *ptr_nest ) {
							case 0:
								if (likely( ret != NULL ))
									ret[ret_len] = 0;
								else
									ret = strdup(arg);

								if ( ! ( exceptionflags & PEF_UNEXPECTED_END ) )
									warning ( "Unexpected end of macro-substitution \"%s\" in value \"%s\"; result value is \"%s\"", ptr, arg, ret );

								free ( arg );
								return ret;

							case '%': {
									char       *variable_name;
									const char *variable_value;
									size_t      variable_value_len;

									if ( macro_count_p != NULL )
										( *macro_count_p )++;

									nest_searching = 0;
									*ptr_nest = 0;
									variable_name  = &ptr[1];
									debug ( 15, "The macro is \"%s\"", variable_name );

									if ( !strcmp ( variable_name, "PID" ) ) {
										debug ( 35, "\"PID\"", variable_name );

										if ( !*ctx_p->pid_str ) {
											snprintf ( ctx_p->pid_str, 64, "%u", ctx_p->pid );
											ctx_p->pid_str_len = strlen ( ctx_p->pid_str );
										}

										variable_value     = ctx_p->pid_str;
										variable_value_len = ctx_p->pid_str_len;
									} else if ( *variable_name >= 'A' && *variable_name <= 'Z' && ( exceptionflags & PEF_LAZY_SUBSTITUTION ) ) {	// Lazy substitution, preserving the value
										debug ( 35, "Lazy substitution", variable_name );
										variable_value     =  ptr;
										variable_value_len = ( ptr_nest - ptr + 1 );
										parameter_get ( variable_name, parameter_get_arg );
									} else {									// Substituting
										debug ( 35, "Substitution", variable_name );
										errno = 0;
										variable_value = parameter_get ( variable_name, parameter_get_arg );

										if ( variable_value == NULL ) {
											if ( ! ( exceptionflags & PEF_UNSET_VARIABLE ) && ( errno != ENOENT ) )
												warning ( "Variable \"%s\" is not set (%s)", variable_name, strerror ( errno ) );

											*ptr_nest = '%';
											errno = 0;
											break;
										}

										variable_value_len = strlen ( variable_value );

										if ( expand_count_p != NULL )
											( *expand_count_p )++;
									}

									*ptr_nest = '%';

									if ( ret_len + variable_value_len + 1 >= ret_size ) {
										ret_size = ret_len + variable_value_len + 1 + ALLOC_PORTION;
										ret      = xrealloc ( ret, ret_size );
									}

									memcpy ( &ret[ret_len], variable_value, variable_value_len );
									ret_len += variable_value_len;
									break;
								}
						}
					}

					ptr = ptr_nest;
					break;
				}

			default: {
					if ( ret_len + 2 >= ret_size ) {
						ret_size += ALLOC_PORTION + 2;
						ret       = xrealloc ( ret, ret_size );
					}

					ret[ret_len++] = *ptr;
					break;
				}
		}
	}

	error ( "Unknown internal error" );
	return arg;
}

/**
 * @brief 			Gets the name of the parameter source by it's id
 *
 * @param[in]	paramsource	The id of the parameter source
 *
 * @retval	char *		Pointer to a constant string, if successful
 * @retval	NULL		On error
 *
 */
const char *parametersource_get_name ( paramsource_t paramsource )
{
	switch ( paramsource ) {
		case PS_UNKNOWN:
			return "unknown_case_0";

		case PS_ARGUMENT:
			return "cli_arguments";

		case PS_CONFIG:
			return "config";

		case PS_CONTROL:
			return "control";

		case PS_DEFAULTS:
			return "defaults";

		case PS_CORRECTION:
			return "correction";
	}

	return "unknown_case_1";
}

static inline int synchandler_arg ( char *arg, size_t arg_len, void *_ctx_p, enum shargsid shargsid )
{
	ctx_t *ctx_p = _ctx_p;
	debug ( 9, "(\"%s\" [%p], %u, %p, %u)", arg, arg, arg_len, _ctx_p, shargsid );

	if ( !strcmp ( arg, "%RSYNC-ARGS%" ) ) {
		char *args_e[] = RSYNC_ARGS_E, *args_i[] = RSYNC_ARGS_I, **args_p;
		free ( arg );
		args_p = ctx_p->flags[RSYNCPREFERINCLUDE] ? args_i : args_e;

		while ( *args_p != NULL ) {
#ifdef VERYPARANOID

			if ( !strcmp ( *args_p, "%RSYNC-ARGS%" ) ) {
				errno = EINVAL;
				critical ( "Infinite recursion detected" );
			}

#endif

			if ( synchandler_arg ( strdup ( *args_p ), strlen ( *args_p ), ctx_p, shargsid ) )
				return errno;

			args_p++;
		}

		return 0;
	}

	if ( ctx_p->synchandler_args[shargsid].c >= MAXARGUMENTS - 2 ) {
		errno = E2BIG;
		error ( "There're too many sync-handler arguments "
		        "(%u > "XTOSTR ( MAXARGUMENTS - 2 ) "; arg == \"%s\").",
		        arg );
		return errno;
	}

#ifdef _DEBUG_FORCE
	debug ( 14, "ctx_p->synchandler_args[%u].v[%u] = %p", shargsid, ctx_p->synchandler_args[shargsid].c, arg );
#endif
	ctx_p->synchandler_args[shargsid].v[ctx_p->synchandler_args[shargsid].c++] = arg;
	return 0;
}

static int synchandler_arg0 ( char *arg, size_t arg_len, void *_ctx_p )
{
	return synchandler_arg ( arg, arg_len, _ctx_p, SHARGS_PRIMARY );
}

static int synchandler_arg1 ( char *arg, size_t arg_len, void *_ctx_p )
{
	return synchandler_arg ( arg, arg_len, _ctx_p, SHARGS_INITIAL );
}

/* strtol wrapper with error checks */
static inline long xstrtol ( const char *str, int *err )
{
	long res;
	char *endptr;
	errno = 0;
	res = strtol ( str, &endptr, 0 );

	if ( errno || *endptr ) {
		error ( "argument \"%s\" can't be parsed as a number", str );
		*err = EINVAL;
	}

	return res;
}

// a wrapper for xstrtol with a trimming of leading and tailing whitespaces
static inline long xstrtol_trim ( char *str, int *err )
{
	// Removing whitespace from the beginning
	while ( *str == ' ' || *str == '\t' || *str == '\r' || *str == '\n' ) str++;

	// Removing whitespaces from the ending
	char *end = str;

	while ( *end != '\0' ) end++; // find the end of the string

	end--;

	while ( *end == ' ' || *end == '\t' || *end == '\r' || *end == '\n' ) end--; // find the end of the string excluding whitespaces

	end++;
	*end = '\0';
	// Calling xstrtol(), obviously :)
	return xstrtol ( str, err );
}

__extension__ static inline int parse_customsignals ( ctx_t *ctx_p, char *arg )
{
	char *ptr = arg, *start = arg;
	int ret = 0;
	unsigned int signal;

	do {
		switch ( *ptr ) {
			case 0:
			case ',':
			case ':':
				// TODO: use xstrtol() instead of atoi()
				//signal = (unsigned int)xstrtol(start, &ret);
				signal = ( unsigned int ) atoi ( start );

				if ( ret ) {
					errno = ret;
					return errno;
				}

				if ( signal == 0 ) {
					// flushing the setting
					int i = 0;

					while ( i < 256 ) {
						if ( ctx_p->customsignal[i] ) {
							free ( ctx_p->customsignal[i] );
							ctx_p->customsignal[i] = NULL;
						}

						i++;
					}

#ifdef _DEBUG_FORCE
					fprintf ( stderr, "Force-Debug: parse_parameter(): Reset custom signals.\n" );
#endif
				} else {
					if ( *ptr != ':' ) {
						char ch = *ptr;
						*ptr = 0;
						errno = EINVAL;
						error ( "Expected \":\" in \"%s\"", start );
						*ptr = ch;
						return errno;
					}

					{
						char ch, *end;
						ptr++;
						end = ptr;

						while ( *end && *end != ',' ) end++;

						if ( end == ptr ) {
							errno = EINVAL;
							error ( "Empty config block name on signal \"%u\"", signal );
							return errno;
						}

						if ( signal > MAXSIGNALNUM ) {
							errno = EINVAL;
							error ( "Too high value of the signal: \"%u\" > "XTOSTR ( MAXSIGNALNUM ) "", signal );
							return errno;
						}

						ch = *end;
						*end = 0;
						ctx_p->customsignal[signal] = strdup ( ptr );
						*end = ch;
#ifdef _DEBUG_FORCE
						fprintf ( stderr, "Force-Debug: parse_parameter(): Adding custom signal %u.\n", signal );
#endif
						ptr = end;
					}
				}

				start = ptr + 1;
				break;

			case '0' ... '9':
				break;

			default:
				errno = EINVAL;
				error ( "Expected a digit, comma (or colon) but got \"%c\"", *ptr );
				return errno;
		}
	} while ( * ( ptr++ ) );

	return 0;
}

__extension__ static int parse_parameter ( ctx_t *ctx_p, uint16_t param_id, char *arg, paramsource_t paramsource )
{
	int ret = 0;
#ifdef _DEBUG_FORCE
	fprintf ( stderr, "Force-Debug: parse_parameter(): %i: %i = \"%s\"\n", paramsource, param_id, arg );
#endif

	switch ( paramsource ) {
		case PS_CONTROL:
		case PS_ARGUMENT:
			if ( param_id & OPTION_CONFIGONLY ) {
				syntax();
				return 0;
			}

			ctx_p->flags_set[param_id] = 1;
			break;

		case PS_CONFIG:
			if ( ctx_p->flags_set[param_id] )
				return 0;

			ctx_p->flags_set[param_id] = 1;
			break;

		case PS_DEFAULTS:
#ifdef VERYPARANOID
			if ( ctx_p->flags_set[param_id] ) {
				error ( "Parameter #%i is already set. No need in setting the default value.", param_id );
				return 0;
			}

#endif
			break;

		/*		case PS_REHASH:
					arg = ctx_p->flags_values_raw[param_id];
		#ifdef VERYPARANOID
					critical_on (arg == NULL);
		#endif

					debug(9, "Rehash setting %i -> \"%s\"", param_id, arg);
					break;*/
		case PS_CORRECTION:
			critical_on ( arg == NULL );
			debug ( 9, "Correcting setting %i -> \"%s\"", param_id, arg );
			break;

		default:
			error ( "Unknown parameter #%i source (value \"%s\").", param_id, arg != NULL ? arg : "" );
			break;
	}

	if ( ( arg != NULL ) /*&& (paramsource != PS_REHASH)*/ ) {
		if ( param_id != SYNCHANDLERARGS0 && param_id != SYNCHANDLERARGS1 )
			arg = parameter_expand ( ctx_p, arg, PEF_NONE, NULL, NULL, parameter_get, ctx_p );

		if ( ctx_p->flags_values_raw[param_id] != NULL )
			free ( ctx_p->flags_values_raw[param_id] );

		ctx_p->flags_values_raw[param_id] = arg;
	}

	switch ( param_id ) {
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
			if ( paramsource == PS_CONTROL ) {
				warning ( "Cannot change \"custom-signal\" in run-time. Ignoring." );
				return 0;
			}

			if ( parse_customsignals ( ctx_p, arg ) )
				return errno;

			break;

		case UID: {
				struct passwd *pwd = getpwnam ( arg );
				ctx_p->flags[param_id]++;

				if ( pwd == NULL ) {
					ctx_p->uid = ( unsigned int ) xstrtol_trim ( arg, &ret );
					break;
				}

				ctx_p->uid = pwd->pw_uid;
				break;
			}

		case GID: {
				struct group *grp = getgrnam ( arg );
				ctx_p->flags[param_id]++;

				if ( grp == NULL ) {
					ctx_p->gid = ( unsigned int ) xstrtol_trim ( arg, &ret );
					break;
				}

				ctx_p->gid = grp->gr_gid;
				break;
			}

#ifdef CAPABILITIES_SUPPORT
# ifdef SECCOMP_SUPPORT

		case SECURESPLITTING: {
				if ( ctx_p->flags_values_raw[CHECK_EXECVP_ARGS] == NULL )
					ctx_p->flags[CHECK_EXECVP_ARGS]++;

				if ( ctx_p->flags_values_raw[SECCOMP_FILTER] == NULL )
					ctx_p->flags[SECCOMP_FILTER]++;

				if ( ctx_p->flags_values_raw[FORBIDDEVICES] == NULL )
					ctx_p->flags[FORBIDDEVICES]++;

				if ( ctx_p->flags_values_raw[SPLITTING] != NULL )
					break;

				arg = "process";
			}

		case SPLITTING: {
				char *value, *arg_orig = arg;

				if ( !*arg ) {
					ctx_p->flags[param_id] = 0;
					return 0;
				}

				splittingmode_t splittingmode = getsubopt ( &arg, splitting_modes, &value );

				if ( ( int ) splittingmode == -1 ) {
					errno = EINVAL;
					error ( "Invalid splitting mode entered: \"%s\"", arg_orig );
					return EINVAL;
				}

				ctx_p->flags[SPLITTING] = splittingmode;

				if ( param_id != SECURESPLITTING )
					break;

				switch ( splittingmode ) {
					case SM_THREAD:
						ctx_p->flags[FORGET_PRIVTHREAD_INFO]++;
						break;

					case SM_PROCESS:
						break;

					case SM_OFF:
						errno = EINVAL;
						error ( "Cannot understand \"--secure-splitting=off\". This configuration line have no sence." );
						break;
				}

				if ( ctx_p->flags_values_raw[PERMIT_MPROTECT] == NULL )
					ctx_p->flags[PERMIT_MPROTECT] = ( splittingmode != SM_THREAD );

				break;
			}

# endif

		case CAP_PRESERVE: {
				char *subopts = arg;
				ctx_p->caps  = 0;

				while ( *subopts != 0 ) {
					char *value;
					__u32 cap = getsubopt ( &subopts, capabilities, &value );
					debug ( 4, "cap == 0x%x", cap );

					if ( cap != X_CAP_RESET )
						ctx_p->caps |= CAP_TO_MASK ( XCAP_TO_CAP ( cap ) );
				}

				break;
			}

		case CAPS_INHERIT: {
				char *value, *arg_orig = arg;

				if ( !*arg ) {
					ctx_p->flags[param_id] = 0;
					return 0;
				}

				capsinherit_t capsinherit = getsubopt ( &arg, capsinherits, &value );

				if ( ( int ) capsinherit == -1 ) {
					errno = EINVAL;
					error ( "Invalid capabilities inheriting mode entered: \"%s\"", arg_orig );
					return EINVAL;
				}

				ctx_p->flags[CAPS_INHERIT] = capsinherit;
				break;
			}

#endif

		case PRIVILEGEDUID: {
				struct passwd *pwd = getpwnam ( arg );
				ctx_p->flags[param_id]++;

				if ( pwd == NULL ) {
					ctx_p->privileged_uid = ( unsigned int ) xstrtol_trim ( arg, &ret );
					debug ( 5, "ctx_p->privileged_uid == %d (case 0)", ctx_p->privileged_uid );
					break;
				}

				debug ( 5, "ctx_p->privileged_uid == %d (case 1)", ctx_p->privileged_uid );
				ctx_p->privileged_uid = pwd->pw_uid;
				break;
			}

		case PRIVILEGEDGID: {
				struct group *grp = getgrnam ( arg );
				ctx_p->flags[param_id]++;

				if ( grp == NULL ) {
					ctx_p->privileged_gid = ( unsigned int ) xstrtol_trim ( arg, &ret );
					debug ( 5, "ctx_p->privileged_gid == %d (case 0)", ctx_p->privileged_gid );
					break;
				}

				debug ( 5, "ctx_p->privileged_gid == %d (case 1)", ctx_p->privileged_gid );
				ctx_p->privileged_gid = grp->gr_gid;
				break;
			}

		case SYNCHANDLERUID: {
				struct passwd *pwd = getpwnam ( arg );
				ctx_p->flags[param_id]++;

				if ( pwd == NULL ) {
					ctx_p->synchandler_uid = ( unsigned int ) xstrtol_trim ( arg, &ret );
					debug ( 5, "ctx_p->synchandler_uid == %d (case 0)", ctx_p->synchandler_uid );
					break;
				}

				debug ( 5, "ctx_p->synchandler_uid == %d (case 1)", ctx_p->synchandler_uid );
				ctx_p->synchandler_uid = pwd->pw_uid;
				break;
			}

		case SYNCHANDLERGID: {
				struct group *grp = getgrnam ( arg );
				ctx_p->flags[param_id]++;

				if ( grp == NULL ) {
					ctx_p->synchandler_gid = ( unsigned int ) xstrtol_trim ( arg, &ret );
					debug ( 5, "ctx_p->synchandler_gid == %d (case 0)", ctx_p->synchandler_gid );
					break;
				}

				debug ( 5, "ctx_p->synchandler_gid == %d (case 1)", ctx_p->synchandler_gid );
				ctx_p->synchandler_gid = grp->gr_gid;
				break;
			}

		case CHROOT:
			if ( paramsource == PS_CONTROL ) {
				warning ( "Cannot change \"chroot\" in run-time. Ignoring." );
				return 0;
			}

			if ( !*arg ) {
				free ( ctx_p->chroot_dir );
				ctx_p->chroot_dir = NULL;
				return 0;
			}

			ctx_p->chroot_dir	= arg;
			break;
#ifdef PIVOTROOT_OPT_SUPPORT

		case PIVOT_ROOT: {
				char *value, *arg_orig = arg;

				if ( !*arg ) {
					ctx_p->flags[PIVOT_ROOT] = DEFAULT_PIVOT_MODE;
					return 0;
				}

				pivotroot_way_t pivotway = getsubopt ( &arg, pivotrootways, &value );

				if ( ( int ) pivotway == -1 ) {
					errno = EINVAL;
					error ( "Invalid pivot_root use way entered: \"%s\"", arg_orig );
					return EINVAL;
				}

				ctx_p->flags[PIVOT_ROOT] = pivotway;
				break;
			}

#endif
#ifdef UNSHARE_SUPPORT

		case DETACH_NETWORK: {
				char *value, *arg_orig = arg;

				if ( !*arg ) {
					ctx_p->flags[param_id] = 0;
					return 0;
				}

				detachnetwork_way_t detachnetwork_way = getsubopt ( &arg, detachnetworkways, &value );

				if ( ( int ) detachnetwork_way == -1 ) {
					errno = EINVAL;
					error ( "Invalid network detach way entered: \"%s\"", arg_orig );
					return EINVAL;
				}

				ctx_p->flags[DETACH_NETWORK] = detachnetwork_way;
				break;
			}

#endif
#ifdef CAPABILITIES_SUPPORT

		case ADDPERMITTEDHOOKFILES: {
				char *ptr;

				if ( paramsource == PS_CONTROL ) {
					warning ( "Cannot change \"add-permitted-hook-files\" in run-time. Ignoring." );
					return 0;
				}

				while ( ctx_p->permitted_hookfiles )
					free ( ctx_p->permitted_hookfile[--ctx_p->permitted_hookfiles] );

				ptr = arg;

				while ( 1 ) {
					char *end = strchr ( ptr, ',' );

					if ( end != NULL )
						*end =  0;

					if ( !*ptr ) {
						while ( ctx_p->permitted_hookfiles )
							free ( ctx_p->permitted_hookfile[--ctx_p->permitted_hookfiles] );

						if ( end != NULL )
							ptr = &end[1];

						continue;
					}

					if ( ctx_p->permitted_hookfiles >= MAXPERMITTEDHOOKFILES ) {
						errno = EINVAL;
						error ( "Too many permitted hook files" );
						return errno;
					}

					ctx_p->permitted_hookfile[ctx_p->permitted_hookfiles++] = strdup ( ptr );

					if ( end == NULL )
						break;

					*end = ',';
					ptr = &end[1];
				}

				break;
			}

#endif
#ifdef UNSHARE_SUPPORT
# ifdef GETMNTENT_SUPPORT

		case MOUNTPOINTS: {
				char *ptr;

				if ( paramsource == PS_CONTROL ) {
					warning ( "Cannot change \"mountpoints\" in run-time. Ignoring." );
					return 0;
				}

				while ( ctx_p->mountpoints )
					free ( ctx_p->mountpoint[--ctx_p->mountpoints] );

				if ( !*arg )
					break;

				ptr = arg;

				while ( 1 ) {
					char *end = strchr ( ptr, ',' );

					if ( end != NULL )
						*end =  0;

					if ( !*ptr ) {
						while ( ctx_p->mountpoints )
							free ( ctx_p->mountpoint[--ctx_p->mountpoints] );

						if ( end != NULL )
							ptr = &end[1];

						continue;
					}

					if ( ctx_p->mountpoints >= MAXMOUNTPOINTS ) {
						errno = EINVAL;
						error ( "Too many mountpoints" );
						return errno;
					}

					ctx_p->mountpoint[ctx_p->mountpoints++] = strdup ( ptr );

					if ( end == NULL )
						break;

					*end = ',';
					ptr = &end[1];
				}

				break;
			}

# endif
#endif

		case PIDFILE:
			if ( paramsource == PS_CONTROL ) {
				warning ( "Cannot change \"pid-file\" in run-time. Ignoring." );
				return 0;
			}

			ctx_p->pidfile		= arg;
			break;

		case RETRIES:
			ctx_p->retries		= ( unsigned int ) xstrtol_trim ( arg, &ret );
			break;
#ifdef THREADING_SUPPORT

		case THREADING: {
				char *value, *arg_orig = arg;

				if ( !*arg ) {
					ctx_p->flags[param_id] = 0;
					return 0;
				}

				threadingmode_t threadingmode = getsubopt ( &arg, threading_modes, &value );

				if ( ( int ) threadingmode == -1 ) {
					errno = EINVAL;
					error ( "Invalid threading mode entered: \"%s\"", arg_orig );
					return EINVAL;
				}

				ctx_p->flags[THREADING] = threadingmode;
				break;
			}

#endif

		case OUTPUT_METHOD: {
				char *value, *arg_orig = arg;

				if ( !*arg ) {
					ctx_p->flags[param_id] = 0;
					return 0;
				}

				outputmethod_t outputmethod = getsubopt ( &arg, output_methods, &value );

				if ( ( int ) outputmethod == -1 ) {
					errno = EINVAL;
					error ( "Invalid log writing destination entered: \"%s\"", arg_orig );
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
			ctx_p->cluster_mcastipport	= ( uint16_t ) xstrtol_trim ( arg, &ret );
			break;

		case CLUSTERTIMEOUT:
			ctx_p->cluster_timeout		= ( unsigned int ) xstrtol_trim ( arg, &ret );
			break;

		case CLUSTERNODENAME:
			ctx_p->cluster_nodename		= arg;
			break;

		case CLUSTERHDLMIN:
			ctx_p->cluster_hash_dl_min	= ( uint16_t ) xstrtol_trim ( arg, &ret );
			break;

		case CLUSTERHDLMAX:
			ctx_p->cluster_hash_dl_max	= ( uint16_t ) xstrtol_trim ( arg, &ret );
			break;

		case CLUSTERSDLMAX:
			ctx_p->cluster_scan_dl_max	= ( uint16_t ) xstrtol_trim ( arg, &ret );
			break;
#endif

		case OUTLISTSDIR:
			ctx_p->listoutdir		= arg;
			break;

		case LABEL:
			ctx_p->label			= arg;
			break;
#ifdef CGROUP_SUPPORT

		case CG_GROUPNAME:
			ctx_p->cg_groupname		= arg;
			break;
#endif

		case STANDBYFILE:
			if ( strlen ( arg ) ) {
				ctx_p->standbyfile		= arg;
				ctx_p->flags[STANDBYFILE]	= 1;
			} else {
				ctx_p->standbyfile		= NULL;
				ctx_p->flags[STANDBYFILE]	= 0;
			}

			break;

		case MODSIGN: {
				char *subopts = arg;
				ctx_p->flags[MODSIGN] = 0;

				while ( *subopts != 0 ) {
					char *value;
					typeof ( ctx_p->flags[MODSIGN] ) field = getsubopt ( &subopts, stat_fields, &value );
					debug ( 4, "field == %i -> %x (%s)", field, xstatfield_to_statfield[field], value );

					if ( field != X_STAT_FIELD_RESET )
						ctx_p->flags[MODSIGN] |= xstatfield_to_statfield[field];
				}

				debug ( 5, "ctx_p->flags[MODSIGN] == 0x%x", ctx_p->flags[MODSIGN] );
				break;
			}

		case SYNCDELAY:
			ctx_p->syncdelay		= ( unsigned int ) xstrtol_trim ( arg, &ret );
			break;

		case DELAY:
			ctx_p->_queues[QUEUE_NORMAL].collectdelay  = ( unsigned int ) xstrtol_trim ( arg, &ret );
			break;

		case BFILEDELAY:
			ctx_p->_queues[QUEUE_BIGFILE].collectdelay = ( unsigned int ) xstrtol_trim ( arg, &ret );
			break;

		case BFILETHRESHOLD:
			ctx_p->bfilethreshold = ( unsigned long ) xstrtol_trim ( arg, &ret );
			break;

		case CANCEL_SYSCALLS: {
				char *subopts = arg;

				while ( *subopts != 0 ) {
					char *value;
					typeof ( ctx_p->flags[CANCEL_SYSCALLS] ) syscall_bitmask = getsubopt ( &subopts, syscalls_bitmask, &value );
					debug ( 4, "cancel syscall == %i -> 0x%x", syscall_bitmask, xcsc_to_csc[syscall_bitmask] );

					if ( syscall_bitmask == X_CSC_RESET ) {
						ctx_p->flags[CANCEL_SYSCALLS] = 0;
						continue;
					}

					ctx_p->flags[CANCEL_SYSCALLS] |= xcsc_to_csc[syscall_bitmask];
				}

				break;
			}

		case MONITOR: {
				char *value, *arg_orig = arg;

				if ( paramsource == PS_CONTROL ) {
					warning ( "Cannot change \"monitor\" in run-time. Ignoring." );
					return 0;
				}

				if ( !*arg ) {
					ctx_p->flags_set[param_id] = 0;
					return 0;
				}

				notifyengine_t notifyengine = getsubopt ( &arg, notify_engines, &value );

				if ( ( int ) notifyengine == -1 ) {
					errno = EINVAL;
					error ( "Invalid FS monitor subsystem entered: \"%s\"", arg_orig );
					return EINVAL;
				}

				switch ( notifyengine ) {
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
					case NE_BSM_PREFETCH:
#endif
#ifdef GIO_SUPPORT
					case NE_GIO:
#endif
#ifdef DTRACEPIPE_SUPPORT
					case NE_DTRACEPIPE:
#endif
						break;

					default:
						error ( PROGRAM" is compiled without %s subsystem support. Recompile with option \"--with-%s\" if you're planning to use it.", arg_orig, arg_orig );
						return EINVAL;
				}

				ctx_p->flags[MONITOR] = notifyengine;
				break;
			}

		case RSYNCINCLIMIT:
			ctx_p->rsyncinclimit = ( unsigned int ) xstrtol_trim ( arg, &ret );
			break;

		case SYNCTIMEOUT:
			ctx_p->synctimeout   = ( unsigned int ) xstrtol_trim ( arg, &ret );
			break;

		case PREEXITHOOK:
			if ( strlen ( arg ) ) {
				ctx_p->preexithookfile		= arg;
				ctx_p->flags[PREEXITHOOK]	= 1;
			} else {
				ctx_p->preexithookfile		= NULL;
				ctx_p->flags[PREEXITHOOK]	= 0;
			}

			break;

		case EXITHOOK:
			if ( strlen ( arg ) ) {
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
					switch ( *ptr ) {
						case 0:
						case ',':
//						*ptr=0;
							exitcode = ( unsigned char ) atoi ( start );

							if ( exitcode == 0 ) {
								// flushing the setting
								int i = 0;

								while ( i < 256 )
									ctx_p->isignoredexitcode[i++] = 0;

#ifdef _DEBUG_FORCE
								fprintf ( stderr, "Force-Debug: parse_parameter(): Reset ignored exitcodes.\n" );
#endif
							} else {
								ctx_p->isignoredexitcode[exitcode] = 1;
#ifdef _DEBUG_FORCE
								fprintf ( stderr, "Force-Debug: parse_parameter(): Adding ignored exitcode %u.\n", exitcode );
#endif
							}

							start = ptr + 1;
							break;

						case '0' ... '9':
							break;

						default:
							errno = EINVAL;
							error ( "Expected a digit or comma but got \"%c\"", *ptr );
							return errno;
					}
				} while ( * ( ptr++ ) );

				break;
			}

		case SHOW_VERSION:
			version();
			break;

		case WATCHDIR:
			if ( paramsource == PS_CONTROL ) {
				warning ( "Cannot change \"watch-dir\" in run-time. Ignoring." );
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
				char *sep = strstr ( arg, "://" );

				if ( ctx_p->destproto != NULL ) {
					free ( ctx_p->destproto );
					ctx_p->destproto = NULL;
				}

				ctx_p->destdir	 = arg;

				if ( sep == NULL ) {
					char *at_ptr = strchr ( arg, '@' );
					char *cl_ptr = strchr ( arg, ':' );

					if ( at_ptr != NULL && cl_ptr != NULL && at_ptr < cl_ptr ) {
						ctx_p->destproto = strdup ( "rsync+ssh" );
						debug ( 5, "Destination proto is: %s (case #0)", ctx_p->destproto );
					}

					break;
				}

				{
					char *ptr = arg;

					while ( ptr < sep ) {
						if ( *ptr < 'a' || *ptr > 'z' )
							break;

						ptr++;
					}

					if ( ptr == sep ) {
						size_t len = ( ptr - arg ) + 1;
						ctx_p->destproto = xmalloc ( len + 1 );
						memcpy ( ctx_p->destproto, arg, len );
						ctx_p->destproto[len] = 0;
					}

					debug ( 5, "Destination proto is: %s (case #1)", ctx_p->destproto );
				}

				break;
			}

		case SOCKETPATH:
			ctx_p->socketpath	= arg;
			break;

		case SOCKETAUTH: {
				char *value;
				ctx_p->flags[SOCKETAUTH] = getsubopt ( &arg, socketauth, &value );

				if ( ctx_p->flags[SOCKETAUTH] == -1 ) {
					error ( "Wrong socket auth mech entered: \"%s\"", arg );
					return EINVAL;
				}
			}

		case SOCKETMOD:
			if ( !sscanf ( arg, "%o", ( unsigned int * ) &ctx_p->socketmod ) ) {
				error ( "Non octal value passed to --socket-mod: \"%s\"", arg );
				return EINVAL;
			}

			ctx_p->flags[param_id]++;
			break;

		case SOCKETOWN: {
				char *colon = strchr ( arg, ':' );
				uid_t uid;
				gid_t gid;

				if ( colon == NULL ) {
					struct passwd *pwent = getpwnam ( arg );

					if ( pwent == NULL ) {
						error ( "Cannot find username \"%s\" (case #0)",
						        arg );
						return EINVAL;
					}

					uid = pwent->pw_uid;
					gid = pwent->pw_gid;
				} else {
					char user[USER_LEN + 2], group[GROUP_LEN + 2];
					memcpy ( user, arg, MIN ( USER_LEN, colon - arg ) );
					user[colon - arg] = 0;
					xstrncpy ( group, &colon[1], GROUP_LEN );
					errno = 0;
					struct passwd *pwent = getpwnam ( user );

					if ( pwent == NULL ) {
						error ( "Cannot find username \"%s\" (case #1)",
						        user );
						return EINVAL;
					}

					errno = 0;
					struct group  *grent = getgrnam ( group );

					if ( grent == NULL ) {
						error ( "Cannot find group \"%s\"",
						        group );
						return EINVAL;
					}

					uid = pwent->pw_uid;
					gid = grent->gr_gid;
				}

				ctx_p->socketuid = uid;
				ctx_p->socketgid = gid;
				ctx_p->flags[param_id]++;
				debug ( 2, "socket: uid == %u; gid == %u", uid, gid );
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
				ctx_p->flags[MODE]  = getsubopt ( &arg, modes, &value );

				if ( ctx_p->flags[MODE] == -1 ) {
					error ( "Wrong mode name entered: \"%s\"", arg );
					return EINVAL;
				}

				break;
			}

		case SYNCHANDLERARGS0:
			str_splitargs ( arg, synchandler_arg0, ctx_p );
			break;

		case SYNCHANDLERARGS1:
			str_splitargs ( arg, synchandler_arg1, ctx_p );
			break;

		default:
			if ( arg == NULL )
				ctx_p->flags[param_id]++;
			else
				ctx_p->flags[param_id] = xstrtol_trim ( arg, &ret );

#ifdef _DEBUG_FORCE
			fprintf ( stderr, "Force-Debug: flag %i is set to %i\n", param_id & 0xff, ctx_p->flags[param_id] );
#endif
			break;
	}

	if ( ret != 0 ) {
		if ( arg == NULL ) {
			error ( "Unable to process option \"%s\" from \"%s\"", parameter_get_name_by_id ( param_id ), parametersource_get_name ( paramsource ) );
		} else {
			error ( "Unable to process option \"%s\" (with argument: \"%s\") from \"%s\"", parameter_get_name_by_id ( param_id ), arg, parametersource_get_name ( paramsource ) );
		}
	}

	return ret;
}

int arguments_parse ( int argc, char *argv[], struct ctx *ctx_p )
{
	int c;
	int option_index = 0;
	// Generating "optstring" (man 3 getopt_long) with using information from struct array "long_options"
	char *optstring     = alloca ( ( ( 'z' - 'a' + 1 ) * 3 + '9' - '0' + 1 ) * 3 + 1 );
	char *optstring_ptr = optstring;
	const struct option *lo_ptr = long_options;

	while ( lo_ptr->name != NULL ) {
		if ( ! ( lo_ptr->val & ( OPTION_CONFIGONLY | OPTION_LONGOPTONLY ) ) ) {
			* ( optstring_ptr++ ) = lo_ptr->val & 0xff;

			if ( lo_ptr->has_arg == required_argument )
				* ( optstring_ptr++ ) = ':';

			if ( lo_ptr->has_arg == optional_argument ) {
				* ( optstring_ptr++ ) = ':';
				* ( optstring_ptr++ ) = ':';
			}
		}

		lo_ptr++;
	}

	*optstring_ptr = 0;
#ifdef _DEBUG_FORCE
	fprintf ( stderr, "Force-Debug: %s\n", optstring );
#endif

	// Parsing arguments
	while ( 1 ) {
		c = getopt_long ( argc, argv, optstring, long_options, &option_index );

		if ( c == -1 ) break;

		int ret = parse_parameter ( ctx_p, c, optarg == NULL ? NULL : strdup ( optarg ), PS_ARGUMENT );

		if ( ret ) return ret;
	}

	if ( optind < argc ) {
		synchandler_args_t *args_p = &ctx_p->synchandler_args[SHARGS_PRIMARY];

		while ( args_p->c )
			free ( args_p->v[--args_p->c] );

		if ( ( optind + 1 != argc ) || ( *argv[optind] ) ) {	// If there's only "" after the "--", just reset "synchandler_argc" to "0", otherwise:
			do {
				if ( synchandler_arg0 ( strdup ( argv[optind++] ), 0, ctx_p ) )
					return errno;
			} while ( optind < argc );
		}
	}

	return 0;
}

void gkf_parse ( ctx_t *ctx_p, GKeyFile *gkf, paramsource_t paramsource )
{
	debug ( 9, "" );
	char *config_block = ( char * ) ctx_p->config_block;

	while ( config_block != NULL ) {
		const struct option *lo_ptr = long_options;

		if ( config_block != ctx_p->config_block ) {
			ctx_p->flags_values_raw[CONFIGBLOCKINHERITS] = NULL;
			ctx_p->flags_set[CONFIGBLOCKINHERITS] = 0;
		}

		while ( lo_ptr->name != NULL ) {
			gchar *value = g_key_file_get_value ( gkf, config_block, lo_ptr->name, NULL );

			if ( value != NULL ) {
				int ret = parse_parameter ( ctx_p, lo_ptr->val, value, paramsource );

				if ( ret ) exit ( ret );
			}

			lo_ptr++;
		}

		if ( config_block != ctx_p->config_block )
			free ( config_block );

		config_block = ctx_p->flags_values_raw[CONFIGBLOCKINHERITS];

		if ( config_block != NULL )
			debug ( 2, "Next block is: %s", config_block );
	};

	return;
}

int configs_parse ( ctx_t *ctx_p, paramsource_t paramsource )
{
	GKeyFile *gkf;
	gkf = g_key_file_new();

	if ( ctx_p->config_path ) {
		GError *g_error = NULL;

		if ( !strcmp ( ctx_p->config_path, "/NULL/" ) ) {
			debug ( 2, "Empty path to config file. Don't read any of config files." );
			return 0;
		}

		debug ( 1, "Trying config-file \"%s\" (case #0)", ctx_p->config_path );

		if ( !g_key_file_load_from_file ( gkf, ctx_p->config_path, G_KEY_FILE_NONE, &g_error ) ) {
			error ( "Cannot open/parse file \"%s\" (g_error #%u.%u: %s)", ctx_p->config_path, g_error->domain, g_error->code, g_error->message );
			g_key_file_free ( gkf );
			return -1;
		} else
			gkf_parse ( ctx_p, gkf, paramsource );
	} else {
		char  *config_paths[] = CONFIG_PATHS;
		char **config_path_p = config_paths, *config_path_real = xmalloc ( PATH_MAX );
		size_t config_path_real_size = PATH_MAX;
		char  *homedir     = getenv ( "HOME" );
		size_t homedir_len = ( homedir == NULL ? 0 : strlen ( homedir ) );

		while ( *config_path_p != NULL ) {
			size_t config_path_len = strlen ( *config_path_p );

			if ( config_path_len + homedir_len + 3 > config_path_real_size ) {
				config_path_real_size = config_path_len + homedir_len + 3;
				config_path_real      = xmalloc ( config_path_real_size );
			}

			if ( *config_path_p[0] != '/' ) {
				memcpy ( config_path_real, homedir, homedir_len );
				config_path_real[homedir_len] = '/';
				memcpy ( &config_path_real[homedir_len + 1], *config_path_p, config_path_len + 1 );
			} else
				memcpy ( config_path_real, *config_path_p, config_path_len + 1 );

			debug ( 1, "Trying config-file \"%s\" (case #1)", config_path_real );

			if ( !g_key_file_load_from_file ( gkf, config_path_real, G_KEY_FILE_NONE, NULL ) ) {
				debug ( 1, "Cannot open/parse file \"%s\"", config_path_real );
				config_path_p++;
				continue;
			}

			gkf_parse ( ctx_p, gkf, paramsource );
			break;
		}

		free ( config_path_real );
	}

	g_key_file_free ( gkf );
	return 0;
}

int ctx_check ( ctx_t *ctx_p )
{
	int ret = 0;
#ifdef CLUSTER_SUPPORT
	struct utsname utsname;
#endif
#ifndef _DEBUG_SUPPORT

	if ( ctx_p->flags[DEBUG] ) {
		ret = errno = EINVAL;
		error ( "Clsync was compiled without debugging support, please recompile with --enable-debug in order to be able to use debugging" );
	}

#endif

	if ( ctx_p->socketpath != NULL ) {
#ifndef ENABLE_SOCKET
		ret = EINVAL;
		error ( "clsync is compiled without control socket support, option \"--socket\" cannot be used." );
#endif

		if ( ctx_p->flags[SOCKETAUTH] == SOCKAUTH_UNSET )
			ctx_p->flags[SOCKETAUTH] = SOCKAUTH_NULL;
	}

	if ( ( ctx_p->flags[SOCKETOWN] ) && ( ctx_p->socketpath == NULL ) ) {
		ret = errno = EINVAL;
		error ( "\"--socket-own\" is useless without \"--socket\"" );
	}

	if ( ( ctx_p->flags[SOCKETMOD] ) && ( ctx_p->socketpath == NULL ) ) {
		ret = errno = EINVAL;
		error ( "\"--socket-mod\" is useless without \"--socket\"" );
	}

	if ( ( ctx_p->flags[SOCKETAUTH] ) && ( ctx_p->socketpath == NULL ) ) {
		ret = errno = EINVAL;
		error ( "\"--socket-auth\" is useless without \"--socket\"" );
	}

#ifdef PIVOTROOT_OPT_SUPPORT

	if ( ( ctx_p->flags[PIVOT_ROOT] != PW_OFF ) && ( ctx_p->chroot_dir == NULL ) ) {
		ret = errno = EINVAL;
		error ( "\"--pivot-root\" cannot be used without \"--chroot\"" );
	}

# ifdef UNSHARE_SUPPORT
#  ifdef GETMNTENT_SUPPORT

	if ( ( ctx_p->flags[PIVOT_ROOT] != PW_OFF ) && ( ctx_p->mountpoints ) )
		warning ( "\"--mountpoints\" is set while \"--pivot-root\" is set, too" );

#  endif
# endif
#endif

	if ( ctx_p->flags[STANDBYFILE] && ( ctx_p->flags[MODE] == MODE_SIMPLE ) ) {
		ret = errno = EINVAL;
		error ( "Sorry but option \"--standby-file\" cannot be used in mode \"simple\", yet." );
	}

#ifdef THREADING_SUPPORT
# ifdef VERYPARANOID

	if ( ( ctx_p->retries != 1 ) && ctx_p->flags[THREADING] ) {
		ret = errno = EINVAL;
		error ( "\"--retries\" values should be equal to \"1\" for this \"--threading\" value." );
	}

# endif

	if ( ctx_p->flags[THREADING] && ctx_p->flags[ONLYINITSYNC] ) {
		ret = errno = EINVAL;
		error ( "Conflicting options: This value of \"--threading\" cannot be used in conjunction with \"--only-initialsync\"." );
	}

	if ( ctx_p->flags[THREADING] && ctx_p->flags[EXITONNOEVENTS] ) {
		ret = errno = EINVAL;
		error ( "Conflicting options: This value of \"--threading\" cannot be used in conjunction with \"--exit-on-no-events\"." );
	}

	if ( ctx_p->flags[THREADING] && ctx_p->flags[MAXITERATIONS] ) {
		ret = errno = EINVAL;
		error ( "Conflicting options: This value of \"--threading\" cannot be used in conjunction with \"--max-iterations\"." );
	}

	if ( ctx_p->flags[THREADING] && ctx_p->flags[PREEXITHOOK] ) {
		ret = errno = EINVAL;
		error ( "Conflicting options: This value of \"--threading\" cannot be used in conjunction with \"--pre-exit-hook\"." );
	}

	if ( ctx_p->flags[THREADING] && ctx_p->flags[SPLITTING] == SM_THREAD ) {
		ret = errno = EINVAL;
		error ( "Conflicting options: This value of \"--threading\" cannot be used in conjunction with \"--splitting=thread\"." );
	}

# ifdef SECCOMP_SUPPORT

	if ( ctx_p->flags[THREADING] && ctx_p->flags[SECCOMP_FILTER] ) {
		ret = errno = EINVAL;
		error ( "Conflicting options: This value of \"--threading\" cannot be used in conjunction with \"--seccomp-filter\"." );
	}

# endif
#endif

	if ( ctx_p->flags[SKIPINITSYNC] && ctx_p->flags[EXITONNOEVENTS] ) {
		ret = errno = EINVAL;
		error ( "Conflicting options: \"--skip-initialsync\" and \"--exit-on-no-events\" cannot be used together." );
	}

	if ( ctx_p->flags[ONLYINITSYNC] && ctx_p->flags[EXITONNOEVENTS] ) {
		ret = errno = EINVAL;
		error ( "Conflicting options: \"--only-initialsync\" and \"--exit-on-no-events\" cannot be used together." );
	}

	if ( ctx_p->flags[SKIPINITSYNC] && ctx_p->flags[ONLYINITSYNC] ) {
		ret = errno = EINVAL;
		error ( "Conflicting options: \"--skip-initialsync\" and \"--only-initialsync\" cannot be used together." );
	}

	if ( ctx_p->flags[INITFULL] && ctx_p->flags[SKIPINITSYNC] ) {
		ret = errno = EINVAL;
		error ( "Conflicting options: \"--full-initialsync\" and \"--skip-initialsync\" cannot be used together." );
	}

	if ( ctx_p->flags[MODSIGN] && ( ctx_p->flags[CANCEL_SYSCALLS]&CSC_MON_STAT ) ) {
		ret = errno = EINVAL;
		error ( "Conflicting options: \"--modification-signature\" and \"--cancel-syscalls=mon_stat\" cannot be used together." );
	}

	if ( ctx_p->flags[EXCLUDEMOUNTPOINTS] )
		ctx_p->flags[ONEFILESYSTEM] = 1;

	if ( ctx_p->flags[MODE] == MODE_UNSET ) {
		ret = errno = EINVAL;
		error ( "\"--mode\" is not set." );
	}

	if ( ctx_p->watchdir == NULL ) {
		ret = errno = EINVAL;
		error ( "\"--watch-dir\" is not set." );
	}

	if ( ctx_p->handlerfpath == NULL ) {
		switch ( ctx_p->flags[MODE] ) {
			case MODE_DIRECT:
				ctx_p->handlerfpath = DEFAULT_CP_PATH;
				break;

			case MODE_RSYNCDIRECT:
				ctx_p->handlerfpath = DEFAULT_RSYNC_PATH;
				break;

			default:
				ret = errno = EINVAL;
				error ( "\"--sync-handler\" path is not set." );
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

	if ( ( ctx_p->flags[MODE] == MODE_RSYNCDIRECT ) && ( ctx_p->destdir == NULL ) ) {
		ret = errno = EINVAL;
		error ( "Mode \"rsyncdirect\" cannot be used without specifying \"--destination-dir\"." );
	}

#ifdef CLUSTER_SUPPORT

	if ( ( ctx_p->flags[MODE] == MODE_RSYNCDIRECT ) && ( ctx_p->cluster_iface != NULL ) ) {
		ret = errno = EINVAL;
		error ( "Mode \"rsyncdirect\" cannot be used in conjunction with \"--cluster-iface\"." );
	}

	if ( ( ctx_p->cluster_iface == NULL ) && ( ( ctx_p->cluster_mcastipaddr != NULL ) || ( ctx_p->cluster_nodename != NULL ) || ( ctx_p->cluster_timeout ) || ( ctx_p->cluster_mcastipport ) ) ) {
		ret = errno = EINVAL;
		error ( "ctx \"--cluster-ip\", \"--cluster-node-name\", \"--cluster_timeout\" and/or \"cluster_ipport\" cannot be used without \"--cluster-iface\"." );
	}

	if ( ctx_p->cluster_hash_dl_min > ctx_p->cluster_hash_dl_max ) {
		ret = errno = EINVAL;
		error ( "\"--cluster-hash-dl-min\" cannot be greater than \"--cluster-hash-dl-max\"." );
	}

	if ( ctx_p->cluster_hash_dl_max > ctx_p->cluster_scan_dl_max ) {
		ret = errno = EINVAL;
		error ( "\"--cluster-hash-dl-max\" cannot be greater than \"--cluster-scan-dl-max\"." );
	}

	if ( !ctx_p->cluster_timeout )
		ctx_p->cluster_timeout	    = DEFAULT_CLUSTERTIMEOUT;

	if ( !ctx_p->cluster_mcastipport )
		ctx_p->cluster_mcastipport = DEFAULT_CLUSTERIPPORT;

	if ( !ctx_p->cluster_mcastipaddr )
		ctx_p->cluster_mcastipaddr = DEFAULT_CLUSTERIPADDR;

	if ( ctx_p->cluster_iface != NULL ) {
#ifndef _DEBUG_FORCE
		ret = errno = EINVAL;
		error ( "Cluster subsystem is not implemented, yet. Sorry." );
#endif

		if ( ctx_p->cluster_nodename == NULL ) {
			if ( !uname ( &utsname ) )
				ctx_p->cluster_nodename = strdup ( utsname.nodename );

			debug ( 1, "cluster node name is: %s", ctx_p->cluster_nodename );
		}

		if ( ctx_p->cluster_nodename == NULL ) {
			ret = errno = EINVAL;
			error ( "Option \"--cluster-iface\" is set, but \"--cluster-node-name\" is not set and cannot get the nodename with uname()." );
		} else {
			ctx_p->cluster_nodename_len = strlen ( ctx_p->cluster_nodename );
		}
	}

#endif // CLUSTER_SUPPORT

	switch ( ctx_p->flags[MODE] ) {
		case MODE_RSYNCSO:
			ctx_p->synchandler_argf |= SHFL_EXCLUDE_LIST_PATH;
			ctx_p->synchandler_argf |= SHFL_INCLUDE_LIST_PATH;
			break;
	}

	if (
	    ctx_p->flags[RSYNCPREFERINCLUDE] &&
	    ! (
	        ctx_p->flags[MODE] == MODE_RSYNCDIRECT ||
	        ctx_p->flags[MODE] == MODE_RSYNCSHELL  ||
	        ctx_p->flags[MODE] == MODE_RSYNCSO
	    )
	)
		warning ( "Option \"--rsyncpreferinclude\" is useless if mode is not \"rsyncdirect\", \"rsyncshell\" or \"rsyncso\"." );

#ifdef AUTORULESW

	if (
	    (
	        ctx_p->flags[MODE] == MODE_RSYNCDIRECT ||
	        ctx_p->flags[MODE] == MODE_RSYNCSHELL  ||
	        ctx_p->flags[MODE] == MODE_RSYNCSO
	    )
	    && ctx_p->flags[AUTORULESW]
	)
		warning ( "Option \"--auto-add-rules-w\" in modes \"rsyncdirect\", \"rsyncshell\" and \"rsyncso\" may cause unexpected problems." );

#endif

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
		error ( "Option \"--have-recursive-sync\" with nodes \"rsyncdirect\", \"rsyncshell\" and \"rsyncso\" are incompatible." );
	}

	if ( ctx_p->flags[SYNCLISTSIMPLIFY] && ( ctx_p->listoutdir == NULL ) ) {
		ret = errno = EINVAL;
		error ( "Option \"--dir-lists\" should be set to use option \"--synclist-simplify\"." );
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
		error ( "Option \"--synclist-simplify\" with nodes \"rsyncdirect\" and \"rsyncshell\" are incompatible." );
	}

#ifdef GIO_SUPPORT
# ifdef SECCOMP_SUPPORT

	if ( ( ctx_p->flags[MONITOR] == NE_GIO ) && ( ctx_p->flags[SECCOMP_FILTER] ) ) {
		ret = errno = EINVAL;
		error ( "GIO is not compatible with seccomp filter (\"--monitor=gio\" and \"--seccomp-filter\" are incompatible)" );
	}

# endif
#endif
#ifdef FANOTIFY_SUPPORT

	if ( ctx_p->flags[MONITOR] == NE_FANOTIFY )
		critical ( "fanotify is not supported, now!" );
	else
#endif
		switch ( ctx_p->flags[MONITOR] ) {
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
			case NE_BSM_PREFETCH:
#endif
#ifdef GIO_SUPPORT
			case NE_GIO:
#endif
#ifdef DTRACEPIPE_SUPPORT
			case NE_DTRACEPIPE:
#endif
				break;

			default: {
					ret = errno = EINVAL;
					char monitor_types[] =
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
#ifdef GIO_SUPPORT
					    " \"--monitor=gio\""
#endif
#ifdef DTRACEPIPE_SUPPORT
					    " \"--monitor=dtracepipe\""
#endif
					    ;
					error ( "Required one of the next options: %s", monitor_types );
				}
		}

	if ( ctx_p->flags[EXITHOOK] ) {
#ifdef VERYPARANOID

		if ( ctx_p->exithookfile == NULL ) {
			ret = errno = EINVAL;
			error ( "ctx_p->exithookfile == NULL" );
		} else
#endif
		{
			if ( access ( ctx_p->exithookfile, X_OK ) == -1 ) {
				error ( "\"%s\" is not executable.", ctx_p->exithookfile );

				if ( !ret )
					ret = errno;
			}
		}
	}

	if ( ctx_p->flags[CHECK_EXECVP_ARGS] && ( ctx_p->flags[MODE] == MODE_DIRECT ) ) {
		ret = errno = EINVAL;
		error ( "Options --check-execvp-arguments/--secure-splitting cannot be used in conjunction with --mode=direct (see \"man 1 clsync\": --check-execvp-arguments)." );
	}

#if 0

	if ( ctx_p->handlerfpath != NULL )
		if ( access ( ctx_p->handlerfpath, X_OK ) == -1 ) {
			error ( "\"%s\" is not executable.", ctx_p->handlerfpath );

			if ( !ret )
				ret = errno;
		}

#endif
	return ret;
}

int config_block_parse ( ctx_t *ctx_p, const char *const config_block_name )
{
	int rc;
	debug ( 1, "(ctx_p, \"%s\")", config_block_name );
	ctx_p->config_block = config_block_name;
	rc = configs_parse ( ctx_p, PS_CONTROL );

	if ( !rc )
		rc = ctx_check ( ctx_p );

	return errno = rc;
}

int ctx_set ( ctx_t *ctx_p, const char *const parameter_name, const char *const parameter_value )
{
	int ret = ENOENT;
	const struct option *lo_ptr = long_options;

	while ( lo_ptr->name != NULL ) {
		if ( !strcmp ( lo_ptr->name, parameter_name ) ) {
			ret = parse_parameter ( ctx_p, lo_ptr->val, strdup ( parameter_value ), PS_CONTROL );
			break;
		}

		lo_ptr++;
	}

	ret = ctx_check ( ctx_p );

	if ( ret )
		critical ( "Cannot continue with this setup" );

	return ret;
}

void ctx_cleanup ( ctx_t *ctx_p )
{
	int i = 0;
	debug ( 9, "" );

	while ( i < OPTION_FLAGS ) {
		if ( ctx_p->flags_values_raw[i] != NULL ) {
			free ( ctx_p->flags_values_raw[i] );
			ctx_p->flags_values_raw[i] = NULL;
		}

		i++;
	}

	{
		int n = 0;

		while ( n < SHARGS_MAX ) {
			int i = 0,  e = ctx_p->synchandler_args[n].c;

			while ( i < e ) {
#ifdef _DEBUG_FORCE
				debug ( 14, "synchandler args: %u, %u: free(%p)", n, i, ctx_p->synchandler_args[n].v[i] );
#endif
				free ( ctx_p->synchandler_args[n].v[i] );
				ctx_p->synchandler_args[n].v[i] = NULL;
				i++;
			}

			ctx_p->synchandler_args[n].c = 0;
			n++;
		}
	}

	return;
}

int becomedaemon()
{
	int pid;
	signal ( SIGPIPE, SIG_IGN );

	switch ( ( pid = fork() ) ) {
		case -1:
			error ( "Cannot fork()." );
			return ( errno );

		case 0:
			setsid();
			break;

		default:
			debug ( 1, "fork()-ed, pid is %i.", pid );
			errno = 0;
			exit ( 0 );
	}

	return 0;
}

int main_cleanup ( ctx_t *ctx_p )
{
	int i = 0;

	while ( ( i < MAXRULES ) && ( ctx_p->rules[i].mask != RA_NONE ) )
		regfree ( &ctx_p->rules[i++].expr );

	debug ( 3, "%i %i %i %i", ctx_p->watchdirsize, ctx_p->watchdirwslashsize, ctx_p->destdirsize, ctx_p->destdirwslashsize );
	return 0;
}

int main_rehash ( ctx_t *ctx_p )
{
	debug ( 3, "" );
	int ret = 0;
	main_cleanup ( ctx_p );

	if ( ctx_p->rulfpath != NULL ) {
		ret = parse_rules_fromfile ( ctx_p );

		if ( ret )
			error ( "Got error from parse_rules_fromfile()." );
	} else {
		ctx_p->rules[0].perm = DEFAULT_RULES_PERM;
		ctx_p->rules[0].mask = RA_NONE;		// Terminator. End of rules.
	}

	return ret;
}

FILE *main_statusfile_f;
int main_status_update ( ctx_t *ctx_p )
{
	static state_t state_old = STATE_UNKNOWN;
	state_t        state     = ctx_p->state;
	debug ( 4, "%u", state );

	if ( state == state_old ) {
		debug ( 3, "State unchanged: %u == %u", state, state_old );
		return 0;
	}

#ifdef VERYPARANOID

	if ( status_descr[state] == NULL ) {
		error ( "status_descr[%u] == NULL.", state );
		return EINVAL;
	}

#endif
	setenv ( "CLSYNC_STATUS", status_descr[state], 1 );

	if ( ctx_p->statusfile == NULL )
		return 0;

	debug ( 3, "Setting status to %i: %s.", state, status_descr[state] );
	state_old = state;
	int ret = 0;

	if ( ftruncate ( fileno ( main_statusfile_f ), 0 ) ) {
		error ( "Cannot ftruncate() the file \"%s\".",
		        ctx_p->statusfile );
		return errno;
	}

	rewind ( main_statusfile_f );

	if ( fprintf ( main_statusfile_f, "%s", status_descr[state] ) <= 0 ) {	// TODO: check output length
		error ( "Cannot write to file \"%s\".",
		        ctx_p->statusfile );
		return errno;
	}

	if ( fflush ( main_statusfile_f ) ) {
		error ( "Cannot fflush() on file \"%s\".",
		        ctx_p->statusfile );
		return errno;
	}

	return ret;
}

int argc;
char **argv;
#define UGID_PRESERVE (1<<16)
int main ( int _argc, char *_argv[] )
{
	struct ctx *ctx_p = xcalloc ( 1, sizeof ( *ctx_p ) );
	argv = _argv;
	argc = _argc;
	int ret = 0, nret, rm_listoutdir = 0;
	SAFE ( posixhacks_init(), errno = ret = _SAFE_rc );
	ctx_p->flags[MONITOR]			 = DEFAULT_NOTIFYENGINE;
	ctx_p->syncdelay 			 = DEFAULT_SYNCDELAY;
	ctx_p->_queues[QUEUE_NORMAL].collectdelay   = DEFAULT_COLLECTDELAY;
	ctx_p->_queues[QUEUE_BIGFILE].collectdelay  = DEFAULT_BFILECOLLECTDELAY;
	ctx_p->_queues[QUEUE_INSTANT].collectdelay  = COLLECTDELAY_INSTANT;
	ctx_p->_queues[QUEUE_LOCKWAIT].collectdelay = COLLECTDELAY_INSTANT;
	ctx_p->bfilethreshold			 = DEFAULT_BFILETHRESHOLD;
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
#ifdef PIVOTROOT_OPT_SUPPORT
	ctx_p->flags[PIVOT_ROOT]		 = DEFAULT_PIVOT_MODE;
#endif
#ifdef CAPABILITIES_SUPPORT
	ctx_p->flags[CAP_PRESERVE]		 = CAP_PRESERVE_TRY;
	ctx_p->caps				 = DEFAULT_PRESERVE_CAPABILITIES;
	ctx_p->flags[CAPS_INHERIT]		 = DEFAULT_CAPS_INHERIT;
	ctx_p->flags[DETACH_IPC]		 = DEFAULT_DETACH_IPC;
	parse_parameter ( ctx_p, LABEL, strdup ( DEFAULT_LABEL ), PS_DEFAULTS );
	ncpus					 = sysconf ( _SC_NPROCESSORS_ONLN ); // Get number of available logical CPUs
	memory_init();
	{
		struct passwd *pwd = getpwnam ( DEFAULT_USER );
		ctx_p->uid = ( pwd != NULL ) ? pwd->pw_uid : DEFAULT_UID;
		ctx_p->flags[UID]		 = UGID_PRESERVE;
	}
	{
		struct group  *grp = getgrnam ( DEFAULT_GROUP );
		ctx_p->gid = ( grp != NULL ) ? grp->gr_gid : DEFAULT_GID;
		ctx_p->flags[GID]		 = UGID_PRESERVE;
	}
#endif
	ctx_p->pid				 = getpid();
	error_init ( &ctx_p->flags[OUTPUT_METHOD], &ctx_p->flags[QUIET], &ctx_p->flags[VERBOSE], &ctx_p->flags[DEBUG] );
	nret = arguments_parse ( argc, argv, ctx_p );

	if ( nret ) ret = nret;

	if ( !ret ) {
		nret = configs_parse ( ctx_p, PS_CONFIG );

		if ( nret ) ret = nret;
	}

	debug ( 5, "after arguments_parse(): uid == %d, gid == %d, privileged_uid == %d, privileged_gid == %d, synchandler_uid == %d, synchandler_gid == %d",
		ctx_p->uid, ctx_p->gid, ctx_p->privileged_uid, ctx_p->privileged_gid, ctx_p->synchandler_uid, ctx_p->synchandler_gid )

	if ( !ctx_p->flags[PRIVILEGEDUID] )
		ctx_p->privileged_uid = getuid();

	if ( !ctx_p->flags[PRIVILEGEDGID] )
		ctx_p->privileged_gid = getgid();

	if ( !ctx_p->flags[SYNCHANDLERUID] )
		ctx_p->synchandler_uid = ctx_p->privileged_uid;

	if ( !ctx_p->flags[SYNCHANDLERGID] )
		ctx_p->synchandler_gid = ctx_p->privileged_gid;

	debug ( 4, "uid == %d, gid == %d, privileged_uid == %d, privileged_gid == %d, synchandler_uid == %d, synchandler_gid == %d",
		ctx_p->uid, ctx_p->gid, ctx_p->privileged_uid, ctx_p->privileged_gid, ctx_p->synchandler_uid, ctx_p->synchandler_gid )

#ifdef CGROUP_SUPPORT

	if ( ctx_p->cg_groupname == NULL ) {
		ctx_p->cg_groupname = parameter_expand ( ctx_p, strdup ( DEFAULT_CG_GROUPNAME ), PEF_UNSET_VARIABLE, NULL, NULL, parameter_get, ctx_p );
		ctx_p->flags_values_raw[CG_GROUPNAME] = ctx_p->cg_groupname;
	}

#endif

	if ( ctx_p->dump_path == NULL ) {
		ctx_p->dump_path = parameter_expand ( ctx_p, strdup ( DEFAULT_DUMPDIR ), PEF_UNSET_VARIABLE, NULL, NULL, parameter_get, ctx_p );
		ctx_p->flags_values_raw[DUMPDIR] = ctx_p->dump_path;
	}

	if ( !ctx_p->synchandler_args[SHARGS_PRIMARY].c ) {
		char *args_line0 = NULL, *args_line1 = NULL;

		switch ( ctx_p->flags[MODE] ) {
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
				args_line0 = ( ctx_p->flags[RSYNCPREFERINCLUDE] ) ? DEFAULT_SYNCHANDLER_ARGS_RDIRECT_I : DEFAULT_SYNCHANDLER_ARGS_RDIRECT_E;
				break;

			case MODE_RSYNCSHELL:
				args_line0 = ( ctx_p->flags[RSYNCPREFERINCLUDE] ) ? DEFAULT_SYNCHANDLER_ARGS_RSHELL_I  : DEFAULT_SYNCHANDLER_ARGS_RSHELL_E;
				break;

			default:
				break;
		}

		if ( args_line0 != NULL ) {
			char *args_line = strdup ( args_line0 );
			parse_parameter ( ctx_p, SYNCHANDLERARGS0, args_line, PS_DEFAULTS );
		}

		if ( args_line1 != NULL ) {
			char *args_line = strdup ( args_line1 );
			parse_parameter ( ctx_p, SYNCHANDLERARGS1, args_line, PS_DEFAULTS );
		}
	}

	debug ( 4, "ncpus == %u", ncpus );
	debug ( 4, "debugging flags: %u %u %u %u", ctx_p->flags[OUTPUT_METHOD], ctx_p->flags[QUIET], ctx_p->flags[VERBOSE], ctx_p->flags[DEBUG] );

	if ( ctx_p->watchdir != NULL ) {
		char *rwatchdir = realpath ( ctx_p->watchdir, NULL );

		if ( rwatchdir == NULL ) {
			error ( "Got error while realpath() on \"%s\" [#0].", ctx_p->watchdir );
			ret = errno;
		}

		debug ( 5, "rwatchdir == \"%s\"", rwatchdir );
		stat64_t stat64 = {0};

		if ( lstat64 ( ctx_p->watchdir, &stat64 ) ) {
			error ( "Cannot lstat64() on \"%s\"", ctx_p->watchdir );

			if ( !ret )
				ret = errno;
		} else {
			ctx_p->st_dev = stat64.st_dev;
			/*
						if ((stat64.st_mode & S_IFMT) == S_IFLNK) {
							// The proplems may be due to FTS_PHYSICAL option of fts_open() in sync_initialsync_rsync_walk(),
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
			# ifdef PARANOID
								if (ctx_p->watchdirsize)
									if (ctx_p->watchdir != NULL)
										free(ctx_p->watchdir);
			# endif

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
			*/
		}

		if ( !ret ) {
			parse_parameter ( ctx_p, WATCHDIR, rwatchdir, PS_CORRECTION );
			ctx_p->watchdirlen  = strlen ( ctx_p->watchdir );
			ctx_p->watchdirsize = ctx_p->watchdirlen;
#ifdef VERYPARANOID

			if ( ctx_p->watchdirlen == 1 ) {
				ret = errno = EINVAL;
				error ( "Very-Paranoid: --watch-dir is supposed to be not \"/\"." );
			}

#endif
		}

		if ( !ret ) {
			if ( ctx_p->watchdirlen == 1 ) {
				ctx_p->watchdirwslash     = ctx_p->watchdir;
				ctx_p->watchdirwslashsize = 0;
				ctx_p->watchdir_dirlevel  = 0;
			} else {
				size_t size = ctx_p->watchdirlen + 2;
				char *newwatchdir = xmalloc ( size );
				memcpy ( newwatchdir, ctx_p->watchdir, ctx_p->watchdirlen );
				ctx_p->watchdirwslash     = newwatchdir;
				ctx_p->watchdirwslashsize = size;
				memcpy ( &ctx_p->watchdirwslash[ctx_p->watchdirlen], "/", 2 );
				ctx_p->watchdir_dirlevel  = fileutils_calcdirlevel ( ctx_p->watchdirwslash );
			}
		}
	}

	if ( ( ctx_p->destdir != NULL ) && ( ctx_p->destproto == NULL ) ) {	// "ctx_p->destproto == NULL" means "no protocol"/"local directory"
		char *rdestdir = realpath ( ctx_p->destdir, NULL );

		if ( rdestdir == NULL ) {
			error ( "Got error while realpath() on \"%s\" [#1].", ctx_p->destdir );
			ret = errno;
		}

		debug ( 5, "rdestdir == \"%s\"", rdestdir );

		if ( !ret ) {
			parse_parameter ( ctx_p, DESTDIR, rdestdir, PS_CORRECTION );
			ctx_p->destdirlen  = strlen ( ctx_p->destdir );
			ctx_p->destdirsize = ctx_p->destdirlen;

			if ( ctx_p->destdirlen == 1 ) {
				ret = errno = EINVAL;
				error ( "destdir is supposed to be not \"/\"." );
			}
		}

		if ( !ret ) {
			size_t size = ctx_p->destdirlen  + 2;
			char *newdestdir  = xmalloc ( size );
			memcpy ( newdestdir,  ctx_p->destdir,  ctx_p->destdirlen );
			ctx_p->destdirwslash     = newdestdir;
			ctx_p->destdirwslashsize = size;
			memcpy ( &ctx_p->destdirwslash[ctx_p->destdirlen], "/", 2 );
		}
	} else if ( ctx_p->destproto != NULL )
		ctx_p->destdirwslash = ctx_p->destdir;

	if ( ctx_p->rulfpath ) {
		if ( *ctx_p->rulfpath != '/' ) {
			ctx_p->rulfpath     = realpath ( ctx_p->rulfpath, NULL );

			if ( ctx_p->rulfpath == NULL )
				error ( "Cannot find rules-file. Got error while realpath(\"%s\")", ctx_p->rulfpath );
			else
				ctx_p->rulfpathsize = 1;
		}
	}

	if ( ctx_p->handlerfpath != NULL ) {
		char *rhandlerfpath = realpath ( ctx_p->handlerfpath, NULL );
		/*
				if (rhandlerfpath == NULL) {
					error("Got error while realpath() on \"%s\" [#0].", ctx_p->handlerfpath);
					ret = errno;
				}
				debug(5, "rhandlerfpath == \"%s\"", rhandlerfpath);
				ctx_p->handlerfpath = rhandlerfpath;*/

		if ( rhandlerfpath != NULL )
			ctx_p->handlerfpath = rhandlerfpath;
	}

	debug ( 9, "chdir(\"%s\");", ctx_p->watchdir );

	if ( chdir ( ctx_p->watchdir ) ) {
		error ( "Got error while chdir(\"%s\")", ctx_p->watchdir );
		ret = errno;
	}

	/*
		if (ctx_p->flags_values_raw[SYNCHANDLERARGS0] != NULL)
			parse_parameter(ctx_p, SYNCHANDLERARGS0, NULL, PS_REHASH);

		if (ctx_p->flags_values_raw[SYNCHANDLERARGS1] != NULL)
			parse_parameter(ctx_p, SYNCHANDLERARGS1, NULL, PS_REHASH);
	*/
	{
		int n = 0;

		while ( n < SHARGS_MAX ) {
			synchandler_args_t *args_p = &ctx_p->synchandler_args[n++];
			debug ( 9, "Custom arguments %u count: %u", n - 1, args_p->c );
			int i = 0;

			while ( i < args_p->c ) {
				int macros_count = -1, expanded = -1;
				args_p->v[i] = parameter_expand ( ctx_p, args_p->v[i], PEF_LAZY_SUBSTITUTION, &macros_count, &expanded, parameter_get_wmacro, ctx_p );
				debug ( 12, "args_p->v[%u] == \"%s\" (t: %u; e: %u)", i, args_p->v[i], macros_count, expanded );

				if ( macros_count == expanded )
					args_p->isexpanded[i]++;

				i++;
			}
		}
	}
	ctx_p->state = STATE_STARTING;
	{
#ifdef UNSHARE_SUPPORT
# ifdef GETMNTENT_SUPPORT
		struct mntent *ent;
		FILE *ent_f;
		ent_f = NULL;

		if ( ctx_p->mountpoints ) {
			// Openning the file with mount list
			ent_f = setmntent ( "/proc/mounts", "r" );

			if ( ent_f == NULL ) {
				error ( "Got error while setmntent(\"/proc/mounts\", \"r\")" );
				ret = errno;
			}
		}

# endif
# define unshare_wrapper(a) \
	if (unshare(a)) {\
		error("Got error from unshare("TOSTR(a)")");\
		ret = errno;\
	}

		if ( ctx_p->flags[DETACH_IPC] ) {
			unshare ( CLONE_NEWUTS );
			error_init_ipc ( ctx_p->flags[SPLITTING] == SM_PROCESS ? IPCT_SHARED : IPCT_PRIVATE );
		}

		if ( ctx_p->flags[DETACH_MISCELLANEA] ) {
			unshare ( CLONE_NEWIPC );
			unshare ( CLONE_NEWUTS );
			unshare ( CLONE_SYSVSEM );
		}

		if ( ( ctx_p->flags[PIVOT_ROOT] != PW_OFF ) || ctx_p->mountpoints ) {
			unshare_wrapper ( CLONE_FILES );
			unshare_wrapper ( CLONE_FS );
			unshare_wrapper ( CLONE_NEWNS );
		}

		if ( ctx_p->flags[DETACH_NETWORK] == DN_EVERYWHERE )
			unshare_wrapper ( CLONE_NEWNET );

# undef unshare_wrapper
#endif

		if ( ctx_p->chroot_dir != NULL ) {
#ifdef PIVOTROOT_OPT_SUPPORT

			switch ( ctx_p->flags[PIVOT_ROOT] ) {
				case PW_OFF:
				case PW_DIRECT:
					break;

				case PW_AUTO:
				case PW_AUTORO: {
						if ( chdir ( ctx_p->chroot_dir ) ) {
							error ( "Got error while chdir(\"%s\")", ctx_p->chroot_dir );
							ret = errno;
						}

						if ( mkdir ( "old_root", 0700 ) ) {
							if ( errno != EEXIST ) {
								error ( "Got error from mkdir(\"old_root\", 0700)" );
								ret = errno;
								break;
							}
						}

						if ( mkdir ( PIVOT_AUTO_DIR, 0700 ) ) {
							if ( errno != EEXIST ) {
								error ( "Got error from mkdir(\""PIVOT_AUTO_DIR"\", 0700)" );
								ret = errno;
								break;
							}
						}

						unsigned long mount_flags  =  MS_BIND | MS_REC |
						                              ( ( ctx_p->flags[PIVOT_ROOT] == PW_AUTORO ) ? MS_RDONLY : 0 );

						if ( mount ( ctx_p->chroot_dir, PIVOT_AUTO_DIR, NULL, mount_flags, NULL ) ) {
							error ( "Got error while mount(\"%s\", \"%s\", NULL, %o, NULL)",
							        ctx_p->chroot_dir, PIVOT_AUTO_DIR, mount_flags );
							ret = errno;
							break;
						}

						ctx_p->chroot_dir = PIVOT_AUTO_DIR;
						break;
					}
			}

#endif
			debug ( 7, "chdir(\"%s\")", ctx_p->chroot_dir );

			if ( chdir ( ctx_p->chroot_dir ) ) {
				error ( "Got error while chdir(\"%s\")", ctx_p->chroot_dir );
				ret = errno;
			}
		}

#ifdef UNSHARE_SUPPORT
# ifdef GETMNTENT_SUPPORT

		if ( ctx_p->mountpoints && ( ent_f != NULL ) ) {
			// Getting mount-points to be umounted
			while ( NULL != ( ent = getmntent ( ent_f ) ) ) {
				int i;
				debug ( 8, "Checking should \"%s\" be umount or not", ent->mnt_dir );
				i = 0;

				while ( i < ctx_p->mountpoints ) {
					debug ( 9, "\"%s\" <?> \"%s\"", ent->mnt_dir, ctx_p->mountpoint[i] );

					if ( !strcmp ( ent->mnt_dir, ctx_p->mountpoint[i] ) ) {
						debug ( 9, "found" );
						break;
					}

					i++;
				}

				if ( i >= ctx_p->mountpoints ) {
					debug ( 1, "umount2(\"%s\", MNT_DETACH)", ent->mnt_dir );

					if ( umount2 ( ent->mnt_dir, MNT_DETACH ) && errno != ENOENT && errno != EINVAL ) {
						error ( "Got error while umount2(\"%s\", MNT_DETACH)", ent->mnt_dir );
						ret = errno;
					}
				}
			}

			endmntent ( ent_f );
		}

# endif
#endif

		if ( ctx_p->chroot_dir != NULL ) {
#ifdef PIVOTROOT_OPT_SUPPORT

			if ( !ret ) {
				switch ( ctx_p->flags[PIVOT_ROOT] ) {
					case PW_OFF:
						break;

					case PW_DIRECT:
					case PW_AUTO:
					case PW_AUTORO:
						if ( pivot_root ( ".", "old_root" ) ) {
							error ( "Got error while pivot_root(\".\", \"old_root\")" );
							ret = errno;
						}

						break;
				}
			}

#endif
			debug ( 7, "chroot(\".\")" );

			if ( chroot ( "." ) ) {
				error ( "Got error while chroot(\".\")" );
				ret = errno;
			}

#ifdef PIVOTROOT_OPT_SUPPORT

			if ( !ret ) {
				switch ( ctx_p->flags[PIVOT_ROOT] ) {
					case PW_OFF:
						break;

					case PW_DIRECT:
					case PW_AUTO:
					case PW_AUTORO:
						if ( umount2 ( "old_root", MNT_DETACH ) ) {
							error ( "Got error while umount2(\"old_root\", MNT_DETACH)" );
							ret = errno;
						}

						break;
				}
			}

#endif
		}
	}

	if ( ctx_p->statusfile != NULL ) {
		debug ( 1, "Trying to open the status file for writing." );
		main_statusfile_f = fopen ( ctx_p->statusfile, "w" );

		if ( main_statusfile_f != NULL ) {
			uid_t uid = ctx_p->flags[UID] ? ctx_p->uid : getuid();
			gid_t gid = ctx_p->flags[GID] ? ctx_p->gid : getgid();
			debug ( 1, "Changing owner of the status file to %u:%u", uid, gid );

			if ( fchown ( fileno ( main_statusfile_f ), uid, gid ) )
				warning ( "Cannot fchown(%u -> \"%s\", %u, %u)",
				          fileno ( main_statusfile_f ), ctx_p->statusfile, uid, gid );

			main_status_update ( ctx_p );
		}
	}

#ifdef CAPABILITIES_SUPPORT
	debug ( 1, "Preserving Linux capabilities" );

	// Tell kernel not clear capabilities when dropping root
	if ( prctl ( PR_SET_KEEPCAPS, 1 ) < 0 ) {
		error ( "Cannot prctl(PR_SET_KEEPCAPS, 1) to preserve capabilities" );
		ret = errno;
	}

#endif
#ifdef CGROUP_SUPPORT

	if ( ctx_p->flags[FORBIDDEVICES] ) {
		error_on ( clsync_cgroup_init ( ctx_p ) );
		error_on ( clsync_cgroup_forbid_extra_devices() );
		error_on ( clsync_cgroup_attach ( ctx_p ) );
	}

#endif
	nret = main_rehash ( ctx_p );

	if ( nret )
		ret = nret;

	if ( ctx_p->flags[GID] ) {
		int rc;
		debug ( 3, "Trying to drop effective gid to %i", ctx_p->gid );
		rc = setegid ( ctx_p->gid );

		if ( rc && ( ctx_p->flags[GID] != UGID_PRESERVE ) ) {
			error ( "Cannot setegid(%u)", ctx_p->gid );
			ret = errno;
		}
	}

	if ( ctx_p->flags[UID] ) {
		int rc;
		debug ( 3, "Trying to drop effective uid to %i", ctx_p->uid );
		rc = seteuid ( ctx_p->uid );

		if ( rc && ( ctx_p->flags[UID] != UGID_PRESERVE ) ) {
			error ( "Cannot seteuid(%u)", ctx_p->uid );
			ret = errno;
		}
	}

	if ( main_statusfile_f == NULL && ctx_p->statusfile != NULL ) {
		debug ( 1, "Trying to open the status file for writing (after setuid()/setgid())." );
		main_statusfile_f = fopen ( ctx_p->statusfile, "w" );

		if ( main_statusfile_f == NULL ) {
			error ( "Cannot open file \"%s\" for writing.",
			        ctx_p->statusfile );
			ret = errno;
		}
	}

	debug ( 1, "%s [%s] (%p) -> %s [%s] (%p)", ctx_p->watchdir, ctx_p->watchdirwslash, ctx_p->watchdirwslash, ctx_p->destdir ? ctx_p->destdir : "", ctx_p->destdirwslash ? ctx_p->destdirwslash : "", ctx_p->destdirwslash );
	{
		int rc = ctx_check ( ctx_p );

		if ( !ret ) ret = rc;
	}

	if (
	    ( ctx_p->listoutdir == NULL ) &&
	    (
	        ctx_p->synchandler_argf &
	        (
	            SHFL_INCLUDE_LIST_PATH |
	            SHFL_EXCLUDE_LIST_PATH
	        )
	    )
	) {
		// Use $TMPDIR as the temp directory, fall back to /tmp
		char *tempdir = getenv ( "TMPDIR" );
		if ( !tempdir )
			tempdir = TMPDIR_PATH;
		const char *tempsuff = TMPDIR_TEMPLATE;
		size_t tempdir_len = strlen(tempdir);
		size_t tempsuff_len = strlen(tempsuff);

		// template = "$tempdir$tempsuff"
		char *template = xmalloc(tempdir_len + tempsuff_len + 1);
		memcpy ( template, tempdir, tempdir_len);
		memcpy ( template + tempdir_len, tempsuff, tempsuff_len);
		template[tempdir_len + tempsuff_len] = 0;

		ctx_p->listoutdir = mkdtemp ( template );

		if ( ctx_p->listoutdir == NULL ) {
			ret = errno;
			error ( "Cannot create temporary dir for list files by template '%s'", template );
		} else
			rm_listoutdir = 2;
	}

	if ( ctx_p->listoutdir != NULL ) {
		struct stat st = {0};
		errno = 0;

		if ( stat ( ctx_p->listoutdir, &st ) ) {
			if ( errno == ENOENT ) {
				warning ( "Directory \"%s\" doesn't exist. Creating it.", ctx_p->listoutdir );
				errno = 0;

				if ( mkdir ( ctx_p->listoutdir, S_IRWXU ) ) {
					error ( "Cannot create directory \"%s\".", ctx_p->listoutdir );
					ret = errno;
				} else
					rm_listoutdir = 1;
			} else {
				error ( "Got error while stat() on \"%s\".", ctx_p->listoutdir );
				ret = errno;
			}
		}

		if ( !errno )
			if ( st.st_mode & ( S_IRWXG | S_IRWXO ) ) {
#ifdef PARANOID
				ret = errno = EACCES;
				error ( "Insecure: Others have access to directory \"%s\". Exit.", ctx_p->listoutdir );
#else
				warning ( "Insecure: Others have access to directory \"%s\".", ctx_p->listoutdir );
#endif
			}
	}

	if ( ctx_p->flags[BACKGROUND] ) {
		nret = becomedaemon();

		if ( nret )
			ret = nret;
	}

	if ( ctx_p->pidfile != NULL ) {
		debug ( 2, "Trying to open the pidfile \"%s\"", ctx_p->pidfile );
		pid_t pid = getpid();
		FILE *pidfile = fopen ( ctx_p->pidfile, "w" );

		if ( pidfile == NULL ) {
			// If error
			if ( errno == EACCES ) {
				int fd;
				uid_t euid = geteuid();
				gid_t egid = getegid();
				debug ( 1, "Don't have permissions to open file \"%s\". Trying seteuid(0)+open()+fchown()+close()+seteuid(%i)", ctx_p->pidfile, euid );
				errno  = 0;

				if ( !errno ) SAFE ( seteuid ( 0 ),							ret = errno );

				if ( !errno ) SAFE ( ( fd = open ( ctx_p->pidfile, O_CREAT | O_WRONLY, 0644 ) ) == -1,	ret = errno );

				if ( !errno ) SAFE ( fchown ( fd, euid, egid ),					ret = errno );

				if ( !errno ) SAFE ( close ( fd ),							ret = errno );

				if ( !errno ) SAFE ( seteuid ( euid ),						ret = errno );

				pidfile = fopen ( ctx_p->pidfile, "w" );
			}

			if ( pidfile == NULL ) {
				error ( "Cannot open file \"%s\" to write a pid there",
				        ctx_p->pidfile );
				ret = errno;
			}
		}

		if ( pidfile != NULL ) {
			if ( fprintf ( pidfile, "%u", pid ) < 0 ) {
				error ( "Cannot write pid into file \"%s\"",
				        ctx_p->pidfile );
				ret = errno;
			}

			fclose ( pidfile );
		}
	}

	debug ( 3, "Current errno is %i.", ret );

	// == RUNNING ==
	if ( ret == 0 )
		ret = sync_run ( ctx_p );

	// == /RUNNING ==

	if ( ctx_p->pidfile != NULL ) {
		if ( unlink ( ctx_p->pidfile ) ) {
			FILE *pidfile;
			debug ( 1, "Cannot unlink pidfile \"%s\": %s. Just truncating the file.",
			        ctx_p->pidfile, strerror ( errno ) );
			SAFE ( ( pidfile = fopen ( ctx_p->pidfile, "w" ) ) == NULL,	ret = errno );

			if ( pidfile != NULL )
				fclose ( pidfile );
		}
	}

	if ( ctx_p->statusfile != NULL ) {
		if ( main_statusfile_f != NULL )
			if ( fclose ( main_statusfile_f ) ) {
				error ( "Cannot close file \"%s\".",
				        ctx_p->statusfile );
				ret = errno;
			}

		if ( unlink ( ctx_p->statusfile ) ) {
			error ( "Cannot unlink status file \"%s\"",
			        ctx_p->statusfile );
			ret = errno;
		}
	}

	if ( ( !ctx_p->flags[DONTUNLINK] ) && ( ctx_p->listoutdir != NULL ) && rm_listoutdir ) {
		debug ( 2, "rmdir(\"%s\")", ctx_p->listoutdir );

		if ( rmdir ( ctx_p->listoutdir ) )
			error ( "Cannot rmdir(\"%s\")", ctx_p->listoutdir );

		if ( rm_listoutdir == 2 )
			free ( ctx_p->listoutdir );
	}

	/*
		if (ctx_p->flags[PIVOT_ROOT] == PW_AUTO || ctx_p->flags[PIVOT_ROOT] == PW_AUTORO) {
			umount2("/", MNT_DETACH);
			// DELETE THE DIRECTORY
		}
	*/
	main_cleanup ( ctx_p );

	if ( ctx_p->watchdirwslashsize )
		free ( ctx_p->watchdirwslash );

	if ( ctx_p->destdirwslashsize )
		free ( ctx_p->destdirwslash );

	if ( ctx_p->rulfpathsize )
		free ( ctx_p->rulfpath );

	error_deinit();
	ctx_cleanup ( ctx_p );
	debug ( 1, "finished, exitcode: %i: %s.", ret, strerror ( ret ) );
	free ( ctx_p );
#ifndef __FreeBSD__	// Hanging up with 100%CPU eating, https://github.com/clsync/clsync/issues/97
	SAFE ( posixhacks_deinit(), errno = ret = _SAFE_rc );
#endif
	return ret;
}


