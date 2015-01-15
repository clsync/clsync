
#include <stdlib.h>
#include <errno.h>

// Required header:
#include <clsync/compilerflags.h>
#include <clsync/clsync.h>

// Optional headers:
#include <clsync/configuration.h>
#include <clsync/error.h>
#include <clsync/ctx.h>

static struct ctx *ctx_p         = NULL;
static struct indexes *indexes_p = NULL;

static const char *argv[11]   = {NULL};

// Optional function, you can erase it.
int clsyncapi_init(struct ctx *_ctx_p, struct indexes *_indexes_p) {
	debug(1, "Hello world!");

	ctx_p = _ctx_p;
	indexes_p = _indexes_p;

	if (ctx_p->destdir == NULL) {
		error("dest-dir is not set.");
		return EINVAL;
	}

	if (ctx_p->flags[RSYNCPREFERINCLUDE]) {
		error("clsync-synchandler-rsyncso.so cannot be used in conjunction with \"--rsync-prefer-include\" option.");
		return EINVAL;
	}

	if (ctx_p->flags[THREADING]) {
		error("this handler is not pthread-safe.");
		return EINVAL;
	}

	argv[0] = "/usr/bin/rsync";
	argv[1] = ctx_p->flags[DEBUG] >= 4 ? "-avvvvvvH" : "-aH";
	argv[2] = "--exclude-from";
	argv[4] = "--include-from";
	argv[6] = "--exclude=*";
	argv[7] = "--delete-before";
	argv[8] = ctx_p->watchdirwslash;
	argv[9] = ctx_p->destdirwslash;

	return 0;
}

int clsyncapi_rsync(const char *inclistfile, const char *exclistfile) {
	debug(1, "inclistfile == \"%s\"; exclistfile == \"%s\"", inclistfile, exclistfile);

	argv[3] = exclistfile;
	argv[5] = inclistfile;

	if (ctx_p->flags[DEBUG] >= 3) {
		int i=0;
		while (argv[i] != NULL) {
			debug(3, "argv[%i] == \"%s\"", i, argv[i]);
			i++;
		}
	}

	// Forking
	int pid = clsyncapi_fork(ctx_p);
	switch (pid) {
		case -1: 
			error("Cannot fork().");
			return errno;
		case  0:
			execvp(argv[0], (char *const *)argv);
			return errno;
	}

	int status;
	if (waitpid(pid, &status, 0) != pid) {
		error("Cannot waitid().");
		return errno;
	}

	// Return
	int exitcode = WEXITSTATUS(status);
	debug(1, "Execution completed with exitcode %i.", exitcode);

	return exitcode;
}

// Optional function, you can erase it.
int clsyncapi_deinit() {
	debug(1, "Goodbye cruel world!");

	return 0;
}

