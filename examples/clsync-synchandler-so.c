
#include <stdlib.h>
#include <errno.h>

// Required header:
#include <clsync/compilerflags.h>
#include <clsync/clsync.h>

// Optional headers:
#include <clsync/configuration.h>
#include <clsync/error.h>
#include <clsync/ctx.h>

struct ctx *ctx_p = NULL;
struct indexes *indexes_p = NULL;

char **argv      = NULL;
size_t argv_size = 0;

// Optional function, you can erase it.
int clsyncapi_init(struct ctx *_ctx_p, struct indexes *_indexes_p) {
	debug(1, "Hello world! API version is %i", clsyncapi_getapiversion());

	ctx_p = _ctx_p;
	indexes_p = _indexes_p;

	if(ctx_p->destdir == NULL) {
		errno = EINVAL;
		error("destination-dir is not set.");
		return EINVAL;
	}

	if(ctx_p->flags[THREADING]) {
		errno = EINVAL;
		error("this handler is not pthread-safe.");
		return EINVAL;
	}

	argv_size = ALLOC_PORTION;
	argv      = malloc(argv_size * sizeof(char *));

	argv[0] = "/bin/cp";
	argv[1] = "-pf";

	return 0;
}

int clsyncapi_sync(int n, api_eventinfo_t *ei) {
	debug(1, "clsyncapi_sync(): n == %i", n, ei->path);

	if(n+4 > argv_size) {	// "/bin/cp" + "-pf" + n paths + ctx_p->destdir + NULL  -->  n+4
		argv_size = n+4 + ALLOC_PORTION;
		argv      = realloc(argv, argv_size * sizeof(char *));
	}

	int argv_i=2;
	int ei_i=0;
	while(ei_i < n) {
		if(ei[ei_i].path_len > 0) {
			debug(1, "ei[%i].path == \"%s\" (len == %i, type_o == %i, type_n == %i)",
				ei_i, ei[ei_i].path, ei[ei_i].path_len, ei[ei_i].objtype_old, ei[ei_i].objtype_new);
			argv[argv_i++] = (char *)ei[ei_i].path;
		}
		ei_i++;
	}

	if(argv_i == 2) {
		debug(1, "Nothing to sync.");
		return 0;
	}

	argv[argv_i++] = ctx_p->destdir;
	argv[argv_i++] = NULL;

	// Forking
	int pid = clsyncapi_fork(ctx_p);
	switch(pid) {
		case -1: 
			error("Cannot fork().");
			return errno;
		case  0:
			chdir(ctx_p->watchdir);
			execvp(argv[0], (char *const *)argv);
			return errno;
	}

	int status;
	if(waitpid(pid, &status, 0) != pid) {
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

	if(argv != NULL)
		free(argv);

	return 0;
}

