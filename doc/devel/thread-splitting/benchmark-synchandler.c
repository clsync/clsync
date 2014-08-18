
#include <stdlib.h>
#include <errno.h>

// Required header:
#include <clsync/clsync.h>

// Optional headers:
#include <clsync/configuration.h>
#include <clsync/error.h>
#include <clsync/ctx.h>

struct ctx *ctx_p         = NULL;

// Optional function, you can erase it.
int clsyncapi_init(struct ctx *_ctx_p, struct indexes *_indexes_p) {
	debug(1, "Hello world!");

	ctx_p = _ctx_p;

	return 0;
}

int clsyncapi_rsync(const char *inclistfile, const char *exclistfile) {
	debug(1, "clsyncapi_rsync()");
	return 0;
}

int clsyncapi_sync(int n, api_eventinfo_t *ei) {
	debug(1, "clsyncapi_sync(): n == %i", n);
	return 0;
}

int clsyncapi_deinit() {
	debug(1, "Goodbye cruel world!");
	return 0;
}

