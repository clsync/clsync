
#include <stdlib.h>
#include <errno.h>

// Required header:
#include <clsync/clsync.h>

// Optional headers:
#include <clsync/configuration.h>
#include <clsync/error.h>
#include <clsync/ctx.h>

struct ctx *ctx_p         = NULL;

int clsyncapi_init(struct ctx *_ctx_p, struct indexes *_indexes_p) {
	ctx_p = _ctx_p;
	return 0;
}

int clsyncapi_rsync(const char *inclistfile, const char *exclistfile) {
	return 0;
}

int clsyncapi_sync(int n, api_eventinfo_t *ei) {
	return 0;
}

int clsyncapi_deinit() {
	return 0;
}

