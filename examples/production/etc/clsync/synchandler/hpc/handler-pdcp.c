/* This program is free software and is distributed by the terms of
 * GPL v3 license. Author: Andrew Savchenko <bircoph@gmail.com>
 * Based on clsync example. */

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <clsync/clsync.h>
#include <clsync/configuration.h>
#include <clsync/malloc.h>
#include <clsync/error.h>
#include <clsync/ctx.h>

struct ctx *ctx_p;

int clsyncapi_init(struct ctx *_ctx_p, struct indexes *_indexes_p)
{
    if (clsyncapi_getapiversion() != CLSYNC_API_VERSION) {
        error("handler: API version mistmatch: compiled for %i, but have %i",
            CLSYNC_API_VERSION, clsyncapi_getapiversion());
        return -1;
    }

    ctx_p = _ctx_p;

    debug(1, "handler: Initialization OK");
    return 0;
}

int clsyncapi_sync(int n, api_eventinfo_t *ei)
{
    size_t argv_size;
    char **argv;
    int exitcode;

    debug(1, "handler: Sync requested for %i objects.", n);

    argv_size = n+4; // "pdsh" + "-a" + n + "todir" + NULL
    argv = xmalloc(argv_size * sizeof(char *));
    argv[0] = "/usr/bin/pdcp";
    argv[1] = "-a";

    int i=2;
    for (int j=0; j < n; j++) {
        if(ei[j].path_len)
            argv[i++] = (char*)ei[j].path;
    }

    if(i == 2) {
        debug(1, "handler: Nothing to sync.");
        exitcode = 0;
        goto cleanup;
    }

    argv[i++] = ctx_p->watchdir;
    argv[i++] = NULL;

    // Forking
    int pid = clsyncapi_fork(ctx_p);
    switch(pid) {
        case -1:
            error("handler: Can't fork()");
            exitcode = errno;
            goto cleanup;
        case  0:
            if (chdir(ctx_p->watchdir) == -1) {
                error("handler: Can't chdir()");
                exit(errno);
            }
            execv(argv[0], argv);
            error("handler: Can't exec()");
            exit(errno);
    }

    int status;
    if(waitpid(pid, &status, 0) != pid) {
        error("handler: Can't waitid()");
        exitcode = errno;
        goto cleanup;
    }

    // Return
    exitcode = WEXITSTATUS(status);
cleanup:
    free(argv);
    return exitcode; // do not die on errors
}
