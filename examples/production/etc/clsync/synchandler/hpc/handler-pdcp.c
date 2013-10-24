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
#include <clsync/output.h>
#include <clsync/options.h>

struct options *options_p;

int clsyncapi_init(struct options *_options_p, struct indexes *_indexes_p)
{
    if (clsyncapi_getapiversion() != CLSYNC_API_VERSION) {
        printf_e("handler: API version mistmatch: compiled for %i, but have %i",
            CLSYNC_API_VERSION, clsyncapi_getapiversion());
        return -1;
    }

    options_p = _options_p;

    printf_d("handler: Initialization OK\n");
    return 0;
}

int clsyncapi_sync(int n, api_eventinfo_t *ei)
{
    size_t argv_size;
    char **argv;
    int exitcode;

    printf_d("handler: Sync requested for %i objects.\n", n);

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
        printf_d("handler: Nothing to sync.\n");
        exitcode = 0;
        goto cleanup;
    }

    argv[i++] = options_p->watchdir;
    argv[i++] = NULL;

    // Forking
    int pid = clsyncapi_fork(options_p);
    switch(pid) {
        case -1:
            printf_e("handler: Can't fork(): %s\n", strerror(errno));
            exitcode = errno;
            goto cleanup;
        case  0:
            if (chdir(options_p->watchdir) == -1) {
                printf_e("handler: Can't chdir(): %s\n", strerror(errno));
                exit(errno);
            }
            execv(argv[0], argv);
            printf_e("handler: Can't exec(): %s\n", strerror(errno));
            exit(errno);
    }

    int status;
    if(waitpid(pid, &status, 0) != pid) {
        printf_e("handler: Can't waitid(): %s\n", strerror(errno));
        exitcode = errno;
        goto cleanup;
    }

    // Return
    exitcode = WEXITSTATUS(status);
cleanup:
    free(argv);
    return exitcode; // do not die on errors
}
