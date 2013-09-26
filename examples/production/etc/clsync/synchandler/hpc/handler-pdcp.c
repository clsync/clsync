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
#include <clsync/output.h>
#include <clsync/options.h>

struct options *options_p;
struct indexes *indexes_p;

char **argv;
size_t argv_size = 0;

void *xmalloc(size_t size);
void *xrealloc(void *oldptr, size_t size);

int clsyncapi_init(struct options *_options_p, struct indexes *_indexes_p)
{
    options_p = _options_p;
    indexes_p = _indexes_p;

    argv_size = 10;
    argv = xmalloc(argv_size * sizeof(char *));
    argv[0] = "/usr/bin/pdcp";
    argv[1] = "-a";

    printf_d("handler: Initialization OK\n");
    return 0;
}

int clsyncapi_sync(int n, api_eventinfo_t *ei)
{
    printf_d("handler: Sync requested for %i objects.\n", n);

    if(n+4 > argv_size) {    // "pdsh" + "-a" + n + "todir" + NULL
        argv_size *= 2;
        argv = xrealloc(argv, argv_size * sizeof(char *));
    }

    int i=2;
    for (int j=0; j < n; j++) {
        if(ei[j].path_len)
            argv[i++] = (char*)ei[j].path;
    }

    if(i == 2) {
        printf_d("handler: Nothing to sync.\n");
        return 0;
    }

    argv[i++] = options_p->watchdir;
    argv[i++] = NULL;

    // Forking
    int pid = fork();
    switch(pid) {
        case -1: 
            printf_e("handler: Can't fork(): %s\n", strerror(errno));
            return errno;
        case  0:
            if (chdir(options_p->watchdir) == -1) {
                printf_e("handler: Can't chdir(): %s\n", strerror(errno));
                return errno;
            }
            execv(argv[0], argv);
            printf_e("handler: Can't exec(): %s\n", strerror(errno));
            return errno;
    }

    int status;
    if(waitpid(pid, &status, 0) != pid) {
        printf_e("handler: Can't waitid(): %s\n", strerror(errno));
        return errno;
    }

    // Return
    int exitcode = WEXITSTATUS(status);
    printf_d("handler: Execution completed with exitcode %i.\n", exitcode);

    return exitcode;
}
