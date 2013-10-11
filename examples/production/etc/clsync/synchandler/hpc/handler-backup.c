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

#define ARGV_SIZE 32

struct options *options_p;
const char *const decrement = "decrement";
size_t decrement_size;

int clsyncapi_init(struct options *_options_p, struct indexes *_indexes_p)
{
    if (clsyncapi_getapiversion() != CLSYNC_API_VERSION) {
        printf_e("handler: API version mistmatch: compiled for %i, but have %i",
            CLSYNC_API_VERSION, clsyncapi_getapiversion());
        return -1;
    }

    decrement_size = strlen(decrement);
    options_p = _options_p;

    if(!options_p->destdir) {
        printf_e("handler: dest-dir is not set, aborting\n");
        return EINVAL;
    }

    if(!options_p->destdir) {
        printf_e("handler: dest-dir is not set, aborting\n");
        return EINVAL;
    }

    printf_d("handler: Initialization OK\n");
    return 0;
}

/* build backup directory name as dirname(destdir)/decrement */
static inline char* get_decrement_name(const char* path)
{
    char *sep, *ret;
    size_t size;    // length of "dirname(destdir)/"
    sep = strrchr(path,'/');

    if (!sep)
        ret = strdup(decrement);
    else {
        size = sep - path + 1;
        ret = xmalloc(sizeof(char)*size + decrement_size);
        memcpy(ret, path, size);
        memcpy(ret+size, decrement, decrement_size);
    }
    return ret;
}

int clsyncapi_rsync(const char *incl_file, const char *excl_file)
{
    char *argv[ARGV_SIZE];
    size_t back_idx; // remember string to free
    int exitcode;

    printf_d("handler: sync started for include file %s, exclude file %s\n",
        incl_file, excl_file);

    /* form rsync arguments */
    int i = 0;
    argv[i++] = "/usr/bin/rsync";
    if (options_p->flags[DEBUG] >= 4)
        argv[i++] = "-vvvvv";
    argv[i++] = "--archive";
    argv[i++] = "--hard-links";
    argv[i++] = "--acls";
    argv[i++] = "--sparse";
    argv[i++] = "--del";
    argv[i++] = "--partial-dir=.rsync-partial";
    argv[i++] = "--backup";
    argv[i++] = "--backup-dir";
    back_idx = i;
    argv[i++] = get_decrement_name(options_p->destdir);
    if (!options_p->flags[RSYNCPREFERINCLUDE]) {
        argv[i++] = "--exclude-from";
        argv[i++] = (char*)excl_file;
    }
    argv[i++] = "--include-from";
    argv[i++] = (char*)incl_file;
    argv[i++] = "--exclude=*";
    argv[i++] = options_p->watchdirwslash;
    argv[i++] = options_p->destdirwslash;
    argv[i++] = NULL;

    // Forking
    int pid = clsyncapi_fork(options_p);
    switch(pid) {
        case -1:
            printf_e("handler: Can't fork(): %s\n", strerror(errno));
            exitcode = errno;
            goto cleanup;
        case  0:
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
    free(argv[back_idx]);
    return exitcode;
}
