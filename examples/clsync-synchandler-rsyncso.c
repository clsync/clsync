
#include <stdlib.h>
#include <errno.h>

// Required header:
#include <clsync/clsync.h>

// Optional headers:
#include <clsync/configuration.h>
#include <clsync/output.h>
#include <clsync/options.h>

struct options *options_p = NULL;
struct indexes *indexes_p = NULL;

char   *argv[10]   = {NULL};

// Optional function, you can erase it.
int clsyncapi_init(struct options *_options_p, struct indexes *_indexes_p) {
	printf_d("clsyncapi_init(): Hello world!\n");

	options_p = _options_p;
	indexes_p = _indexes_p;

	if(options_p->destdir == NULL) {
		printf_e("Error: clsyncapi_init(): dest-dir is not set.\n");
		return EINVAL;
	}

	if(options_p->flags[RSYNCPREFERINCLUDE]) {
		printf_e("Error: clsync-synchandler-rsyncso.so cannot be used in conjunction with \"--rsync-prefer-include\" option.\n");
		return EINVAL;
	}

	argv[0] = "/usr/bin/rsync";
	argv[1] = options_p->flags[DEBUG] >= 4 ? "-avvvvvvH" : "-aH";
	argv[2] = "--exclude-from";
	argv[4] = "--include-from";
	argv[6] = "--exclude=*";
	argv[7] = options_p->watchdirwslash;
	argv[8] = options_p->destdirwslash;

	return 0;
}

int clsyncapi_rsync(const char *inclistfile, const char *exclistfile) {
	printf_d("clsyncapi_rsync(): inclistfile == \"%s\"; exclistfile == \"%s\"\n", inclistfile, exclistfile);

	argv[3] = (char *)exclistfile;
	argv[5] = (char *)inclistfile;

	if(options_p->flags[DEBUG] >= 3) {
		int i=0;
		while(argv[i] != NULL) {
			printf_ddd("Debug3: clsyncapi_rsync(): argv[%i] == \"%s\"\n", i, argv[i]);
			i++;
		}
	}

	// Forking
	int pid = clsyncapi_fork();
	switch(pid) {
		case -1: 
			printf_e("Error: Cannot fork(): %s (errno: %i).\n", strerror(errno), errno);
			return errno;
		case  0:
			execvp(argv[0], (char *const *)argv);
			return errno;
	}

	int status;
	if(waitpid(pid, &status, 0) != pid) {
		printf_e("Error: Cannot waitid(): %s (errno: %i).\n", strerror(errno), errno);
		return errno;
	}

	// Return
	int exitcode = WEXITSTATUS(status);
	printf_d("clsyncapi_rsync(): Execution completed with exitcode %i.\n", exitcode);

	return exitcode;
}

// Optional function, you can erase it.
int clsyncapi_deinit() {
	printf_d("clsyncapi_deinit(): Goodbye cruel world!\n");

	return 0;
}

