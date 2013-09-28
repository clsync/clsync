
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

char **argv      = NULL;
size_t argv_size = 0;

// Optional function, you can erase it.
int clsyncapi_init(struct options *_options_p, struct indexes *_indexes_p) {
	printf_d("clsyncapi_init(): Hello world! API version is %i\n", clsyncapi_getapiversion());

	options_p = _options_p;
	indexes_p = _indexes_p;

	if(options_p->destdir == NULL) {
		printf_e("Error: clsyncapi_init(): dest-dir is not set.\n");
		return EINVAL;
	}

	argv_size = ALLOC_PORTION;
	argv      = malloc(argv_size * sizeof(char *));

	argv[0] = "/bin/cp";
	argv[1] = "-pf";

	return 0;
}

int clsyncapi_sync(int n, api_eventinfo_t *ei) {
	printf_d("clsyncapi_sync(): n == %i\n", n, ei->path);

	if(n+4 > argv_size) {	// "/bin/cp" + "-pf" + n paths + options_p->destdir + NULL  -->  n+4
		argv_size = n+4 + ALLOC_PORTION;
		argv      = realloc(argv, argv_size * sizeof(char *));
	}

	int argv_i=2;
	int ei_i=0;
	while(ei_i < n) {
		if(ei[ei_i].path_len > 0) {
			printf_d("clsyncapi_sync(): ei[%i].path == \"%s\" (len == %i, type_o == %i, type_n == %i)\n",
				ei_i, ei[ei_i].path, ei[ei_i].path_len, ei[ei_i].objtype_old, ei[ei_i].objtype_new);
			argv[argv_i++] = (char *)ei[ei_i].path;
		}
		ei_i++;
	}

	if(argv_i == 2) {
		printf_d("clsyncapi_sync(): Nothing to sync.\n");
		return 0;
	}

	argv[argv_i++] = options_p->destdir;
	argv[argv_i++] = NULL;

	// Forking
	int pid = clsyncapi_fork();
	switch(pid) {
		case -1: 
			printf_e("Error: Cannot fork(): %s (errno: %i).\n", strerror(errno), errno);
			return errno;
		case  0:
			chdir(options_p->watchdir);
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
	printf_d("clsyncapi_sync(): Execution completed with exitcode %i.\n", exitcode);

	return exitcode;
}

// Optional function, you can erase it.
int clsyncapi_deinit() {
	printf_d("clsyncapi_deinit(): Goodbye cruel world!\n");

	if(argv != NULL)
		free(argv);

	return 0;
}

