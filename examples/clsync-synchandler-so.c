
#include <clsync/common.h>

options_t *options_p = NULL;
indexes_t *indexes_p = NULL;

char **argv      = NULL;
size_t argv_size = 0;

int clsyncapi_init(options_t *_options_p, indexes_t *_indexes_p) {
	printf("clsyncapi_init(): Hello world!\n");

	options_p = _options_p;
	indexes_p = _indexes_p;

	if(options_p->destdir == NULL) {
		fprintf(stderr, "Error: clsyncapi_init(): dest-dir is not set.\n");
		return EINVAL;
	}

	argv_size = ALLOC_PORTION;
	argv      = malloc(argv_size * sizeof(char *));

	argv[0] = "/bin/cp";
	argv[1] = "-pf";

	return 0;
}

int clsyncapi_sync(int n, api_eventinfo_t *ei) {
	printf("clsyncapi_sync(): n == %i\n", n, ei->path);

	if(n+3 > argv_size) {
		argv_size = n+3 + ALLOC_PORTION;
		argv      = realloc(argv, argv_size * sizeof(char *));
	}

	int argv_i=2;
	int ei_i=0;
	while(ei_i < n) {
		if(ei[ei_i].path_len > 0) {
			printf("clsyncapi_sync(): ei[%i].path == \"%s\" (len == %i)\n", ei_i, ei[ei_i].path, ei[ei_i].path_len);
			argv[argv_i++] = (char *)ei[ei_i].path;
		}
		ei_i++;
	}

	if(argv_i == 2) {
		printf("clsyncapi_sync(): Nothing to sync.\n");
		return 0;
	}

	argv[argv_i++] = options_p->destdir;
	argv[argv_i++] = NULL;

	// Forking
	int pid = fork();
	switch(pid) {
		case -1: 
			fprintf(stderr, "Error: Cannot fork(): %s (errno: %i).\n", strerror(errno), errno);
			return errno;
		case  0:
			chdir(options_p->watchdir);
			execvp(argv[0], (char *const *)argv);
			return errno;
	}

	int status;
	if(waitpid(pid, &status, 0) != pid) {
		fprintf(stderr, "Error: Cannot waitid(): %s (errno: %i).\n", strerror(errno), errno);
		return errno;
	}

	// Return
	int exitcode = WEXITSTATUS(status);
	printf("clsyncapi_sync(): Execution completed with exitcode %i.\n", exitcode);

	return exitcode;
}

int clsyncapi_deinit() {
	printf("clsyncapi_deinit(): Goodbye cruel world!\n");

	if(argv != NULL)
		free(argv);

	return 0;
}

