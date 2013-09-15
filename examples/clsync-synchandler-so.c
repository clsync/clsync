
#include <clsync/common.h>

options_t *options_p = NULL;
indexes_t *indexes_p = NULL;

int clsyncapi_init(options_t *_options_p, indexes_t *_indexes_p) {
	printf("clsyncapi_init(): Hello world!\n");

	options_p = _options_p;
	indexes_p = _indexes_p;

	return 0;
}

int clsyncapi_sync(int n, api_eventinfo_t *ei) {
	printf("clsyncapi_sync(): n == %i;\tei->path == \"%s\"\n", n, ei->path);

	return 0;
}

int clsyncapi_deinit() {
	printf("clsyncapi_deinit(): Hello world!\n");

	return 0;
}

