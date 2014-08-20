/*
    clsync - file tree sync utility based on inotify/kqueue/bsm

    Copyright (C) 2014  Dmitry Yu Okunev <dyokunev@ut.mephi.ru> 0x8E30679C

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "common.h"
#include "error.h"
#include <libcgroup.h>

static struct cgroup *cgroup = NULL;

int clsync_cgroup_init(ctx_t *ctx_p) {
	debug(2, "cgroup_name == \"%s\"", ctx_p->cg_groupname);

	SAFE( cgroup_init(),							return -1; );
	SAFE( (cgroup = cgroup_new_cgroup(ctx_p->cg_groupname)) == NULL,	return -1; );

	return 0;
}

int clsync_cgroup_forbid_extra_devices() {
	int rc;
	char *allowed_devices[] = CG_ALLOWED_DEVICES, **allowed_device_i;

	/*
	 * Unfortunately, libcgroup doesn't allow multiple values for one key, and cgroups doesn't allow multiple devices for one set. So I was been have to write this hack. It adds character '/' to start of "devices.allow" for every new entry. So libclsync thinks that it's different keys, "/sys/fs/cgroup/devices/clsync/123/devices.allow" == "/sys/fs/cgroup/devices/clsync/123//devices.allow".
	 */

	char control_name_buf[BUFSIZ+BUFSIZ]={[0 ... BUFSIZ-1] = '/', 'd', 'e', 'v', 'i', 'c', 'e', 's', '.', 'a', 'l', 'l', 'o', 'w'}, *control_name = &control_name_buf[BUFSIZ];
	debug(2, "");

	struct cgroup_controller *cgc;

	SAFE( (cgc = cgroup_add_controller(cgroup, "devices")) == NULL,	return -1; );

	debug(8, "Deny device: \"a\"");
	SAFE( cgroup_add_value_string(cgc, "devices.deny", "a"),	return -1; );
	allowed_device_i = allowed_devices;
	while (*allowed_device_i != NULL) {

		critical_on (control_name < control_name_buf);

		debug(8, "Allow device: \"%s\" (\"%s\" = \"%s\")", *allowed_device_i, control_name, *allowed_device_i);
		SAFE( cgroup_add_value_string(cgc, control_name, *allowed_device_i),return -1; );
		control_name--;
		allowed_device_i++;
	}

	if ((rc=cgroup_create_cgroup(cgroup, 1))) {
		error("Got error while cgroup_create_cgroup(): %s", cgroup_strerror(rc));
		return -1;
	}

	return 0;
}

int clsync_cgroup_attach(ctx_t *ctx_p) {
	int rc;
	debug(2, "");

	if ((rc=cgroup_attach_task_pid(cgroup, ctx_p->pid))) {
		error("Got error while cgroup_attach_task_pid(): %s", cgroup_strerror(rc));
		return -1;
	}

	return 0;
}

int clsync_cgroup_deinit(ctx_t *ctx_p) {
	debug(2, "");

	setuid(0);

	error_on(cgroup_delete_cgroup_ext(cgroup, CGFLAG_DELETE_IGNORE_MIGRATION | CGFLAG_DELETE_RECURSIVE));
	cgroup_free(&cgroup);

	if (ctx_p->uid != 0)
		setuid(ctx_p->uid);

	return 0;
}

