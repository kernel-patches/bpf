// SPDX-License-Identifier: GPL-2.0-only

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <bpf/bpf.h>

#include "unpriv_helpers.h"
#include "detect_mitigations_off.skel.h"

static int unpriv_disabled_cached;
static bool cache_valid;

static int get_mitigations_off(void)
{
	struct detect_mitigations_off *obj = NULL;
	LIBBPF_OPTS(bpf_test_run_opts, run_opts);
	int err;

	obj = detect_mitigations_off__open_and_load();
	if (!obj) {
		err = -errno;
		fprintf(stderr, "%s: can't load detector program: %s\n",
			__FUNCTION__, strerror(errno));
		goto out;
	}
	err = bpf_prog_test_run_opts(bpf_program__fd(obj->progs.cpu_mitigations_off), &run_opts);
	if (err < 0) {
		err = -errno;
		fprintf(stderr, "%s: can't run detector program: %s\n",
			__FUNCTION__, strerror(errno));
		goto out;
	}
	return !!run_opts.retval;

out:
	detect_mitigations_off__destroy(obj);
	return err;
}

int get_unpriv_disabled(void)
{
	bool disabled;
	char buf[2];
	FILE *fd;

	if (cache_valid)
		return unpriv_disabled_cached;

	fd = fopen("/proc/sys/" UNPRIV_SYSCTL, "r");
	if (fd) {
		disabled = (fgets(buf, 2, fd) == buf && atoi(buf));
		fclose(fd);
	} else {
		perror("fopen /proc/sys/" UNPRIV_SYSCTL);
		disabled = true;
	}

	unpriv_disabled_cached = disabled ? true : get_mitigations_off();
	cache_valid = true;
	return unpriv_disabled_cached;
}
