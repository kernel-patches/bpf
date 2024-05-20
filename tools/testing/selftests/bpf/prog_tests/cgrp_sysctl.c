// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) Meta Platforms, Inc. and affiliates. */

#define SYSCTL_ROOT_PATH "/proc/sys/"
#define SYSCTL_NAME_LEN 128
#define RESERVED_PORTS_SYSCTL_NAME "net/ipv4/ip_local_reserved_ports"
#define RESERVED_PORTS_OVERRIDE_VALUE "31337"

#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <fcntl.h>

#include <sys/mount.h>

#include "test_progs.h"
#include "cgrp_sysctl.skel.h"

struct sysctl_test {
	const char *sysctl;
	int open_flags;
	const char *newval;
	const char *updval;
};

static void subtest(int cgroup_fd, struct cgrp_sysctl *skel, struct sysctl_test *test_data)
{
	int fd;

	fd = open(SYSCTL_ROOT_PATH RESERVED_PORTS_SYSCTL_NAME, test_data->open_flags | O_CLOEXEC);
	if (!ASSERT_GT(fd, 0, "sysctl-open"))
		return;

	if (test_data->open_flags == O_RDWR) {
		int wr_ret;

		wr_ret = write(fd, test_data->newval, strlen(test_data->newval));
		if (!ASSERT_GT(wr_ret, 0, "sysctl-write"))
			goto out;

		char buf[SYSCTL_NAME_LEN];
		char updval[SYSCTL_NAME_LEN];

		sprintf(updval, "%s\n", test_data->updval);
		if (!ASSERT_OK(lseek(fd, 0, SEEK_SET), "sysctl-seek"))
			goto out;
		if (!ASSERT_GT(read(fd, buf, sizeof(buf)), 0, "sysctl-read"))
			goto out;
		if (!ASSERT_OK(strncmp(buf, updval, strlen(updval)), "sysctl-updval"))
			goto out;
	}

out:
	close(fd);
}

void test_cgrp_sysctl(void)
{
	struct cgrp_sysctl *skel;
	int cgroup_fd;

	cgroup_fd = test__join_cgroup("/cgrp_sysctl");
	if (!ASSERT_GE(cgroup_fd, 0, "cg-create"))
		return;

	skel = cgrp_sysctl__open();
	if (!ASSERT_OK_PTR(skel, "skel-open"))
		goto close_cgroup;

	struct sysctl_test test_data;

	if (test__start_subtest("overwrite_success")) {
		test_data = (struct sysctl_test){
			.sysctl = RESERVED_PORTS_SYSCTL_NAME,
			.open_flags = O_RDWR,
			.newval = "22222",
			.updval = RESERVED_PORTS_OVERRIDE_VALUE,
		};
		memcpy(skel->rodata->sysctl_name, RESERVED_PORTS_SYSCTL_NAME,
		       sizeof(RESERVED_PORTS_SYSCTL_NAME));
		skel->rodata->name_len = sizeof(RESERVED_PORTS_SYSCTL_NAME);
		memcpy(skel->rodata->sysctl_updval, RESERVED_PORTS_OVERRIDE_VALUE,
		       sizeof(RESERVED_PORTS_OVERRIDE_VALUE));
		skel->rodata->updval_len = sizeof(RESERVED_PORTS_OVERRIDE_VALUE);
	}

	if (!ASSERT_OK(cgrp_sysctl__load(skel), "skel-load"))
		goto close_cgroup;

	skel->links.cgrp_sysctl_overwrite =
		bpf_program__attach_cgroup(skel->progs.cgrp_sysctl_overwrite, cgroup_fd);
	if (!ASSERT_OK_PTR(skel->links.cgrp_sysctl_overwrite, "cg-attach-sysctl"))
		goto skel_destroy;

	subtest(cgroup_fd, skel, &test_data);
	goto skel_destroy;

skel_destroy:
	cgrp_sysctl__destroy(skel);

close_cgroup:
	close(cgroup_fd);
}
