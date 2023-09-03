// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include "cgroup_helpers.h"
#include "test_current_under_cgroupv1v2.skel.h"

#define CGROUP2_DIR "/current_under_cgroup2"

static void attach_progs(int cgrp_fd)
{
	struct test_current_under_cgroupv1v2 *skel;
	int cgrp_map_fd, ret, idx = 0;

	skel = test_current_under_cgroupv1v2__open_and_load();
	if (!ASSERT_OK_PTR(skel, "test_current_under_cgroupv1v2__open"))
		return;

	cgrp_map_fd = bpf_map__fd(skel->maps.cgrp_map);
	ret = bpf_map_update_elem(cgrp_map_fd, &idx, &cgrp_fd, BPF_ANY);
	if (!ASSERT_OK(ret, "update_cgrp_map"))
		goto cleanup;

	/* Attach LSM prog first */
	skel->links.lsm_run = bpf_program__attach_lsm(skel->progs.lsm_run);
	if (!ASSERT_OK_PTR(skel->links.lsm_run, "lsm_attach"))
		goto cleanup;

	/* LSM prog will be triggered when attaching fentry */
	skel->links.fentry_run = bpf_program__attach_trace(skel->progs.fentry_run);
	ASSERT_NULL(skel->links.fentry_run, "fentry_attach");

cleanup:
	test_current_under_cgroupv1v2__destroy(skel);
}

static void current_under_cgroup1(void)
{
	int cgrp_fd, ret;

	/* Setup cgroup1 hierarchy */
	ret = setup_classid_environment();
	if (!ASSERT_OK(ret, "setup_classid_environment"))
		return;

	ret = join_classid();
	if (!ASSERT_OK(ret, "join_cgroup1"))
		goto cleanup;

	cgrp_fd = open_classid();
	attach_progs(cgrp_fd);
	close(cgrp_fd);

cleanup:
	/* Cleanup cgroup1 hierarchy */
	cleanup_classid_environment();
}

static void current_under_cgroup2(void)
{
	int cgrp_fd;

	cgrp_fd = test__join_cgroup(CGROUP2_DIR);
	if (!ASSERT_GE(cgrp_fd, 0, "cgroup_join_cgroup2"))
		return;

	attach_progs(cgrp_fd);
	close(cgrp_fd);
}

void test_current_under_cgroupv1v2(void)
{
	if (test__start_subtest("test_current_under_cgroup2"))
		current_under_cgroup2();
	if (test__start_subtest("test_current_under_cgroup1"))
		current_under_cgroup1();
}
