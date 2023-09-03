// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2023 Yafang Shao <laoar.shao@gmail.com> */

#include <sys/types.h>
#include <unistd.h>
#include <test_progs.h>
#include "cgroup_helpers.h"
#include "test_cgroup_controller.skel.h"

#define CGROUP2_DIR "/cgroup2_controller"

static void bpf_cgroup1_controller(bool sleepable, __u64 cgrp_id)
{
	struct test_cgroup_controller *skel;
	int err;

	skel = test_cgroup_controller__open();
	if (!ASSERT_OK_PTR(skel, "open"))
		return;

	skel->bss->target_pid = getpid();
	skel->bss->ancestor_cgid = cgrp_id;

	err = bpf_program__set_attach_target(skel->progs.fentry_run, 0, "bpf_fentry_test1");
	if (!ASSERT_OK(err, "fentry_set_target"))
		goto cleanup;

	err = test_cgroup_controller__load(skel);
	if (!ASSERT_OK(err, "load"))
		goto cleanup;

	/* Attach LSM prog first */
	if (!sleepable) {
		skel->links.lsm_net_cls = bpf_program__attach_lsm(skel->progs.lsm_net_cls);
		if (!ASSERT_OK_PTR(skel->links.lsm_net_cls, "lsm_attach"))
			goto cleanup;
	} else {
		skel->links.lsm_s_net_cls = bpf_program__attach_lsm(skel->progs.lsm_s_net_cls);
		if (!ASSERT_OK_PTR(skel->links.lsm_s_net_cls, "lsm_attach_sleepable"))
			goto cleanup;
	}

	/* LSM prog will be triggered when attaching fentry */
	skel->links.fentry_run = bpf_program__attach_trace(skel->progs.fentry_run);
	if (cgrp_id) {
		ASSERT_NULL(skel->links.fentry_run, "fentry_attach_fail");
	} else {
		if (!ASSERT_OK_PTR(skel->links.fentry_run, "fentry_attach_success"))
			goto cleanup;
	}

cleanup:
	test_cgroup_controller__destroy(skel);
}

static void cgroup_controller_on_cgroup1(bool sleepable, bool invalid_cgid)
{
	__u64 cgrp_id;
	int err;

	/* Setup cgroup1 hierarchy */
	err = setup_classid_environment();
	if (!ASSERT_OK(err, "setup_classid_environment"))
		return;

	err = join_classid();
	if (!ASSERT_OK(err, "join_cgroup1"))
		goto cleanup;

	cgrp_id = get_classid_cgroup_id();
	if (invalid_cgid)
		bpf_cgroup1_controller(sleepable, 0);
	else
		bpf_cgroup1_controller(sleepable, cgrp_id);

cleanup:
	/* Cleanup cgroup1 hierarchy */
	cleanup_classid_environment();
}

static void bpf_cgroup2_controller(__u64 cgrp_id)
{
	struct test_cgroup_controller *skel;
	int err;

	skel = test_cgroup_controller__open();
	if (!ASSERT_OK_PTR(skel, "open"))
		return;

	skel->bss->target_pid = getpid();
	skel->bss->ancestor_cgid = cgrp_id;

	err = bpf_program__set_attach_target(skel->progs.fentry_run, 0, "bpf_fentry_test1");
	if (!ASSERT_OK(err, "fentry_set_target"))
		goto cleanup;

	err = test_cgroup_controller__load(skel);
	if (!ASSERT_OK(err, "load"))
		goto cleanup;

	skel->links.lsm_cpu = bpf_program__attach_lsm(skel->progs.lsm_cpu);
	if (!ASSERT_OK_PTR(skel->links.lsm_net_cls, "lsm_attach"))
		goto cleanup;

	skel->links.fentry_run = bpf_program__attach_trace(skel->progs.fentry_run);
	ASSERT_NULL(skel->links.fentry_run, "fentry_attach_fail");

cleanup:
	test_cgroup_controller__destroy(skel);
}

static void cgroup_controller_on_cgroup2(void)
{
	int cgrp_fd, cgrp_id, err;

	err = setup_cgroup_environment();
	if (!ASSERT_OK(err, "cgrp2_env_setup"))
		goto cleanup;

	cgrp_fd = test__join_cgroup(CGROUP2_DIR);
	if (!ASSERT_GE(cgrp_fd, 0, "cgroup_join_cgroup2"))
		goto cleanup;

	err = enable_controllers(CGROUP2_DIR, "cpu");
	if (!ASSERT_OK(err, "cgrp2_env_setup"))
		goto close_fd;

	cgrp_id = get_cgroup_id(CGROUP2_DIR);
	if (!ASSERT_GE(cgrp_id, 0, "cgroup2_id"))
		goto close_fd;
	bpf_cgroup2_controller(cgrp_id);

close_fd:
	close(cgrp_fd);
cleanup:
	cleanup_cgroup_environment();
}

void test_cgroup_controller(void)
{
	if (test__start_subtest("test_cgroup1_controller"))
		cgroup_controller_on_cgroup1(false, false);
	if (test__start_subtest("test_invalid_cgroup_id"))
		cgroup_controller_on_cgroup1(false, true);
	if (test__start_subtest("test_sleepable_prog"))
		cgroup_controller_on_cgroup1(true, false);
	if (test__start_subtest("test_cgroup2_controller"))
		cgroup_controller_on_cgroup2();
}
