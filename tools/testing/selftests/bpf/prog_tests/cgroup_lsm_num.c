// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Orange */

/*
 * Test that the kernel enforces CONFIG_CGROUP_LSM_NUM as the maximum
 * number of concurrently used per-cgroup LSM hook slots.
 *
 *  - load a BPF object with 12 programs each on a distinct lsm_cgroup hook
 *  - attach them one by one via bpf_program__attach_cgroup()
 *  - at some point the slots are exhausted and attachment fails
 *  - verify that 10 succeed attachment and 2 fail
 */

#include <test_progs.h>
#include <bpf/bpf.h>

#include "cgroup_lsm_num.skel.h"
#include "cgroup_helpers.h"

void test_cgroup_lsm_num(void)
{
	struct cgroup_lsm_num *skel = NULL;
	struct bpf_program *prog;
	int cgroup_fd = -1;
	int attached = 0;
	int failed = 0;

	cgroup_fd = test__join_cgroup("/cgroup_lsm_num");
	if (!ASSERT_GE(cgroup_fd, 0, "join_cgroup"))
		return;

	skel = cgroup_lsm_num__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		goto out;

	bpf_object__for_each_program(prog, skel->obj) {
		struct bpf_link *link;

		link = bpf_program__attach_cgroup(prog, cgroup_fd);
		if (!link) {
			if (errno == EOPNOTSUPP) {
				test__skip();
				goto out;
			}
			failed++;
		} else {
			attached++;
		}
	}

	// CONFIG_CGROUP_LSM_NUM set to 10
	// -> 10 programs shall be attached
	ASSERT_EQ(attached, 10, "at least one attached");
	// -> 2 programs shall be rejected
	ASSERT_EQ(failed, 2, "limit was enforced");

out:
	close(cgroup_fd);
	cgroup_lsm_num__destroy(skel);
}
