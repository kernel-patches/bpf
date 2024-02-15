// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2017 Facebook
 */

#include <test_progs.h>
#include <time.h>
#include "cgroup_helpers.h"
#include "dev_cgroup.skel.h"

#define TEST_CGROUP "/test-bpf-based-device-cgroup/"

void test_test_dev_cgroup(void)
{
	int cgroup_fd, err, duration = 0;
	struct dev_cgroup *skel;
	__u32 prog_cnt;

	skel = dev_cgroup__open_and_load();
	if (CHECK(!skel, "skel_open_and_load", "failed\n"))
		goto cleanup;

	cgroup_fd = cgroup_setup_and_join(TEST_CGROUP);
	if (CHECK(cgroup_fd < 0, "cgroup_setup_and_join", "failed: %d\n", cgroup_fd))
		goto cleanup;

	err = bpf_prog_attach(bpf_program__fd(skel->progs.bpf_prog1), cgroup_fd,
			      BPF_CGROUP_DEVICE, 0);
	if (CHECK(err, "bpf_attach", "failed: %d\n", err))
		goto cleanup;

	err = bpf_prog_query(cgroup_fd, BPF_CGROUP_DEVICE, 0, NULL, NULL, &prog_cnt);
	if (CHECK(err || prog_cnt != 1, "bpf_query", "failed: %d %d\n", err, prog_cnt))
		goto cleanup;

	/* All operations with /dev/zero and /dev/urandom are allowed,
	 * everything else is forbidden.
	 */
	CHECK(system("rm -f /tmp/test_dev_cgroup_null"), "rm",
	      "unexpected rm on _null\n");
	CHECK(!system("mknod /tmp/test_dev_cgroup_null c 1 3"),
	      "mknod", "unexpected mknod on _null\n");
	CHECK(system("rm -f /tmp/test_dev_cgroup_null"), "rm",
	      "unexpected rm on _null\n");

	/* /dev/zero is whitelisted */
	CHECK(system("rm -f /tmp/test_dev_cgroup_zero"), "rm",
	      "unexpected rm on _zero\n");
	CHECK(system("mknod /tmp/test_dev_cgroup_zero c 1 5"),
	      "mknod", "unexpected mknod on _zero\n");
	CHECK(system("rm -f /tmp/test_dev_cgroup_zero"), "rm",
	      "unexpected rm on _zero\n");

	CHECK(system("dd if=/dev/urandom of=/dev/zero count=64"), "dd",
	      "unexpected dd on /dev/zero\n");

	/* src is allowed, target is forbidden */
	CHECK(!system("dd if=/dev/urandom of=/dev/full count=64"), "dd",
	      "unexpected dd on /dev/full\n");

	/* src is forbidden, target is allowed */
	CHECK(!system("dd if=/dev/random of=/dev/zero count=64"), "dd",
	      "unexpected dd on /dev/zero\n");

cleanup:
	cleanup_cgroup_environment();
	dev_cgroup__destroy(skel);
}
