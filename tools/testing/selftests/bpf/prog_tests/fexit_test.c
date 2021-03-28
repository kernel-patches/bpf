// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2019 Facebook */
#include <test_progs.h>
#include "fexit_test.skel.h"

static __u32 duration;

static int fexit_test(struct fexit_test *fexit_skel)
{
	int err, prog_fd, i;
	__u64 *result;
	__u32 retval;

	prog_fd = bpf_program__fd(fexit_skel->progs.test1);
	err = bpf_prog_test_run(prog_fd, 1, NULL, 0,
				NULL, NULL, &retval, &duration);
	CHECK(err || retval, "test_run",
	      "err %d errno %d retval %d duration %d\n",
	      err, errno, retval, duration);

	result = (__u64 *)fexit_skel->bss;
	for (i = 0; i < 8; i++) {
		if (CHECK(result[i] != 1, "result",
			  "fexit_test%d failed err %lld\n", i + 1, result[i]))
			return -1;
	}

	/* zero results for re-attach test */
	for (i = 0; i < 8; i++)
		result[i] = 0;
	return 0;
}

void test_fexit_test(void)
{
	struct fexit_test *fexit_skel = NULL;
	struct bpf_link *link;
	int err;

	fexit_skel = fexit_test__open_and_load();
	if (CHECK(!fexit_skel, "fexit_skel_load", "fexit skeleton failed\n"))
		goto cleanup;

	err = fexit_test__attach(fexit_skel);
	if (CHECK(err, "fexit_attach", "fexit attach failed: %d\n", err))
		goto cleanup;

	err = fexit_test(fexit_skel);
	if (CHECK(err, "fexit_test", "exit test failed: %d\n", err))
		goto cleanup;

	fexit_test__detach(fexit_skel);

	/* Re-attach and test again */
	err = fexit_test__attach(fexit_skel);
	if (CHECK(err, "fexit_attach", "fexit attach failed: %d\n", err))
		goto cleanup;

	link = bpf_program__attach(fexit_skel->progs.test1);
	if (CHECK(!IS_ERR(link), "attach_fexit re-attach without detach",
		"err: %ld\n", PTR_ERR(link)))
		goto cleanup;

	err = fexit_test(fexit_skel);
	CHECK(err, "fexit_test", "fexit test failed: %d\n", err);

cleanup:
	fexit_test__destroy(fexit_skel);
}
