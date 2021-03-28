// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2019 Facebook */
#include <test_progs.h>
#include "fentry_test.skel.h"

static __u32 duration;

static int fentry_test(struct fentry_test *fentry_skel)
{
	int err, prog_fd, i;
	__u64 *result;
	__u32 retval;

	prog_fd = bpf_program__fd(fentry_skel->progs.test1);
	err = bpf_prog_test_run(prog_fd, 1, NULL, 0,
				NULL, NULL, &retval, &duration);
	CHECK(err || retval, "test_run",
	      "err %d errno %d retval %d duration %d\n",
	      err, errno, retval, duration);

	result = (__u64 *)fentry_skel->bss;
	for (i = 0; i < 8; i++) {
		if (CHECK(result[i] != 1, "result",
			  "fentry_test%d failed err %lld\n", i + 1, result[i]))
			return -1;
	}

	/* zero results for re-attach test */
	for (i = 0; i < 8; i++)
		result[i] = 0;
	return 0;
}

void test_fentry_test(void)
{
	struct fentry_test *fentry_skel = NULL;
	struct bpf_link *link;
	int err;

	fentry_skel = fentry_test__open_and_load();
	if (CHECK(!fentry_skel, "fentry_skel_load", "fentry skeleton failed\n"))
		goto cleanup;

	err = fentry_test__attach(fentry_skel);
	if (CHECK(err, "fentry_attach", "fentry attach failed: %d\n", err))
		goto cleanup;

	err = fentry_test(fentry_skel);
	if (CHECK(err, "fentry_test", "fentry test failed: %d\n", err))
		goto cleanup;

	fentry_test__detach(fentry_skel);

	/* Re-attach and test again */
	err = fentry_test__attach(fentry_skel);
	if (CHECK(err, "fentry_attach", "fentry re-attach failed: %d\n", err))
		goto cleanup;

	link = bpf_program__attach(fentry_skel->progs.test1);
	if (CHECK(!IS_ERR(link), "attach_fentry re-attach without detach",
		  "err: %ld\n", PTR_ERR(link)))
		goto cleanup;

	err = fentry_test(fentry_skel);
	CHECK(err, "fentry_test", "fentry test failed: %d\n", err);

cleanup:
	fentry_test__destroy(fentry_skel);
}
