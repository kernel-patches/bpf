// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2019 Facebook */
#include <test_progs.h>
#include "fentry_test.skel.h"

static __u32 duration;

static int fentry_test(struct fentry_test *fentry_skel)
{
	struct bpf_link *link;
	int err, prog_fd, i;
	__u64 *result;
	__u32 retval;

	err = fentry_test__attach(fentry_skel);
	if (CHECK(err, "fentry_attach", "fentry attach failed: %d\n", err))
		return err;

	/* Check that already linked program can't be attached again. */
	link = bpf_program__attach(fentry_skel->progs.test1);
	if (CHECK(!IS_ERR(link), "fentry_attach_link",
		  "re-attach without detach should not succeed"))
		return -1;

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

	fentry_test__detach(fentry_skel);

	/* zero results for re-attach test */
	for (i = 0; i < 8; i++)
		result[i] = 0;
	return 0;
}

void test_fentry_test(void)
{
	struct fentry_test *fentry_skel = NULL;
	int err;

	fentry_skel = fentry_test__open_and_load();
	if (CHECK(!fentry_skel, "fentry_skel_load", "fentry skeleton failed\n"))
		goto cleanup;

	err = fentry_test(fentry_skel);
	if (CHECK(err, "fentry_test", "first attach failed\n"))
		goto cleanup;

	err = fentry_test(fentry_skel);
	CHECK(err, "fentry_test", "second attach failed\n");

cleanup:
	fentry_test__destroy(fentry_skel);
}
