// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2019 Facebook */
#include <test_progs.h>
#include "trampoline_batch_test.skel.h"

void test_trampoline_batch(void)
{
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts);
	struct trampoline_batch_test *skel = NULL;
	int err, prog_fd, i;
	__u32 duration = 0, retval;
	__u64 *result;

	opts.trampoline_attach_batch = true;

	skel = trampoline_batch_test__open_opts(&opts);
	if (CHECK(!skel, "skel_open", "open failed\n"))
		goto cleanup;

	err = trampoline_batch_test__load(skel);
	if (CHECK(err, "skel_load", "load failed: %d\n", err))
		goto cleanup;

	err = trampoline_batch_test__attach(skel);
	if (CHECK(err, "skel_attach", "attach failed: %d\n", err))
		goto cleanup;

	prog_fd = bpf_program__fd(skel->progs.test1);
	err = bpf_prog_test_run(prog_fd, 1, NULL, 0,
				NULL, NULL, &retval, &duration);
	CHECK(err || retval, "test_run",
	      "err %d errno %d retval %d duration %d\n",
	      err, errno, retval, duration);

	result = (__u64 *)skel->bss;
	for (i = 0; i < 6; i++) {
		if (CHECK(result[i] != 1, "result",
			  "trampoline_batch_test fentry_test%d failed err %lld\n",
			  i + 1, result[i]))
			goto cleanup;
	}

cleanup:
	trampoline_batch_test__destroy(skel);
}
