// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2019 Facebook */
#include <test_progs.h>
#include "fentry_test.lskel.h"
#include "fexit_test.lskel.h"

void test_fentry_fexit(void)
{
	struct fentry_test_lskel *fentry_skel = NULL;
	struct fexit_test_lskel *fexit_skel = NULL;
	__u64 *fentry_res, *fexit_res;
	int err, prog_fd, i;
	LIBBPF_OPTS(bpf_test_run_opts, topts,
		.repeat = 1,
	);

	fentry_skel = fentry_test_lskel__open_and_load();
	if (CHECK_OPTS(!fentry_skel, "fentry_skel_load",
		       "fentry skeleton failed\n"))
		goto close_prog;
	fexit_skel = fexit_test_lskel__open_and_load();
	if (CHECK_OPTS(!fexit_skel, "fexit_skel_load",
		       "fexit skeleton failed\n"))
		goto close_prog;

	err = fentry_test_lskel__attach(fentry_skel);
	if (CHECK_OPTS(err, "fentry_attach", "fentry attach failed: %d\n", err))
		goto close_prog;
	err = fexit_test_lskel__attach(fexit_skel);
	if (CHECK_OPTS(err, "fexit_attach", "fexit attach failed: %d\n", err))
		goto close_prog;

	prog_fd = fexit_skel->progs.test1.prog_fd;
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	CHECK_OPTS(err || topts.retval, "ipv6",
		   "err %d errno %d retval %d duration %d\n", err, errno,
		   topts.retval, topts.duration);

	fentry_res = (__u64 *)fentry_skel->bss;
	fexit_res = (__u64 *)fexit_skel->bss;
	printf("%lld\n", fentry_skel->bss->test1_result);
	for (i = 0; i < 8; i++) {
		CHECK_OPTS(fentry_res[i] != 1, "result",
			   "fentry_test%d failed err %lld\n", i + 1,
			   fentry_res[i]);
		CHECK_OPTS(fexit_res[i] != 1, "result",
			   "fexit_test%d failed err %lld\n", i + 1,
			   fexit_res[i]);
	}

close_prog:
	fentry_test_lskel__destroy(fentry_skel);
	fexit_test_lskel__destroy(fexit_skel);
}
