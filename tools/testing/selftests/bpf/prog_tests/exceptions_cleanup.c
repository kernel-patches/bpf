// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <test_progs.h>
#include "exceptions_cleanup.h"
#include "exceptions_cleanup.skel.h"
#include "exceptions_cleanup_fail.skel.h"

/* foo3 threw: every frame that has a pad ran it. */
#define PADS_FOO3_THREW \
	(RAN_FOO3_PREEMPT | RAN_FOO2_RCU | RAN_FOO1V_PREEMPT | RAN_FOO2_DROP)

/* foo2 threw after foo3 returned normally: foo3's pad must not run. */
#define PADS_FOO2_THREW \
	(RAN_FOO2_RCU | RAN_FOO1V_PREEMPT | RAN_FOO2_DROP)

static void run(struct exceptions_cleanup *skel, __u64 input, __u32 retval,
		__u64 pads)
{
	__u64 ctx = 0;
	int err;

	LIBBPF_OPTS(bpf_test_run_opts, topts,
		    .ctx_in = &ctx,
		    .ctx_size_in = sizeof(ctx),
	);

	skel->bss->input = input;
	skel->bss->pads_ran = 0;
	skel->bss->result = 0;

	err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.entry), &topts);
	if (!ASSERT_OK(err, "run"))
		return;
	ASSERT_EQ(topts.retval, retval, "retval");
	ASSERT_EQ(skel->bss->pads_ran, pads | RAN_BUMP, "pads_ran");
}

void test_exceptions_cleanup(void)
{
	char log[8192] = {};

	LIBBPF_OPTS(bpf_object_open_opts, opts,
		    .kernel_log_buf = log,
		    .kernel_log_size = sizeof(log));
	struct exceptions_cleanup *skel;
	int err;

	skel = exceptions_cleanup__open_opts(&opts);
	if (!ASSERT_OK_PTR(skel, "open"))
		return;

	err = exceptions_cleanup__load(skel);
	if (err) {
		if (err == -EOPNOTSUPP &&
		    strstr(log, "exception cleanup needs a JIT that can dispatch landing pads"))
			test__skip();
		else if (!ASSERT_OK(err, "load"))
			fprintf(stderr, "%s", log);
		exceptions_cleanup__destroy(skel);
		return;
	}

	/* No throw: foo3 returns 1 ^ 1 == 0, foo2 adds one, no pad runs. */
	if (test__start_subtest("no_throw"))
		run(skel, 1, 1, 0);

	/* foo3 throws; every pad runs and the cookie is delivered at entry. */
	if (test__start_subtest("throw_from_foo3"))
		run(skel, 101, THROW_COOKIE, PADS_FOO3_THREW);

	/* foo3 returns 2 ^ 1 == 3, so foo2 throws from its own second region;
	 * foo3's frame is long gone, so its pad must not run.
	 */
	if (test__start_subtest("throw_from_foo2"))
		run(skel, 2, THROW_COOKIE, PADS_FOO2_THREW);

	exceptions_cleanup__destroy(skel);

	RUN_TESTS(exceptions_cleanup_fail);
}
