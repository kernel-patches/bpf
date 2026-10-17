// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <test_progs.h>
#include "exceptions_cleanup.h"
#include "exceptions_cleanup.skel.h"
#include "exceptions_cleanup_fail.skel.h"
#include "exceptions_cleanup_tracing.skel.h"

/* foo3 unwound: every frame that has a pad ran it. */
#define PADS_FOO3_UNWOUND \
	(RAN_FOO3_PREEMPT | RAN_FOO2_RCU | RAN_FOO1V_PREEMPT | RAN_FOO2_DROP)

/* foo2 unwound after foo3 returned normally: foo3's pad must not run. */
#define PADS_FOO2_UNWOUND \
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
	/* bump() is not a landing pad; it sets its bit on every run. */
	ASSERT_EQ(skel->bss->pads_ran, pads | RAN_BUMP, "pads_ran");
}

/*
 * Tracing programs against foo1(), which an unwind passes through. fexit
 * keeps a trampoline frame between foo1() and its caller that the unwind
 * cannot walk past, so it is refused; fentry leaves none, so foo3 can still
 * unwind through foo1() with it attached.
 */
static void test_tracing(struct exceptions_cleanup *tgt)
{
	struct exceptions_cleanup_tracing *skel;
	int tgt_fd = bpf_program__fd(tgt->progs.entry);
	char log[8192] = {};
	int err;

	LIBBPF_OPTS(bpf_object_open_opts, opts,
		    .kernel_log_buf = log,
		    .kernel_log_size = sizeof(log));

	skel = exceptions_cleanup_tracing__open_opts(&opts);
	if (!ASSERT_OK_PTR(skel, "tracer open"))
		return;
	bpf_program__set_autoload(skel->progs.fentry_unwinding_subprog, true);
	err = bpf_program__set_attach_target(skel->progs.fentry_unwinding_subprog,
					     tgt_fd, "foo1");
	if (!ASSERT_OK(err, "fentry target"))
		goto out;
	err = exceptions_cleanup_tracing__load(skel);
	if (!ASSERT_OK(err, "fentry load"))
		goto out;
	err = exceptions_cleanup_tracing__attach(skel);
	if (!ASSERT_OK(err, "fentry attach"))
		goto out;
	run(tgt, 101, 0, PADS_FOO3_UNWOUND);
	ASSERT_EQ(skel->bss->fentry_hits, 1, "fentry_hits");
	exceptions_cleanup_tracing__destroy(skel);

	skel = exceptions_cleanup_tracing__open_opts(&opts);
	if (!ASSERT_OK_PTR(skel, "tracer open"))
		return;
	bpf_program__set_autoload(skel->progs.fexit_unwinding_subprog, true);
	err = bpf_program__set_attach_target(skel->progs.fexit_unwinding_subprog,
					     tgt_fd, "foo1");
	if (!ASSERT_OK(err, "fexit target"))
		goto out;
	err = exceptions_cleanup_tracing__load(skel);
	ASSERT_EQ(err, -EINVAL, "fexit load");
	ASSERT_HAS_SUBSTR(log, "Cannot attach fexit, fmod_ret or fsession to foo1",
			  "fexit log");
out:
	exceptions_cleanup_tracing__destroy(skel);
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
		    strstr(log, "exception cleanup needs a JIT that can dispatch landing pads")) {
			printf("%s:SKIP:JIT cannot dispatch exception cleanup landing pads\n",
			       __func__);
			test__skip();
		} else if (!ASSERT_OK(err, "load")) {
			fprintf(stderr, "%s", log);
		}
		exceptions_cleanup__destroy(skel);
		return;
	}

	/* No unwind: foo3 returns 1 ^ 1 == 0, foo2 adds one, no pad runs. */
	if (test__start_subtest("no_unwind"))
		run(skel, 1, 1, 0);

	/* foo3 unwinds; every pad runs and entry returns zero. */
	if (test__start_subtest("unwind_from_foo3"))
		run(skel, 101, 0, PADS_FOO3_UNWOUND);

	/*
	 * foo3 returns 2 ^ 1 == 3, so foo2 unwinds from its own second region;
	 * foo3's frame is long gone, so its pad must not run.
	 */
	if (test__start_subtest("unwind_from_foo2"))
		run(skel, 2, 0, PADS_FOO2_UNWOUND);

	if (test__start_subtest("tracing_unwinding_subprog"))
		test_tracing(skel);

	exceptions_cleanup__destroy(skel);

	RUN_TESTS(exceptions_cleanup_fail);
}
