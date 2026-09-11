// SPDX-License-Identifier: GPL-2.0
/*
 * Exception cleanup (.bpf_cleanup) end to end.
 *
 * progs/exceptions_cleanup.c hand-writes, in inline assembly, the cleanup
 * landing pads and the .bpf_cleanup records that an unwinding language
 * frontend would emit, so this needs nothing beyond the clang the selftests
 * already build with.
 *
 * The program is
 *
 *	entry -> foo1 -> foo1v -> foo2 -> foo3
 *
 * where foo3 disables preemption, foo2 takes an RCU read lock and owns a
 * second tracked resource, foo1v disables preemption and returns void, and
 * foo1 owns nothing. With @input over 100 foo3 throws, and unwinding has to
 * run the cleanup pads of every frame that has one and pop foo1's, so:
 *
 *   - the program only loads at all if the landing pads are reachable and
 *     balanced: the verifier tracks bpf_preempt_disable/bpf_preempt_enable and
 *     bpf_rcu_read_lock/bpf_rcu_read_unlock, and rejects an exit that still
 *     holds either;
 *   - each pad sets its own bit in @pads_ran, so that names exactly the pads
 *     that ran, independently of the cookie delivered at the boundary.
 *
 * With @input at or under 100 nothing throws and the ordinary return path
 * runs, which checks that the lowering leaves a normal call untouched.
 *
 * progs/exceptions_cleanup_fail.c covers what the kernel has to refuse.
 */
#include <test_progs.h>
#include "exceptions_cleanup.skel.h"
#include "exceptions_cleanup_fail.skel.h"
#include "exceptions_cleanup_shapes.skel.h"

/* Must match progs/exceptions_cleanup.c. */
#define THROW_COOKIE		0x100
#define RAN_FOO3_PREEMPT	0x1
#define RAN_FOO2_RCU		0x2
#define RAN_FOO2_TRACKER	0x4
#define RAN_FOO1V_PREEMPT	0x8
#define RAN_FOO2_DROP		0x10
#define RAN_BUMP		0x20

/* Must match progs/exceptions_cleanup_shapes.c, which has its own bits. */
#define RAN_SWEEP		0x1
#define RAN_SHARED		0x2
#define RAN_REGS		0x4
#define RAN_TAIL_CALL		0x8
#define RAN_MAIN_PAD		0x10

/* foo3 threw: every frame that has a pad ran it. */
#define PADS_FOO3_THREW \
	(RAN_FOO3_PREEMPT | RAN_FOO2_RCU | RAN_FOO2_TRACKER | RAN_FOO1V_PREEMPT | \
	 RAN_FOO2_DROP)

/* foo2 threw after foo3 returned normally: foo3's pad must not run. */
#define PADS_FOO2_THREW \
	(RAN_FOO2_RCU | RAN_FOO2_TRACKER | RAN_FOO1V_PREEMPT | RAN_FOO2_DROP)

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

/*
 * The individual shapes, one program each. Same idea as run() above, but these
 * do not go through foo1() and so set no RAN_BUMP.
 */
static void run_shape(struct exceptions_cleanup_shapes *skel, struct bpf_program *prog,
		      __u64 input, __u32 retval, __u64 pads)
{
	__u64 ctx = 0;
	int err;

	LIBBPF_OPTS(bpf_test_run_opts, topts,
		    .ctx_in = &ctx,
		    .ctx_size_in = sizeof(ctx),
	);

	skel->bss->input = input;
	skel->bss->pads_ran = 0;

	err = bpf_prog_test_run_opts(bpf_program__fd(prog), &topts);
	if (!ASSERT_OK(err, "run"))
		return;
	ASSERT_EQ(topts.retval, retval, "retval");
	ASSERT_EQ(skel->bss->pads_ran, pads, "pads_ran");
}

static void test_shapes(void)
{
	struct exceptions_cleanup_shapes *skel;

	skel = exceptions_cleanup_shapes__open_and_load();
	if (!ASSERT_OK_PTR(skel, "shapes open_and_load"))
		return;

	/* The frame loads at all only if everything unreachable in it went. */
	if (test__start_subtest("sweep_no_throw"))
		run_shape(skel, skel->progs.entry_sweep, 1, 0, 0);
	if (test__start_subtest("sweep_throw"))
		run_shape(skel, skel->progs.entry_sweep, 101, THROW_COOKIE, RAN_SWEEP);

	/* The covered call unwinds to the pad; the uncovered one never does. */
	if (test__start_subtest("shared_callee_no_throw"))
		run_shape(skel, skel->progs.entry_shared, 1, 2, 0);
	if (test__start_subtest("shared_callee_throw"))
		run_shape(skel, skel->progs.entry_shared, 101, THROW_COOKIE, RAN_SHARED);

	/* The pad only sets its bit if it got the frame's own r6-r9 back. */
	if (test__start_subtest("pad_sees_callee_saved"))
		run_shape(skel, skel->progs.entry_regs, 101, THROW_COOKIE, RAN_REGS);

	/* Same check, with a tail-call-reachable callee: its spill moves. */
	if (test__start_subtest("tail_call_no_throw"))
		run_shape(skel, skel->progs.entry_tail_call, 1, 0, 0);
	if (test__start_subtest("tail_call_throw"))
		run_shape(skel, skel->progs.entry_tail_call, 101, THROW_COOKIE,
			  RAN_TAIL_CALL);

	/* A pad in the main program's own frame, not in a subprogram. */
	if (test__start_subtest("main_program_pad"))
		run_shape(skel, skel->progs.entry_main_pad, 101, THROW_COOKIE,
			  RAN_MAIN_PAD);

	exceptions_cleanup_shapes__destroy(skel);
}

void test_exceptions_cleanup(void)
{
	struct exceptions_cleanup *skel;

	skel = exceptions_cleanup__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	/* No throw: foo3 returns 1 ^ 1 == 0, foo2 adds one, no pad runs. */
	if (test__start_subtest("no_throw"))
		run(skel, 1, 1, 0);

	/* foo3 throws; every pad runs and the cookie is delivered at entry. */
	if (test__start_subtest("throw_from_foo3"))
		run(skel, 101, THROW_COOKIE, PADS_FOO3_THREW);

	/*
	 * foo3 returns 2 ^ 1 == 3, so foo2 throws from its own second cleanup
	 * region. foo3's frame is long gone, so its pad must not run.
	 */
	if (test__start_subtest("throw_from_foo2"))
		run(skel, 2, THROW_COOKIE, PADS_FOO2_THREW);

	exceptions_cleanup__destroy(skel);

	test_shapes();

	RUN_TESTS(exceptions_cleanup_fail);
}
