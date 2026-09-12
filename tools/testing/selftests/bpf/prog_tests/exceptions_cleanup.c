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
 * where foo3 disables preemption, foo2 takes an RCU read lock and has two
 * call sites sharing one pad, foo1v disables preemption and returns void, and
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
 * runs, which checks that carrying a cleanup table leaves an ordinary call
 * untouched.
 *
 * progs/exceptions_cleanup_fail.c covers what the kernel has to refuse.
 */
#include <test_progs.h>
#include "exceptions_cleanup.skel.h"
#include "exceptions_cleanup_fail.skel.h"
#include "exceptions_cleanup_shapes.skel.h"
#include "exceptions_cleanup_freplace.skel.h"
#include "exceptions_cleanup_pad_freplace.skel.h"
#include "exceptions_cleanup_ext_table.skel.h"

/* Must match progs/exceptions_cleanup.c. */
#define THROW_COOKIE		0x100
#define RAN_FOO3_PREEMPT	0x1
#define RAN_FOO2_RCU		0x2
#define RAN_FOO1V_PREEMPT	0x4
#define RAN_FOO2_DROP		0x8
#define RAN_BUMP		0x10

/* Must match progs/exceptions_cleanup_shapes.c, which has its own bits. */
#define RAN_SWEEP		0x1
#define RAN_SHARED		0x2
#define RAN_REGS		0x4
#define RAN_TAIL_CALL		0x8
#define RAN_MAIN_PAD		0x10
#define RAN_TC_TAKEN		0x20
#define RAN_FREPLACE		0x40
#define RAN_ADDR_TAKEN		0x80
#define RAN_NO_SUBPROG		0x100
#define RAN_PAD_CALLS		0x200
#define RAN_PAD_FIRST		0x400
#define RAN_WIDE_REC		0x800
#define INNER_COOKIE		0x200

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

/*
 * Attach an extension program over fr_callee() and run the frame that calls
 * it. The extension throws, but it is a program in its own right, so the walk
 * ends in its frame: the cookie is delivered there and comes back as this
 * program's return value, and the pad of the frame that called it stays put.
 */
static void test_freplace(struct exceptions_cleanup_shapes *skel)
{
	struct exceptions_cleanup_freplace *fr;
	struct bpf_link *link;
	int tgt_fd;

	tgt_fd = bpf_program__fd(skel->progs.entry_freplace);

	fr = exceptions_cleanup_freplace__open();
	if (!ASSERT_OK_PTR(fr, "freplace open"))
		return;

	if (!ASSERT_OK(bpf_program__set_attach_target(fr->progs.new_fr_callee,
						      tgt_fd, "fr_callee"),
		       "set_attach_target"))
		goto out;
	if (!ASSERT_OK(exceptions_cleanup_freplace__load(fr), "freplace load"))
		goto out;

	link = bpf_program__attach_freplace(fr->progs.new_fr_callee, tgt_fd,
					    "fr_callee");
	if (!ASSERT_OK_PTR(link, "attach_freplace"))
		goto out;

	run_shape(skel, skel->progs.entry_freplace, 101, THROW_COOKIE, 0);
	bpf_link__destroy(link);
out:
	exceptions_cleanup_freplace__destroy(fr);
}

/*
 * Attach a throwing extension over pad_callee(), which entry_pad_calls() calls
 * from inside its landing pad, and run the frame so that the pad executes.
 *
 * The load-time rule against throwing from a pad cannot see this coming: the
 * subprogram it checked does not throw, and the extension replaces it
 * afterwards. What has to hold instead is that the inner exception stops in
 * the extension's own frame, so the pad runs once and the outer unwind
 * delivers the outer cookie.
 */
static void test_pad_calls_freplace(struct exceptions_cleanup_shapes *skel)
{
	struct exceptions_cleanup_pad_freplace *fr;
	struct bpf_link *link;
	__u64 ctx = 0;
	int tgt_fd, err;

	LIBBPF_OPTS(bpf_test_run_opts, topts,
		    .ctx_in = &ctx,
		    .ctx_size_in = sizeof(ctx),
	);

	tgt_fd = bpf_program__fd(skel->progs.entry_pad_calls);

	fr = exceptions_cleanup_pad_freplace__open();
	if (!ASSERT_OK_PTR(fr, "pad freplace open"))
		return;

	if (!ASSERT_OK(bpf_program__set_attach_target(fr->progs.new_pad_callee,
						      tgt_fd, "pad_callee"),
		       "set_attach_target"))
		goto out;
	if (!ASSERT_OK(exceptions_cleanup_pad_freplace__load(fr), "pad freplace load"))
		goto out;

	link = bpf_program__attach_freplace(fr->progs.new_pad_callee, tgt_fd,
					    "pad_callee");
	if (!ASSERT_OK_PTR(link, "attach_freplace"))
		goto out;

	skel->bss->input = 101;
	skel->bss->pads_ran = 0;
	skel->bss->pad_runs = 0;

	err = bpf_prog_test_run_opts(tgt_fd, &topts);
	if (!ASSERT_OK(err, "run"))
		goto out_link;

	/* The pad ran once, not once per exception in flight. */
	ASSERT_EQ(skel->bss->pad_runs, 1, "pad_runs");
	ASSERT_EQ(skel->bss->pads_ran, RAN_PAD_CALLS, "pads_ran");
	/* The outer exception is the one that reaches the boundary. */
	ASSERT_EQ(topts.retval, THROW_COOKIE, "retval");
out_link:
	bpf_link__destroy(link);
out:
	exceptions_cleanup_pad_freplace__destroy(fr);
}

/*
 * The same call site as test_freplace(), with an extension that carries a
 * cleanup table of its own. Its frame is the first the walk visits and the
 * boundary it ends at, so its pad runs off the spill its throw site made; the
 * frame it stands in for belongs to another program, whose pad must not run.
 */
static void test_ext_table(struct exceptions_cleanup_shapes *skel)
{
	struct exceptions_cleanup_ext_table *fr;
	struct bpf_link *link;
	int tgt_fd;

	tgt_fd = bpf_program__fd(skel->progs.entry_freplace);

	fr = exceptions_cleanup_ext_table__open();
	if (!ASSERT_OK_PTR(fr, "ext table open"))
		return;

	if (!ASSERT_OK(bpf_program__set_attach_target(fr->progs.new_fr_callee,
						      tgt_fd, "fr_callee"),
		       "set_attach_target"))
		goto out;
	if (!ASSERT_OK(exceptions_cleanup_ext_table__load(fr), "ext table load"))
		goto out;

	link = bpf_program__attach_freplace(fr->progs.new_fr_callee, tgt_fd,
					    "fr_callee");
	if (!ASSERT_OK_PTR(link, "attach_freplace"))
		goto out;

	fr->bss->ext_pad_ran = 0;
	run_shape(skel, skel->progs.entry_freplace, 101, THROW_COOKIE, 0);
	/* The extension cleaned up after itself on the way out. */
	ASSERT_EQ(fr->bss->ext_pad_ran, 1, "ext_pad_ran");

	bpf_link__destroy(link);
out:
	exceptions_cleanup_ext_table__destroy(fr);
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

	/*
	 * The same call site with and without an extension program standing
	 * in for its callee. The real subprogram's throw unwinds into this
	 * frame and runs its pad; the extension's is delivered at the
	 * extension's own boundary, so the pad stays put.
	 */
	if (test__start_subtest("freplace_subprog_throws"))
		run_shape(skel, skel->progs.entry_freplace, 7, THROW_COOKIE,
			  RAN_FREPLACE);
	if (test__start_subtest("freplace_extension_throws"))
		test_freplace(skel);

	/*
	 * A tail call that is taken: the walk ends at the target, so the
	 * cookie comes back from there and this frame's pad does not run.
	 */
	if (test__start_subtest("tail_call_taken")) {
		int key = 0, prog_fd = bpf_program__fd(skel->progs.tc_target);

		if (ASSERT_OK(bpf_map_update_elem(bpf_map__fd(skel->maps.taken_table),
						  &key, &prog_fd, BPF_ANY),
			      "populate taken_table"))
			run_shape(skel, skel->progs.entry_tail_taken, 101,
				  THROW_COOKIE, 0);
	}

	/*
	 * A throwing subprogram named by a BPF_PSEUDO_FUNC that no helper is
	 * ever handed. The frame loads at all only if what refuses a throwing
	 * callback looks at the bpf_loop() rather than at the ld_imm64.
	 */
	if (test__start_subtest("addr_taken_no_throw"))
		run_shape(skel, skel->progs.entry_addr_taken, 1, 2, 0);
	if (test__start_subtest("addr_taken_throw"))
		run_shape(skel, skel->progs.entry_addr_taken, 101, THROW_COOKIE,
			  RAN_ADDR_TAKEN);

	/*
	 * A record covering bpf_throw() itself rather than a call to a frame
	 * that throws: raised, caught up with and delivered in one frame.
	 */
	if (test__start_subtest("no_subprog_no_throw"))
		run_shape(skel, skel->progs.entry_no_subprog, 1, 0, 0);
	if (test__start_subtest("no_subprog_throw"))
		run_shape(skel, skel->progs.entry_no_subprog, 101, THROW_COOKIE,
			  RAN_NO_SUBPROG);

	/*
	 * A pad that calls a subprogram, with and without a throwing extension
	 * standing in for it. Without, the pad simply runs; with, the nested
	 * exception has to stop in the extension rather than restart this
	 * frame's cleanup.
	 */
	if (test__start_subtest("pad_calls_subprog")) {
		skel->bss->pad_runs = 0;
		run_shape(skel, skel->progs.entry_pad_calls, 101, THROW_COOKIE,
			  RAN_PAD_CALLS);
		ASSERT_EQ(skel->bss->pad_runs, 1, "pad_runs");
	}
	if (test__start_subtest("pad_calls_throwing_extension"))
		test_pad_calls_freplace(skel);

	/*
	 * A covered throw the sweep leaves as the program's last instruction,
	 * where the default exception callback is then patched in. The pad
	 * only sets its bit if the throw site still spilled r6-r9.
	 */
	if (test__start_subtest("pad_before_throw"))
		run_shape(skel, skel->progs.entry_pad_first, 101, THROW_COOKIE,
			  RAN_PAD_FIRST);

	/*
	 * A region whose last instruction is a 16-byte one, so that end - 1
	 * names the half of it that is not an instruction.
	 */
	if (test__start_subtest("region_ends_on_ldimm64"))
		run_shape(skel, skel->progs.entry_wide_rec, 101, THROW_COOKIE,
			  RAN_WIDE_REC);

	/* An extension program with a cleanup table of its own. */
	if (test__start_subtest("extension_carries_table"))
		test_ext_table(skel);

	exceptions_cleanup_shapes__destroy(skel);
}

/*
 * The only load failure this test is willing to be quiet about, verbatim from
 * bpf_prepare_cleanup_exceptions().
 */
#define NO_PAD_DISPATCH_MSG \
	"exception cleanup needs a JIT that can dispatch landing pads"

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

	/*
	 * Dispatching a landing pad needs a JIT that can do it -- x86-64 with
	 * CONFIG_UNWINDER_ORC, or arm64 -- and needs the JIT to be enabled at
	 * all. All three ways of not having that come back from the one check
	 * in bpf_prepare_cleanup_exceptions(), and that is the only reason to
	 * skip rather than fail. The errno alone does not say so: EOPNOTSUPP
	 * is what a good many other refusals return too, and skipping on one
	 * of those would quietly stop testing anything. Match on what the
	 * kernel actually said.
	 *
	 * libbpf fills the log buffer by retrying the load with one when the
	 * first attempt fails, so this costs nothing on the way through.
	 */
	err = exceptions_cleanup__load(skel);
	if (err) {
		if (err == -EOPNOTSUPP && strstr(log, NO_PAD_DISPATCH_MSG))
			test__skip();
		else if (!ASSERT_OK(err, "load"))
			/* A log libbpf did not allocate is one it does not print. */
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
