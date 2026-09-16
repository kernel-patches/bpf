// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <test_progs.h>
#include "exceptions_cleanup.h"
#include "exceptions_cleanup.skel.h"
#include "exceptions_cleanup_fail.skel.h"
#include "exceptions_cleanup_shapes.skel.h"
#include "exceptions_cleanup_freplace.skel.h"
#include "exceptions_cleanup_pad_freplace.skel.h"
#include "exceptions_cleanup_ext_table.skel.h"

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

	ASSERT_EQ(skel->bss->pad_runs, 1, "pad_runs");
	ASSERT_EQ(skel->bss->pads_ran, RAN_PAD_CALLS, "pads_ran");
	ASSERT_EQ(topts.retval, THROW_COOKIE, "retval");
out_link:
	bpf_link__destroy(link);
out:
	exceptions_cleanup_pad_freplace__destroy(fr);
}

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

	/* A region around a nounwind call: no pad dispatched, still loads. */
	if (test__start_subtest("nounwind_region"))
		run_shape(skel, skel->progs.entry_nounwind_rec, 1, 0, 0);

	/* A pad in the main program's own frame, not in a subprogram. */
	if (test__start_subtest("main_program_pad"))
		run_shape(skel, skel->progs.entry_main_pad, 101, THROW_COOKIE,
			  RAN_MAIN_PAD);

	/* The same call site either way: the subprogram's throw unwinds into
	 * this frame and runs its pad, an extension's stops at its own boundary.
	 */
	if (test__start_subtest("freplace_subprog_throws"))
		run_shape(skel, skel->progs.entry_freplace, 7, THROW_COOKIE,
			  RAN_FREPLACE);
	if (test__start_subtest("freplace_extension_throws"))
		test_freplace(skel);

	/* A tail call that is taken: the walk ends at the target, so the cookie
	 * comes back from there and this frame's pad does not run.
	 */
	if (test__start_subtest("tail_call_taken")) {
		int key = 0, prog_fd = bpf_program__fd(skel->progs.tc_target);

		if (ASSERT_OK(bpf_map_update_elem(bpf_map__fd(skel->maps.taken_table),
						  &key, &prog_fd, BPF_ANY),
			      "populate taken_table"))
			run_shape(skel, skel->progs.entry_tail_taken, 101,
				  THROW_COOKIE, 0);
	}

	/* A throwing subprog named by a BPF_PSEUDO_FUNC no helper is handed: the
	 * callback check has to look at the bpf_loop(), not at the ld_imm64.
	 */
	if (test__start_subtest("addr_taken_no_throw"))
		run_shape(skel, skel->progs.entry_addr_taken, 1, 2, 0);
	if (test__start_subtest("addr_taken_throw"))
		run_shape(skel, skel->progs.entry_addr_taken, 101, THROW_COOKIE,
			  RAN_ADDR_TAKEN);

	/* A record covering bpf_throw() itself rather than a call to a frame
	 * that throws: raised, caught up with and delivered in one frame.
	 */
	if (test__start_subtest("no_subprog_no_throw"))
		run_shape(skel, skel->progs.entry_no_subprog, 1, 0, 0);
	if (test__start_subtest("no_subprog_throw"))
		run_shape(skel, skel->progs.entry_no_subprog, 101, THROW_COOKIE,
			  RAN_NO_SUBPROG);

	/* A pad that calls a subprogram; with a throwing extension in its place,
	 * the nested exception has to stop there, not restart this pad.
	 */
	if (test__start_subtest("pad_calls_subprog")) {
		skel->bss->pad_runs = 0;
		run_shape(skel, skel->progs.entry_pad_calls, 101, THROW_COOKIE,
			  RAN_PAD_CALLS);
		ASSERT_EQ(skel->bss->pad_runs, 1, "pad_runs");
	}
	if (test__start_subtest("pad_calls_throwing_extension"))
		test_pad_calls_freplace(skel);

	/* A covered throw the sweep leaves last, where the default exception
	 * callback is patched in; the pad's bit needs r6-r9 still spilled.
	 */
	if (test__start_subtest("pad_before_throw"))
		run_shape(skel, skel->progs.entry_pad_first, 101, THROW_COOKIE,
			  RAN_PAD_FIRST);

	/* A region whose last instruction is a 16-byte one, so that end - 1
	 * names the half of it that is not an instruction.
	 */
	if (test__start_subtest("region_ends_on_ldimm64"))
		run_shape(skel, skel->progs.entry_wide_rec, 101, THROW_COOKIE,
			  RAN_WIDE_REC);

	/* A pad that reloads from and writes to its own frame's stack, which a
	 * JIT addressing the frame through the stack pointer gets wrong.
	 */
	if (test__start_subtest("pad_uses_own_frame"))
		run_shape(skel, skel->progs.entry_pad_stack, 101, THROW_COOKIE,
			  RAN_PAD_STACK);

	/* The same, with an uncovered frame between the throw and the pad. */
	if (test__start_subtest("pad_two_frames_up"))
		run_shape(skel, skel->progs.entry_deep_pad, 101, THROW_COOKIE,
			  RAN_DEEP_PAD);

	/* An extension program with a cleanup table of its own. */
	if (test__start_subtest("extension_carries_table"))
		test_ext_table(skel);

	/* A pad terminated by _Unwind_Resume, which libbpf maps onto the kfunc;
	 * every other program here calls bpf_unwind_resume directly.
	 */
	if (test__start_subtest("resume_alias"))
		run_shape(skel, skel->progs.entry_resume_alias, 101,
			  THROW_COOKIE, RAN_RESUME_ALIAS);

	/* A pad that calls a subprogram which tail calls, array empty and then
	 * populated: the tail call releases only the callee's own prologue.
	 */
	if (test__start_subtest("pad_callee_tail_call")) {
		int key = 0, prog_fd = bpf_program__fd(skel->progs.pad_tc_target);

		skel->bss->pad_tc_target_ran = 0;
		skel->bss->pad_runs = 0;
		run_shape(skel, skel->progs.entry_pad_tail_call, 101,
			  THROW_COOKIE, RAN_PAD_TAIL_CALL);
		ASSERT_EQ(skel->bss->pad_tc_target_ran, 0, "target not run");
		ASSERT_EQ(skel->bss->pad_runs, 1, "pad_runs");

		if (ASSERT_OK(bpf_map_update_elem(bpf_map__fd(skel->maps.pad_tc_table),
						  &key, &prog_fd, BPF_ANY),
			      "populate pad_tc_table")) {
			skel->bss->pad_runs = 0;
			run_shape(skel, skel->progs.entry_pad_tail_call, 101,
				  THROW_COOKIE, RAN_PAD_TAIL_CALL);
			ASSERT_EQ(skel->bss->pad_tc_target_ran, 1, "target ran");
			ASSERT_EQ(skel->bss->pad_runs, 1, "pad_runs");
		}
	}

	/* The same, into a target that carries a table and throws: that target
	 * is a boundary, so the outer pad runs once, not twice.
	 */
	if (test__start_subtest("pad_callee_tail_call_throws")) {
		int key = 0, prog_fd = bpf_program__fd(skel->progs.pad_tc_throw_target);

		if (ASSERT_OK(bpf_map_update_elem(bpf_map__fd(skel->maps.pad_tc_table),
						  &key, &prog_fd, BPF_ANY),
			      "populate pad_tc_table")) {
			skel->bss->pad_runs = 0;
			skel->bss->tc_target_pad_runs = 0;
			run_shape(skel, skel->progs.entry_pad_tail_call, 101,
				  THROW_COOKIE, RAN_PAD_TAIL_CALL);
			/* The target cleaned up after itself, once. */
			ASSERT_EQ(skel->bss->tc_target_pad_runs, 1,
				  "tc_target_pad_runs");
			/* And the outer pad was not started over. */
			ASSERT_EQ(skel->bss->pad_runs, 1, "pad_runs");
		}
	}

	exceptions_cleanup_shapes__destroy(skel);
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

	test_shapes();

	RUN_TESTS(exceptions_cleanup_fail);
}
