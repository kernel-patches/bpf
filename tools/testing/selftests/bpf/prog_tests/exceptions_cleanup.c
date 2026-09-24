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
#include "exceptions_cleanup_light.lskel.h"

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
	/* bump() is not a landing pad; it sets its bit on every run. */
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

	run_shape(skel, skel->progs.entry_freplace, 101, 0, 0);
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
	ASSERT_EQ(topts.retval, 0, "retval");
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
	run_shape(skel, skel->progs.entry_freplace, 101, 0, 0);
	ASSERT_EQ(fr->bss->ext_pad_ran, 1, "ext_pad_ran");

	bpf_link__destroy(link);
out:
	exceptions_cleanup_ext_table__destroy(fr);
}

static void test_light_skeleton(void)
{
	struct exceptions_cleanup_light_lskel *skel;
	__u64 ctx = 0;
	int err;

	LIBBPF_OPTS(bpf_test_run_opts, topts,
		    .ctx_in = &ctx,
		    .ctx_size_in = sizeof(ctx),
	);

	skel = exceptions_cleanup_light_lskel__open_and_load();
	if (!ASSERT_OK_PTR(skel, "light open_and_load"))
		return;

	err = bpf_prog_test_run_opts(skel->progs.entry_light.prog_fd, &topts);
	if (!ASSERT_OK(err, "run"))
		goto out;
	ASSERT_EQ(topts.retval, 0, "retval");
	ASSERT_EQ(skel->bss->pads_ran, RAN_LIGHT, "pads_ran");
out:
	exceptions_cleanup_light_lskel__destroy(skel);
}

static void test_shapes(void)
{
	struct exceptions_cleanup_shapes *skel;

	skel = exceptions_cleanup_shapes__open_and_load();
	if (!ASSERT_OK_PTR(skel, "shapes open_and_load"))
		return;

	/* Same check, with a tail-call-reachable callee: its spill moves. */
	if (test__start_subtest("tail_call_no_throw"))
		run_shape(skel, skel->progs.entry_tail_call, 1, 0, 0);
	if (test__start_subtest("tail_call_throw"))
		run_shape(skel, skel->progs.entry_tail_call, 101, 0,
			  RAN_TAIL_CALL);

	/*
	 * The same call site either way: the subprogram's throw unwinds into
	 * this frame and runs its pad, an extension's stops at its own boundary.
	 */
	if (test__start_subtest("freplace_subprog_throws"))
		run_shape(skel, skel->progs.entry_freplace, 7, 0,
			  RAN_FREPLACE);
	if (test__start_subtest("freplace_extension_throws"))
		test_freplace(skel);

	/*
	 * A tail call that is taken: the walk ends at the target, so the cookie
	 * comes back from there and this frame's pad does not run -- though it
	 * is reachable, so a walk past the boundary would find it.
	 */
	if (test__start_subtest("tail_call_taken")) {
		int key = 0, prog_fd = bpf_program__fd(skel->progs.tc_target);

		if (ASSERT_OK(bpf_map_update_elem(bpf_map__fd(skel->maps.taken_table),
						  &key, &prog_fd, BPF_ANY),
			      "populate taken_table"))
			run_shape(skel, skel->progs.entry_tail_taken, 101,
				   0, 0);
	}

	/*
	 * A throwing subprog named by a BPF_PSEUDO_FUNC and handed to a
	 * bpf_loop() the verifier never reaches: the callback check has to fire
	 * on the helper call, not on the ld_imm64.
	 */
	if (test__start_subtest("addr_taken_no_throw"))
		run_shape(skel, skel->progs.entry_addr_taken, 1, 2, 0);
	if (test__start_subtest("addr_taken_throw"))
		run_shape(skel, skel->progs.entry_addr_taken, 101, 0,
			  RAN_ADDR_TAKEN);

	/*
	 * A record covering bpf_throw() itself rather than a call to a frame
	 * that throws: raised, caught up with and delivered in one frame.
	 */
	if (test__start_subtest("no_subprog_no_throw"))
		run_shape(skel, skel->progs.entry_no_subprog, 1, 0, 0);
	if (test__start_subtest("no_subprog_throw"))
		run_shape(skel, skel->progs.entry_no_subprog, 101, 0,
			  RAN_NO_SUBPROG);

	/*
	 * A pad that calls a subprogram; with a throwing extension in its place,
	 * the nested exception has to stop there, not restart this pad.
	 */
	if (test__start_subtest("pad_calls_subprog")) {
		skel->bss->pad_runs = 0;
		run_shape(skel, skel->progs.entry_pad_calls, 101, 0,
			  RAN_PAD_CALLS);
		ASSERT_EQ(skel->bss->pad_runs, 1, "pad_runs");
	}
	if (test__start_subtest("pad_calls_throwing_extension"))
		test_pad_calls_freplace(skel);

	/* An extension program with a cleanup table of its own. */
	if (test__start_subtest("extension_carries_table"))
		test_ext_table(skel);

	/*
	 * A pad that calls a subprogram which tail calls, array empty and then
	 * populated: the tail call releases only the callee's own prologue.
	 */
	if (test__start_subtest("pad_callee_tail_call")) {
		int key = 0, prog_fd = bpf_program__fd(skel->progs.pad_tc_target);

		skel->bss->pad_tc_target_ran = 0;
		skel->bss->pad_runs = 0;
		run_shape(skel, skel->progs.entry_pad_tail_call, 101,
			   0, RAN_PAD_TAIL_CALL);
		ASSERT_EQ(skel->bss->pad_tc_target_ran, 0, "target not run");
		ASSERT_EQ(skel->bss->pad_runs, 1, "pad_runs");

		if (ASSERT_OK(bpf_map_update_elem(bpf_map__fd(skel->maps.pad_tc_table),
						  &key, &prog_fd, BPF_ANY),
			      "populate pad_tc_table")) {
			skel->bss->pad_runs = 0;
			run_shape(skel, skel->progs.entry_pad_tail_call, 101,
				   0, RAN_PAD_TAIL_CALL);
			ASSERT_EQ(skel->bss->pad_tc_target_ran, 1, "target ran");
			ASSERT_EQ(skel->bss->pad_runs, 1, "pad_runs");
		}
	}

	/*
	 * The same, into a target that carries a table and throws: that target
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
				   0, RAN_PAD_TAIL_CALL);
			/* The target cleaned up after itself, once. */
			ASSERT_EQ(skel->bss->tc_target_pad_runs, 1,
				  "tc_target_pad_runs");
			/* And the outer pad was not started over. */
			ASSERT_EQ(skel->bss->pad_runs, 1, "pad_runs");
		}
	}

	exceptions_cleanup_shapes__destroy(skel);
}

/*
 * A table with more records than the program has instructions: no valid one
 * can look like that, and it is refused before the kernel allocates for it.
 */
static void test_cleanup_info_cnt(void)
{
	struct bpf_insn insns[] = {
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	struct bpf_cleanup_info rec = {
		.begin_off = 0,
		.end_off = 1,
		.landing_pad_off = 1,
	};
	char log[512] = {};

	LIBBPF_OPTS(bpf_prog_load_opts, opts,
		    .log_buf = log,
		    .log_size = sizeof(log),
		    .log_level = 1,
		    .cleanup_info = &rec,
		    .cleanup_info_cnt = 1 << 20,
		    .cleanup_info_rec_size = sizeof(rec));
	int fd;

	fd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, NULL, "GPL",
			   insns, ARRAY_SIZE(insns), &opts);
	if (!ASSERT_LT(fd, 0, "load")) {
		close(fd);
		return;
	}
	/*
	 * Turned away on the count, rather than on whatever the records past
	 * the one below happen to hold.
	 */
	ASSERT_HAS_SUBSTR(log, "cleanup info has 1048576 records for 2 instructions",
			  "log");
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

	/* No throw: foo3 returns 1 ^ 1 == 0, foo2 adds one, no pad runs. */
	if (test__start_subtest("no_throw"))
		run(skel, 1, 1, 0);

	/* foo3 throws; every pad runs and the cookie is delivered at entry. */
	if (test__start_subtest("throw_from_foo3"))
		run(skel, 101, 0, PADS_FOO3_THREW);

	/*
	 * foo3 returns 2 ^ 1 == 3, so foo2 throws from its own second region;
	 * foo3's frame is long gone, so its pad must not run.
	 */
	if (test__start_subtest("throw_from_foo2"))
		run(skel, 2, 0, PADS_FOO2_THREW);

	exceptions_cleanup__destroy(skel);

	if (test__start_subtest("light_skeleton"))
		test_light_skeleton();

	test_shapes();

	RUN_TESTS(exceptions_cleanup_fail);
	RUN_TESTS(exceptions_cleanup_shapes);

	if (test__start_subtest("cleanup_info_cnt"))
		test_cleanup_info_cnt();
}
