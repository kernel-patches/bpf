// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */

#include <test_progs.h>
#include <time.h>
#include "test_sleepable_tracepoints.skel.h"
#include "test_sleepable_tracepoints_fail.skel.h"

static void trigger_nanosleep(void)
{
	syscall(__NR_nanosleep, &(struct timespec){ .tv_nsec = 555 }, NULL);
}

static void run_test(struct test_sleepable_tracepoints *skel)
{
	skel->bss->target_pid = getpid();
	skel->bss->triggered = 0;
	skel->bss->err = 0;
	skel->bss->copied_tv_nsec = 0;

	trigger_nanosleep();

	ASSERT_EQ(skel->bss->triggered, 1, "triggered");
	ASSERT_EQ(skel->bss->err, 0, "err");
	ASSERT_EQ(skel->bss->copied_tv_nsec, 555, "copied_tv_nsec");
}

static void run_auto_attach_test(struct bpf_program *prog, struct test_sleepable_tracepoints *skel)
{
	struct bpf_link *link;

	link = bpf_program__attach(prog);
	if (!ASSERT_OK_PTR(link, "prog_attach"))
		return;

	run_test(skel);
	bpf_link__destroy(link);
}

void test_sleepable_tracepoints(void)
{
	struct test_sleepable_tracepoints *skel;
	struct bpf_link *link;

	skel = test_sleepable_tracepoints__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		return;

	/* Primary functional tests: full bpf_copy_from_user exercise */

	if (test__start_subtest("tp_btf"))
		run_auto_attach_test(skel->progs.handle_sys_enter_tp_btf, skel);

	if (test__start_subtest("raw_tp"))
		run_auto_attach_test(skel->progs.handle_sys_enter_raw_tp, skel);

	if (test__start_subtest("tracepoint"))
		run_auto_attach_test(skel->progs.handle_sys_enter_tp, skel);

	/* Alias SEC variants: verify libbpf prefix parsing */

	if (test__start_subtest("tracepoint_alias")) {
		link = bpf_program__attach(skel->progs.handle_sys_enter_tp_alias);
		if (ASSERT_OK_PTR(link, "tp_alias_attach"))
			bpf_link__destroy(link);
	}

	if (test__start_subtest("raw_tracepoint_alias")) {
		link = bpf_program__attach(skel->progs.handle_sys_enter_raw_tp_alias);
		if (ASSERT_OK_PTR(link, "raw_tp_alias_attach"))
			bpf_link__destroy(link);
	}

	/* Bare SEC variants: verify manual attach */

	if (test__start_subtest("raw_tp_bare")) {
		link = bpf_program__attach_raw_tracepoint(skel->progs.handle_raw_tp_bare,
							  "sys_enter");
		if (ASSERT_OK_PTR(link, "raw_tp_bare_attach"))
			bpf_link__destroy(link);
	}

	if (test__start_subtest("tp_bare")) {
		link = bpf_program__attach_tracepoint(skel->progs.handle_tp_bare, "syscalls",
						      "sys_enter_nanosleep");
		if (ASSERT_OK_PTR(link, "tp_bare_attach"))
			bpf_link__destroy(link);
	}

	/* Sys exit test */

	if (test__start_subtest("sys_exit")) {
		link = bpf_program__attach(skel->progs.handle_sys_exit_tp);
		if (ASSERT_OK_PTR(link, "sys_exit_attach")) {
			skel->bss->target_pid = getpid();
			skel->bss->exit_triggered = 0;

			trigger_nanosleep();

			ASSERT_EQ(skel->bss->exit_triggered, 1, "exit_triggered");
			bpf_link__destroy(link);
		}
	}

	/* Negative: attach-time rejection on non-faultable tracepoints */

	if (test__start_subtest("raw_tp_non_faultable")) {
		link = bpf_program__attach(skel->progs.handle_raw_tp_non_faultable);
		ASSERT_ERR_PTR(link, "raw_tp_non_faultable_attach");
	}

	if (test__start_subtest("tp_non_syscall")) {
		link = bpf_program__attach(skel->progs.handle_tp_non_syscall);
		ASSERT_ERR_PTR(link, "tp_non_syscall_attach");
	}

	test_sleepable_tracepoints__destroy(skel);

	/* Negative: load-time rejection (separate BPF object) */
	RUN_TESTS(test_sleepable_tracepoints_fail);
}
