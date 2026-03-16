// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */

#include <test_progs.h>
#include <time.h>
#include "test_sleepable_tracepoints.skel.h"

static void run_test(struct bpf_program *prog,
		     struct test_sleepable_tracepoints *skel)
{
	struct bpf_link *link;

	link = bpf_program__attach(prog);
	if (!ASSERT_OK_PTR(link, "prog_attach"))
		return;

	skel->bss->target_pid = getpid();
	skel->bss->triggered = 0;
	skel->bss->err = 0;
	skel->bss->copied_tv_nsec = 0;

	syscall(__NR_nanosleep, &(struct timespec){ .tv_nsec = 555 }, NULL);

	ASSERT_EQ(skel->bss->triggered, 1, "triggered");
	ASSERT_EQ(skel->bss->err, 0, "err");
	ASSERT_EQ(skel->bss->copied_tv_nsec, 555, "copied_tv_nsec");

	bpf_link__destroy(link);
}

void test_sleepable_tracepoints(void)
{
	struct test_sleepable_tracepoints *skel;

	skel = test_sleepable_tracepoints__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return;

	bpf_program__set_autoload(skel->progs.handle_sched_switch, false);

	if (!ASSERT_OK(test_sleepable_tracepoints__load(skel), "skel_load"))
		goto cleanup;

	if (test__start_subtest("tp_btf"))
		run_test(skel->progs.handle_sys_enter_tp_btf, skel);

	if (test__start_subtest("classic"))
		run_test(skel->progs.handle_sys_enter_raw_tp, skel);

	if (test__start_subtest("tracepoint"))
		run_test(skel->progs.handle_sys_enter_tp, skel);

cleanup:
	test_sleepable_tracepoints__destroy(skel);

	RUN_TESTS(test_sleepable_tracepoints);
}
