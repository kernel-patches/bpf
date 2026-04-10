// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */

#include <test_progs.h>
#include <time.h>
#include "test_sleepable_tracepoints.skel.h"
#include "test_sleepable_tracepoints_fail.skel.h"

static void run_test(struct test_sleepable_tracepoints *skel)
{
	skel->bss->target_pid = getpid();
	skel->bss->prog_triggered = 0;
	skel->bss->err = 0;
	skel->bss->copied_tv_nsec = 0;

	syscall(__NR_nanosleep, &(struct timespec){ .tv_nsec = 555 }, NULL);

	ASSERT_EQ(skel->bss->prog_triggered, 1, "prog_triggered");
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
	int err, i;

	skel = test_sleepable_tracepoints__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		return;

	/* Primary functional tests: full bpf_copy_from_user exercise */
	{
		struct {
			const char *name;
			struct bpf_program *prog;
		} func_tests[] = {
			{ "tp_btf", skel->progs.handle_sys_enter_tp_btf },
			{ "raw_tp", skel->progs.handle_sys_enter_raw_tp },
			{ "tracepoint", skel->progs.handle_sys_enter_tp },
			{ "sys_exit", skel->progs.handle_sys_exit_tp },
		};

		for (i = 0; i < ARRAY_SIZE(func_tests); i++) {
			if (test__start_subtest(func_tests[i].name))
				run_auto_attach_test(func_tests[i].prog, skel);
		}
	}

	/* Attach-only tests: verify libbpf prefix parsing for aliases */
	{
		struct {
			const char *name;
			struct bpf_program *prog;
		} attach_tests[] = {
			{ "tracepoint_alias", skel->progs.handle_sys_enter_tp_alias },
			{ "raw_tracepoint_alias", skel->progs.handle_sys_enter_raw_tp_alias },
		};

		for (i = 0; i < ARRAY_SIZE(attach_tests); i++) {
			if (!test__start_subtest(attach_tests[i].name))
				continue;
			link = bpf_program__attach(attach_tests[i].prog);
			if (ASSERT_OK_PTR(link, "attach"))
				bpf_link__destroy(link);
		}
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

	/* BPF_PROG_TEST_RUN: exercise bpf_prog_test_run_raw_tp() */
	{
		struct {
			const char *name;
			__u32 flags;
			bool expect_err;
		} run_tests[] = {
			{ "test_run", 0, false },
			{ "test_run_on_cpu_reject", BPF_F_TEST_RUN_ON_CPU, true },
		};

		for (i = 0; i < ARRAY_SIZE(run_tests); i++) {
			__u64 args[2] = {0x1234ULL, 0x5678ULL};
			LIBBPF_OPTS(bpf_test_run_opts, topts,
				.ctx_in = args,
				.ctx_size_in = sizeof(args),
				.flags = run_tests[i].flags,
			);
			int fd;

			if (!test__start_subtest(run_tests[i].name))
				continue;

			fd = bpf_program__fd(skel->progs.handle_test_run);
			err = bpf_prog_test_run_opts(fd, &topts);
			if (!run_tests[i].expect_err) {
				ASSERT_OK(err, "test_run");
				ASSERT_EQ(topts.retval, args[0] + args[1], "test_run_retval");
			} else {
				ASSERT_ERR(err, "test_run_err");
			}
		}
	}

	/* Negative: attach-time rejection on non-faultable tracepoints */
	{
		struct {
			const char *name;
			struct bpf_program *prog;
		} neg_tests[] = {
			{ "raw_tp_non_faultable", skel->progs.handle_raw_tp_non_faultable },
			{ "tp_non_syscall", skel->progs.handle_tp_non_syscall },
		};

		for (i = 0; i < ARRAY_SIZE(neg_tests); i++) {
			if (!test__start_subtest(neg_tests[i].name))
				continue;
			link = bpf_program__attach(neg_tests[i].prog);
			ASSERT_ERR_PTR(link, "attach_should_fail");
		}
	}

	test_sleepable_tracepoints__destroy(skel);

	/* Negative: load-time rejection (separate BPF object) */
	RUN_TESTS(test_sleepable_tracepoints_fail);
}
