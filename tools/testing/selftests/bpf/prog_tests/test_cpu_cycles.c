// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Inc. */

#include <test_progs.h>
#include "test_cpu_cycles.skel.h"

static void cpu_cycles(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	struct test_cpu_cycles *skel;
	int err, pfd;

	skel = test_cpu_cycles__open_and_load();
	if (!ASSERT_OK_PTR(skel, "test_cpu_cycles open and load"))
		return;

	pfd = bpf_program__fd(skel->progs.bpf_cpu_cycles);
	if (!ASSERT_GT(pfd, 0, "test_cpu_cycles fd"))
		goto fail;

	err = bpf_prog_test_run_opts(pfd, &opts);
	if (!ASSERT_OK(err, "test_cpu_cycles test run"))
		goto fail;

	ASSERT_NEQ(skel->bss->cycles, 0, "test_cpu_cycles 0 cycles");
	ASSERT_NEQ(skel->bss->ns, 0, "test_cpu_cycles 0 ns");
fail:
	test_cpu_cycles__destroy(skel);
}

void test_cpu_cycles(void)
{
	if (test__start_subtest("cpu_cycles"))
		cpu_cycles();
}
