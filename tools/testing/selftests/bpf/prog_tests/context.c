// SPDX-License-Identifier: GPL-2.0
#include <error.h>
#include <test_progs.h>
#include "context_prog.skel.h"

void test_context(void)
{
	struct context_prog *skel = NULL;

	skel = context_prog__open_and_load();
	if (!ASSERT_OK_PTR(skel, "loading prog fail"))
		return;

	context_prog__attach(skel);
	getuid();
	sleep(5);

	if (!ASSERT_EQ(1, skel->bss->in_hardirq, "hardirq not triggered"))
		goto out;
	if (!ASSERT_EQ(1, skel->bss->in_softriq, "softirq not triggered"))
		goto out;
	if (!ASSERT_EQ(1, skel->bss->in_task, "task context not triggered"))
		goto out;
out:
	context_prog__destroy(skel);
}

void test_bpf_context(void)
{
	if (test__start_subtest("context"))
		test_context();
}
