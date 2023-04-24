// SPDX-License-Identifier: GPL-2.0

#include <unistd.h>
#include <test_progs.h>
#include "uprobe_multi.skel.h"

noinline void uprobe_multi_func_1(void)
{
	asm volatile ("");
}

noinline void uprobe_multi_func_2(void)
{
	asm volatile ("");
}

noinline void uprobe_multi_func_3(void)
{
	asm volatile ("");
}

static void uprobe_multi_test_run(struct uprobe_multi *skel)
{
	skel->bss->uprobe_multi_func_1_addr = (u64) uprobe_multi_func_1;
	skel->bss->uprobe_multi_func_2_addr = (u64) uprobe_multi_func_2;
	skel->bss->uprobe_multi_func_3_addr = (u64) uprobe_multi_func_3;

	skel->bss->pid = getpid();

	uprobe_multi_func_1();
	uprobe_multi_func_2();
	uprobe_multi_func_3();

	ASSERT_EQ(skel->bss->uprobe_multi_func_1_result, 1, "uprobe_multi_func_1_result");
	ASSERT_EQ(skel->bss->uprobe_multi_func_2_result, 1, "uprobe_multi_func_2_result");
	ASSERT_EQ(skel->bss->uprobe_multi_func_3_result, 1, "uprobe_multi_func_3_result");

	ASSERT_EQ(skel->bss->uretprobe_multi_func_1_result, 1, "uretprobe_multi_func_1_result");
	ASSERT_EQ(skel->bss->uretprobe_multi_func_2_result, 1, "uretprobe_multi_func_2_result");
	ASSERT_EQ(skel->bss->uretprobe_multi_func_3_result, 1, "uretprobe_multi_func_3_result");
}

static void test_skel_api(void)
{
	struct uprobe_multi *skel = NULL;
	int err;

	skel = uprobe_multi__open_and_load();
	if (!ASSERT_OK_PTR(skel, "uprobe_multi__open_and_load"))
		goto cleanup;

	err = uprobe_multi__attach(skel);
	if (!ASSERT_OK(err, "uprobe_multi__attach"))
		goto cleanup;

	uprobe_multi_test_run(skel);

cleanup:
	uprobe_multi__destroy(skel);
}

void test_uprobe_multi_test(void)
{
	if (test__start_subtest("skel_api"))
		test_skel_api();
}
