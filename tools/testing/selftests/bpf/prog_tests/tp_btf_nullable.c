// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include "test_tp_btf_nullable.skel.h"
#include "test_tp_btf_nullable_runtime.skel.h"

static void test_nullable_runtime(void)
{
	struct test_tp_btf_nullable_runtime *skel;

	skel = test_tp_btf_nullable_runtime__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	skel->bss->monitored_tid = sys_gettid();

	if (!ASSERT_OK(test_tp_btf_nullable_runtime__attach(skel), "attach"))
		goto out;

	if (!ASSERT_OK(trigger_module_test_read(2), "trigger"))
		goto out;

	ASSERT_EQ(skel->bss->calls, 2, "calls");
	ASSERT_EQ(skel->bss->nonnull_len, 2, "nonnull_len");
	ASSERT_EQ(skel->bss->null_len, 0, "null_len");

out:
	test_tp_btf_nullable_runtime__destroy(skel);
}

void test_tp_btf_nullable(void)
{
	if (!env.has_testmod) {
		test__skip();
		return;
	}

	RUN_TESTS(test_tp_btf_nullable);

	if (test__start_subtest("runtime"))
		test_nullable_runtime();
}
