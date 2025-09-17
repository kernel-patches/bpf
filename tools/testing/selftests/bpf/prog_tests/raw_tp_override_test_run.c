// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include "bpf/libbpf_internal.h"
#include "test_raw_tp_override_test_run.skel.h"

void test_raw_tp_override_test_run(void)
{
	struct test_raw_tp_override_test_run *skel;

	skel = test_raw_tp_override_test_run__open_and_load();
	if (!ASSERT_OK_PTR(skel, "test_raw_tp_override_test_run__open_and_load"))
		return;

	if (!ASSERT_OK(test_raw_tp_override_test_run__attach(skel),
		       "test_raw_tp_override_test_run__attach"))
		goto cleanup;
	ASSERT_OK(trigger_module_test_write(1), "trigger_write");
	ASSERT_EQ(skel->bss->flag, 1, "check_flag");

cleanup:
	test_raw_tp_override_test_run__destroy(skel);
}
