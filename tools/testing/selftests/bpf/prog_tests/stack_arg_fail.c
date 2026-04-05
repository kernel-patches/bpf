// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <test_progs.h>
#include "stack_arg_fail.skel.h"

void test_stack_arg_fail(void)
{
	struct stack_arg_fail *skel;

	skel = stack_arg_fail__open();
	if (!ASSERT_OK_PTR(skel, "open"))
		return;

	if (!skel->rodata->has_stack_arg) {
		test__skip();
		goto out;
	}

	ASSERT_ERR(stack_arg_fail__load(skel), "load_should_fail");

out:
	stack_arg_fail__destroy(skel);
}
