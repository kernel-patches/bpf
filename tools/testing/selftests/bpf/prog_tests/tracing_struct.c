// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Meta Platforms, Inc. and affiliates. */

#include <test_progs.h>
#include "tracing_struct.skel.h"

static void test_fentry(void)
{
	struct tracing_struct *skel;
	int err;

	skel = tracing_struct__open_and_load();
	if (!ASSERT_OK_PTR(skel, "tracing_struct__open_and_load"))
		return;

	err = tracing_struct__attach(skel);
	if (!ASSERT_OK(err, "tracing_struct__attach"))
		return;

        ASSERT_OK(trigger_module_test_read(256), "trigger_read");

	ASSERT_EQ(skel->bss->t1_a_a, 2, "t1:a.a");
	ASSERT_EQ(skel->bss->t1_a_b, 3, "t1:a.b");
	ASSERT_EQ(skel->bss->t1_b, 1, "t1:b");
	ASSERT_EQ(skel->bss->t1_c, 4, "t1:c");

	ASSERT_EQ(skel->bss->t2_a, 1, "t2:a");
	ASSERT_EQ(skel->bss->t2_b_a, 2, "t2:b.a");
	ASSERT_EQ(skel->bss->t2_b_b, 3, "t2:b.b");
	ASSERT_EQ(skel->bss->t2_c, 4, "t2:c");

	ASSERT_EQ(skel->bss->t3_a, 1, "t3:a");
	ASSERT_EQ(skel->bss->t3_b, 4, "t3:b");
	ASSERT_EQ(skel->bss->t3_c_a, 2, "t3:c.a");
	ASSERT_EQ(skel->bss->t3_c_b, 3, "t3:c.b");

	ASSERT_EQ(skel->bss->t4_a_a, 10, "t4:a.a");
	ASSERT_EQ(skel->bss->t4_b, 1, "t4:b");
	ASSERT_EQ(skel->bss->t4_c, 2, "t4:c");
	ASSERT_EQ(skel->bss->t4_d, 3, "t4:d");
	ASSERT_EQ(skel->bss->t4_e_a, 2, "t4:e.a");
	ASSERT_EQ(skel->bss->t4_e_b, 3, "t4:e.b");

	tracing_struct__detach(skel);
	tracing_struct__destroy(skel);
}

void test_tracing_struct(void)
{
	test_fentry();
}
