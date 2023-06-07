// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2020 Facebook */

#include <test_progs.h>
#include <stdbool.h>
#include "test_subprogs_extable.skel.h"

static int duration;

void test_subprogs_extable(void)
{
	const int READ_SZ = 456;
	struct test_subprogs_extable *skel;
	int err;

	skel = test_subprogs_extable__open();
	if (CHECK(!skel, "skel_open", "failed to open skeleton\n"))
		return;

	err = test_subprogs_extable__load(skel);
	if (CHECK(err, "skel_load", "failed to load skeleton\n"))
		return;

	err = test_subprogs_extable__attach(skel);
	if (CHECK(err, "skel_attach", "skeleton attach failed: %d\n", err))
		goto cleanup;

	/* trigger tracepoint */
	ASSERT_OK(trigger_module_test_read(READ_SZ), "trigger_read");

	test_subprogs_extable__detach(skel);

cleanup:
	test_subprogs_extable__destroy(skel);
}
