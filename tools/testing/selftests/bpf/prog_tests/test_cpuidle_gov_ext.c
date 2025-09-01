// SPDX-License-Identifier: GPL-2.0
/*
 * test_cpuidle_gov_ext.c - test cpuidle governor ext's load, attach and kfuncs
 *
 * Copyright (C) Yikai Lin <yikai.lin@vivo.com>
 */

#include <test_progs.h>
#include "cpuidle_gov_ext.skel.h"

void test_test_cpuidle_gov_ext(void)
{
	struct cpuidle_gov_ext *skel;
	int err;

	skel = cpuidle_gov_ext__open_and_load();
	if (!ASSERT_OK_PTR(skel, "cpuidle_gov_ext__open_and_load"))
		return;

	skel->bss->expect_deeper = 1;
	err = cpuidle_gov_ext__attach(skel);
	if (!ASSERT_OK(err, "cpuidle_gov_ext__attach"))
		goto cleanup;

cleanup:
	cpuidle_gov_ext__destroy(skel);
}

