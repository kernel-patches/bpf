// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2022 Huawei Technologies Duesseldorf GmbH
 */

#include <test_progs.h>

static int duration;

void test_test_gen_preload_methods(void)
{
	char diff_cmd[1024];
	int err;

	snprintf(diff_cmd, sizeof(diff_cmd),
		 "diff -up gen_preload_methods.lskel.h "
		 "gen_preload_methods.preload.lskel.h "
		 "| tail -n +4 | "
		 "diff -u - "
		 "<(tail -n +4 prog_tests/gen_preload_methods.expected.diff)");
	err = system(diff_cmd);
	if (CHECK(err, "diff",
		  "differing test output, err=%d, diff cmd:\n%s\n",
		  err, diff_cmd))
		return;
}
