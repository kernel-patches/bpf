// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Meta Platforms, Inc. and affiliates. */

#include <test_progs.h>

#include "array_kptr.skel.h"

void test_array_kptr(void)
{
	if (env.has_testmod)
		RUN_TESTS(array_kptr);
}
