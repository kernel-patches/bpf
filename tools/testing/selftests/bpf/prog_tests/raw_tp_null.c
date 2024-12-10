// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */

#include <test_progs.h>
#include "raw_tp_null.skel.h"
#include "raw_tp_scalar.skel.h"

void test_raw_tp_null(void)
{
	RUN_TESTS(raw_tp_null);
	RUN_TESTS(raw_tp_scalar);
}
