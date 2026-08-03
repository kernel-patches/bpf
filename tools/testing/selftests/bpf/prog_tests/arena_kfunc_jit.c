// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <test_progs.h>
#include "arena_kfunc_jit.skel.h"

/*
 * Runs with full capabilities: resolving module kfunc ksyms requires
 * CAP_SYS_ADMIN, which rules out the capability-restricted runner.
 */
void test_arena_kfunc_jit(void)
{
	RUN_TESTS(arena_kfunc_jit);
}
