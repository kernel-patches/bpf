// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <test_progs.h>

#include "arena_kfunc.skel.h"

/*
 * The test kfuncs live in bpf_testmod. Resolving kfuncs against module
 * BTFs needs CAP_SYS_ADMIN, so run with full capabilities instead of
 * through the verifier tests' capability-restricted runner.
 */
void test_arena_kfunc(void)
{
	RUN_TESTS(arena_kfunc);
}
