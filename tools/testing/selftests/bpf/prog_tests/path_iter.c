// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */

#include <test_progs.h>
#include <bpf/libbpf.h>
#include <bpf/btf.h>
#include "path_iter.skel.h"

void test_path_iter(void)
{
	RUN_TESTS(path_iter);
}
