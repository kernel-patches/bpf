// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Meta Platforms, Inc. and affiliates. */
#include <test_progs.h>
#include <time.h>

#include "rcu_tasks_trace_gp.skel.h"
#include "struct_ops_module.skel.h"

static void test_regular_load(void)
{
	struct struct_ops_module *skel;
	struct bpf_link *link;
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts);
	int err;

	skel = struct_ops_module__open_opts(&opts);
	if (!ASSERT_OK_PTR(skel, "struct_ops_module_open"))
		return;
	err = struct_ops_module__load(skel);
	if (!ASSERT_OK(err, "struct_ops_module_load"))
		return;

	link = bpf_map__attach_struct_ops(skel->maps.testmod_1);
	ASSERT_OK_PTR(link, "attach_test_mod_1");

	ASSERT_EQ(skel->bss->test_2_result, 7, "test_2_result");

	bpf_link__destroy(link);

	struct_ops_module__destroy(skel);
}

void serial_test_struct_ops_module(void)
{
	if (test__start_subtest("regular_load"))
		test_regular_load();
}

